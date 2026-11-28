#!/usr/bin/env python3
# ============================================================
# Script:       snapshot.py
# Purpose:      Read-only, multi-vendor network snapshot. Logs in to every device
#               in an inventory over SSH, runs the read-only commands its vendor
#               profile lists, strips the lines that change on their own (clocks,
#               timers, counters), saves one text file per command, and commits the
#               run to a git repo so any two runs can be compared. Also saves device
#               state (ARP, MAC tables, bindings; per VRF) outside git with the previous
#               run beside it, and joins it into a host table (.snapshot/hosts.csv).
#               Writes a JSON report: failures first, reboots, changed files, hosts.
# Usage:        python snapshot.py --inventory inventory.yaml [--site S | --device D]
#                                  [--no-state] [--full] [--health]
#               python snapshot.py --set-credential <username>
#               python snapshot.py --check-profiles
# Dependencies: Python 3.9+, netmiko, keyring, pyyaml, git on PATH.
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/netops-skills (plugins/network-snapshot)
# Notes:        Never changes config. Every profile command must start with a
#               read verb (show / get / display) or the profile is refused at load;
#               commands built from device output (VRF names) are checked again just
#               before they are sent. FortiGate logins go through fortigate_guard.py.
#               Passwords come from the shared credential lookup (lib/credentials):
#               an environment variable, the inventory's credentials command, then the
#               OS credential store. Never from files or arguments; never printed.
# ============================================================
import argparse
import datetime as dt
import getpass
import json
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

import pluginlib  # noqa: F401  (puts plugins/network-ops/lib on sys.path)
import credentials
import hosttable
from snapshotfiles import slug  # the file each command's output is saved to

READ_VERBS = ("show", "get", "display")
# output pipes and redirects that write a file or chain a second command: never allowed
WRITING_PIPES = re.compile(r"\|\s*(redirect|append|tee|copy|save)\b|[;>]", re.I)  # NX-OS: > >> ;
# a VRF name comes from device output, so it is untrusted text until it matches this
VRF_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
HERE = Path(__file__).resolve().parent
PLATFORMS = HERE.parent / "platforms"
UNITS = {"year": 31536000, "week": 604800, "day": 86400, "hour": 3600, "minute": 60, "second": 1}


def check_command(cmd):
    """The command, if it is a plain read: one line, starting with a read verb, with no pipe
    that writes to the device. Raises ValueError otherwise. Run on every profile command at
    load and again on every command built from device output just before it is sent."""
    words = str(cmd or "").split()
    if (not words or words[0].lower() not in READ_VERBS or re.search(r"[\r\n\x00-\x08\x0b-\x1f]", cmd)
            or WRITING_PIPES.search(cmd)):
        raise ValueError(f"refused, not a read-only command: {cmd!r}")
    return cmd


def valid_vrfs(names):
    """(good, bad): VRF names that may go into a command, and the ones refused."""
    good, bad = [], []
    for n in names:
        (good if VRF_NAME.match(n or "") else bad).append(n)
    return good, bad


def expand(cmd, vrfs):
    """[(command, vrf)]: a '{vrf}' template once per VRF (none when there are no VRFs), any
    other command once with vrf None. Every VRF name is validated and every result guarded."""
    if "{vrf}" not in cmd:
        return [(check_command(cmd), None)]
    good, bad = valid_vrfs(vrfs)
    if bad:
        raise ValueError(f"refused VRF names {bad!r} for {cmd!r}")
    return [(check_command(cmd.replace("{vrf}", v)), v) for v in good]


def load_profile(device_type):
    path = PLATFORMS / f"{device_type}.yaml"
    if not path.exists():
        raise ValueError(f"no profile for device_type '{device_type}' (expected {path.name})")
    prof = yaml.safe_load(path.read_text(encoding="utf-8"))
    prof.setdefault("health_commands", [])
    prof.setdefault("state_commands", [])
    extra = [prof["uptime"]["cmd"]] + [prof[k]["cmd"] for k in ("privilege", "vrfs") if prof.get(k)]
    entries = prof["commands"] + prof["state_commands"] + prof["health_commands"]
    bad = []
    for c in [e["cmd"] for e in entries] + extra:
        try:
            check_command(c.replace("{vrf}", "x"))
        except ValueError:
            bad.append(c)
    if bad:
        raise ValueError(f"profile {path.name} refused, not read-only: {bad}")
    if any("{vrf}" in e["cmd"] for e in entries) and not prof.get("vrfs"):
        raise ValueError(f"profile {path.name}: a command uses {{vrf}} but the profile has no 'vrfs' block")
    for e in entries:
        e["_when"] = re.compile(e["when"], re.M) if e.get("when") else None
    if prof.get("vrfs"):
        prof["vrfs"]["_rx"] = re.compile(prof["vrfs"]["regex"], re.M)
    prof["_strip"] = [re.compile(p) for p in prof.get("strip", [])]
    prof["_mask"] = [(re.compile(m["pattern"], re.M), m["replace"]) for m in prof.get("mask", [])]
    return prof


def normalize(text, prof, cmd=None):
    lines = [l.rstrip() for l in text.replace("\r", "").split("\n")]
    lines = [l for l in lines if not any(p.search(l) for p in prof["_strip"])]
    if cmd and cmd in prof.get("sort_blocks", {}):
        # neighbor tables list entries in discovery order, which shuffles after a reboot
        start = re.compile(prof["sort_blocks"][cmd])
        head, blocks = [], []
        for l in lines:
            if start.search(l):
                blocks.append([l])
            elif blocks:
                blocks[-1].append(l)
            else:
                head.append(l)
        lines = head + [l for b in sorted(blocks) for l in b]
    out = ("\n".join(lines).strip("\n") or "(no output)") + "\n"
    for pat, rep in prof["_mask"]:
        out = pat.sub(rep, out)
    return out


def uptime_seconds(text, regex):
    m = re.search(regex, text, re.I)
    if not m:
        return None
    total = 0
    text = m.group(1)
    for num, unit in re.findall(r"(\d+)\s*(year|week|day|hour|minute|second)", text, re.I):
        total += int(num) * UNITS[unit.lower()]
    if not total:  # compact forms: "1w2d", "2d05h"
        short = {"y": 31536000, "w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
        for num, unit in re.findall(r"(\d+)([ywdhms])", text):
            total += int(num) * short[unit]
    hms = re.search(r"\b(\d{1,2}):(\d{2})(?::(\d{2}))?\b", text)
    if hms and not re.search(r"hour|minute", text, re.I):  # "12 days, 3:04:05", "1w2d 03:04"
        total += int(hms.group(1)) * 3600 + int(hms.group(2)) * 60 + int(hms.group(3) or 0)
    # a device that booted seconds ago says "0 minutes": that is uptime 0, not unknown
    if not total and not re.search(r"\d", text):
        return None
    return total


def is_unsupported(output, prof):
    return any(marker in output for marker in prof.get("invalid_markers", []))


def is_no_data(output, prof):
    """Accepted, but nothing to show (no IPv6 in this VRF, BGP not running): not an error."""
    return any(marker in output for marker in prof.get("no_data_markers", []))


def connect(prof, params):
    """A Netmiko connection. FortiGate goes through the read-only guard (fortigate_guard.py),
    which refuses a device rather than let the driver write console config."""
    if prof["netmiko_device_type"] == "fortinet":
        import fortigate_guard
        return fortigate_guard.connect(**params)
    from netmiko import ConnectHandler
    return ConnectHandler(**params)


def collect(dev, prof, password, health=False, state=False, full=False):
    """Run one device's profile. Order: uptime, privilege, committed commands (then the
    '{vrf}' ones, once VRFs are known from this run's output), state, health. A command listed
    in more than one class runs once. Every command is checked read-only right before it is
    sent."""
    params = {"device_type": prof["netmiko_device_type"], "host": dev["host"], "username": dev["username"],
              "password": password, "timeout": 30, "fast_cli": False, **prof.get("connect", {})}
    result = {"files": {}, "health": {}, "state": {}, "unsupported": [], "unsupported_health": [],
              "unsupported_state": [], "no_data": [], "no_data_state": [], "skipped_by_when": [],
              "command_errors": [], "uptime": None, "reload_reason": None, "privilege": None,
              "vrfs": [], "invalid_vrfs": [], "outputs": []}
    started = time.monotonic()
    conn = connect(prof, params)
    cache = {}

    def send(cmd, timeout):
        # one slow or broken command never costs the rest of the device: record it and move on
        check_command(cmd)
        if cmd in cache:
            return cache[cmd]
        try:
            out = conn.send_command(cmd, read_timeout=timeout)
        except Exception as e:
            result["command_errors"].append(
                {"cmd": cmd, "error": (str(e).strip().splitlines() or [type(e).__name__])[0]})
            if not conn.is_alive():
                raise
            out = None
        cache[cmd] = out
        return out

    def run_list(entries, kind, vrf_pass):
        """kind: 'files' (committed), 'state' or 'health'. vrf_pass: run the '{vrf}' templates
        (True) or the plain commands (False)."""
        for c in entries:
            if ("{vrf}" in c["cmd"]) != vrf_pass:
                continue
            if c.get("tier") == "full" and not full:
                continue
            if c.get("_when") and not c["_when"].search(config_text()):
                result["skipped_by_when"].append(c["cmd"])
                continue
            for cmd, vrf in expand(c["cmd"], result["vrfs"]):
                fname = slug(cmd)
                if vrf and fname in result[kind]:  # two VRFs whose names differ only in case
                    result["invalid_vrfs"].append(vrf)
                    continue
                out = send(cmd, c.get("timeout", 90))
                if out is None:
                    continue
                if is_unsupported(out, prof):
                    # rejected: not supported on this platform, or not permitted for this account
                    result[{"files": "unsupported", "state": "unsupported_state",
                            "health": "unsupported_health"}[kind]].append(cmd)
                    continue
                if kind != "health" and is_no_data(out, prof):
                    result["no_data" if kind == "files" else "no_data_state"].append(cmd)
                if kind != "health":  # what the host table is built from
                    result["outputs"].append({"cmd": cmd, "vrf": vrf, "text": out})
                if kind == "files":
                    result["files"][fname] = normalize(out, prof, cmd)
                else:
                    # state and health are kept as the device printed them: the moving numbers are the point
                    result[kind][fname] = (out.replace("\r", "").strip("\n") or "(no output)") + "\n"

    def config_text():
        # 'when:' rules match the config, which is the profile's first command
        return cache.get(prof["commands"][0]["cmd"]) or ""

    try:
        up_raw = conn.send_command(prof["uptime"]["cmd"], read_timeout=60)
        cache[prof["uptime"]["cmd"]] = up_raw
        result["uptime"] = uptime_seconds(up_raw, prof["uptime"]["regex"])
        if prof["uptime"].get("reload_reason"):
            m = re.search(prof["uptime"]["reload_reason"], up_raw, re.I | re.M)
            result["reload_reason"] = m.group(1).strip() if m else None
        if prof.get("privilege"):
            m = re.search(prof["privilege"]["regex"], send(prof["privilege"]["cmd"], 60) or "")
            result["privilege"] = int(m.group(1)) if m else None
        run_list(prof["commands"], "files", False)
        if prof.get("vrfs"):
            vrf_out = send(prof["vrfs"]["cmd"], 90) or ""
            names = [] if is_unsupported(vrf_out, prof) else prof["vrfs"]["_rx"].findall(vrf_out)
            result["vrfs"], result["invalid_vrfs"] = valid_vrfs(list(dict.fromkeys(names)))
        run_list(prof["commands"], "files", True)
        lists = ([(prof["state_commands"], "state")] if state else []) + \
                ([(prof["health_commands"], "health")] if health else [])
        for entries, kind in lists:
            run_list(entries, kind, False)
            run_list(entries, kind, True)
    finally:
        conn.disconnect()
    result["run"] = {"seconds": round(time.monotonic() - started, 1), "commands_sent": len(cache)}
    return result


def cred_key(dev):
    """Credential-store entry for a device: its 'credential' field, else its username."""
    return dev.get("credential", dev["username"])


def rotate(state_dir, kind, d, name):
    """(dir, prev_dir, prev_taken) for one device's state or health output: this run's
    folder, emptied, with the last run's moved to '<kind>-prev' so the two can be compared."""
    rel = Path(d.get("site", "unassigned")) / name
    cur, prev = state_dir / kind / rel, state_dir / f"{kind}-prev" / rel
    if cur.exists():
        if prev.exists():
            shutil.rmtree(prev)
        prev.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(cur), str(prev))
    cur.mkdir(parents=True, exist_ok=True)
    ptaken = prev / "_taken.txt"
    return cur, prev, ptaken.read_text().strip() if ptaken.exists() else None


def write_hosts(state_dir, devices):
    """Build the host table for this run's devices, keep the last one as hosts-prev.csv, and
    return {file, rows, devices, changes} (changes: hosts new and gone since last run)."""
    path, prev = state_dir / "hosts.csv", state_dir / "hosts-prev.csv"
    rows = hosttable.build(devices)
    before = None
    if path.exists():
        before = hosttable.read_csv(path)
        shutil.move(str(path), str(prev))
    hosttable.write_csv(rows, path)
    return {"file": str(path), "rows": len(rows), "devices": [d["name"] for d in devices],
            "kinds": {k: sum(r["kind"] == k for r in rows) for k in sorted({r["kind"] for r in rows})},
            "changes": hosttable.compare(before, rows)}


def git(repo, *args, check=True):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=check).stdout


def run(args):
    repo = Path(args.repo).expanduser()
    inv_path = Path(args.inventory) if args.inventory else repo / "inventory.yaml"
    if not inv_path.exists():
        sys.exit(f"no inventory at {inv_path}: copy inventory.example.yaml there and edit it")
    inv = yaml.safe_load(inv_path.read_text(encoding="utf-8"))
    defaults = inv.get("defaults", {})
    devices = [{**defaults, **d} for d in inv["devices"]]
    if args.site:
        devices = [d for d in devices if d.get("site") == args.site]
    if args.device:
        devices = [d for d in devices if d["name"] == args.device]
    if not devices:
        sys.exit("no devices match that target")

    repo.mkdir(parents=True, exist_ok=True)
    if not (repo / ".git").exists():
        git(repo, "init", "-q")
        (repo / ".gitignore").write_text(".snapshot/\n", encoding="utf-8")
    state_dir = repo / ".snapshot"
    state_dir.mkdir(exist_ok=True)
    up_file = state_dir / "uptime.json"
    last_up = json.loads(up_file.read_text()) if up_file.exists() else {}

    taken_iso = dt.datetime.now().isoformat(timespec="seconds")
    try:
        creds = credentials.Credentials(inv.get("credentials"))
    except credentials.CredentialError as e:
        sys.exit(f"{inv_path}: {e}")
    profiles, passwords, failures, results = {}, {}, [], {}
    for d in devices:
        try:
            profiles.setdefault(d["device_type"], load_profile(d["device_type"]))
        except ValueError as e:
            failures.append({"device": d["name"], "error": str(e)})
            continue
        try:
            passwords[cred_key(d)] = creds.get(cred_key(d))  # one lookup per name, then cached
        except credentials.CredentialError as e:
            failures.append({"device": d["name"], "error": str(e)})
    failed = {f["device"] for f in failures}
    todo = [d for d in devices if d["name"] not in failed]

    do_state = not getattr(args, "no_state", False)
    full = getattr(args, "full", False)

    def work(d):
        try:
            return d, collect(d, profiles[d["device_type"]], passwords[cred_key(d)], args.health,
                              state=do_state, full=full), None
        except Exception as e:  # keep going: one bad device never stops the run
            return d, None, (str(e).strip().splitlines() or [type(e).__name__])[0]

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for d, res, err in pool.map(work, todo):
            if err:
                failures.append({"device": d["name"], "error": err})
            else:
                results[d["name"]] = (d, res)

    reboots, recent, unsupported, health, cmd_errors = [], [], {}, {}, {}
    state, no_data, privilege, skipped, timing = {}, {}, {}, {}, {}
    for name, (d, res) in results.items():
        folder = repo / d.get("site", "unassigned") / name
        folder.mkdir(parents=True, exist_ok=True)
        for fname, text in res["files"].items():
            (folder / fname).write_text(text, encoding="utf-8", newline="\n")
        if res["unsupported"]:
            unsupported[name] = res["unsupported"]
        if res["command_errors"]:
            cmd_errors[name] = res["command_errors"]
        if res["no_data"]:
            no_data[name] = res["no_data"]
        if res["skipped_by_when"]:
            skipped[name] = sorted(set(res["skipped_by_when"]))
        privilege[name] = res["privilege"]
        timing[name] = res["run"]
        if do_state:
            sdir, spdir, prev_taken = rotate(state_dir, "state", d, name)
            for fname, text in res["state"].items():
                (sdir / fname).write_text(text, encoding="utf-8", newline="\n")
            (sdir / "_taken.txt").write_text(taken_iso + "\n", encoding="utf-8")
            state[name] = {"dir": str(sdir), "files": sorted(res["state"]), "rejected": res["unsupported_state"],
                           "no_data": res["no_data_state"], "vrfs": res["vrfs"],
                           "invalid_vrfs": sorted(set(res["invalid_vrfs"])),
                           "previous": {"dir": str(spdir), "taken": prev_taken} if spdir.exists() else None}
        prev, now = last_up.get(name), res["uptime"]
        if prev is not None and now is not None and now < prev:
            reboots.append({"device": name, "uptime_before_s": prev, "uptime_now_s": now})
        if now is not None:
            last_up[name] = now
            if now < 86400:  # catches a reboot even with no earlier snapshot to compare against
                recent.append({"device": name, "uptime_s": now, "reload_reason": res["reload_reason"]})
        if args.health:
            hdir, pdir, prev_taken = rotate(state_dir, "health", d, name)
            for fname, text in res["health"].items():
                (hdir / fname).write_text(text, encoding="utf-8", newline="\n")
            (hdir / "_taken.txt").write_text(taken_iso + "\n", encoding="utf-8")
            health[name] = {"dir": str(hdir), "files": sorted(res["health"]), "uptime_s": now,
                            "rejected": res["unsupported_health"],
                            "previous": {"dir": str(pdir), "taken": prev_taken} if pdir.exists() else None}
    up_file.write_text(json.dumps(last_up, indent=1), encoding="utf-8")

    hosts = None
    if do_state:
        try:  # a join error must never cost the run its commit
            hosts = write_hosts(state_dir, [{"name": n, "platform": profiles[d["device_type"]].get("host_table", d["device_type"]),
                                             "outputs": res["outputs"]} for n, (d, res) in sorted(results.items())])
        except Exception as e:
            hosts = {"error": f"host table not built: {type(e).__name__}: {e}"}

    stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    target = f"site {args.site}" if args.site else f"device {args.device}" if args.device else "all"
    git(repo, "add", "-A")
    changed = [l.split("\t", 1) for l in git(repo, "diff", "--cached", "--name-status").splitlines() if l]
    commit = None
    if changed:
        msg = f"snapshot {stamp} {target}: {len(results)} ok, {len(failures)} failed"
        git(repo, "-c", "user.name=network-snapshot", "-c", "user.email=network-snapshot@localhost",
            "commit", "-q", "-m", msg)
        commit = git(repo, "rev-parse", "--short", "HEAD").strip()

    by_device = {}
    for status, path in changed:
        parts = Path(path).parts
        if len(parts) >= 3:
            by_device.setdefault(parts[1], []).append(f"{status} {parts[2]}")
    report = {
        "taken": stamp, "target": target, "repo": str(repo), "commit": commit,
        "first_snapshot": commit is not None and git(repo, "rev-list", "--count", "HEAD").strip() == "1",
        "devices_ok": sorted(results), "failures": failures, "reboots": reboots,
        "up_less_than_24h": recent,
        "changed": by_device, "unchanged": sorted(n for n in results if n not in by_device),
        "unsupported_commands": unsupported,
        "no_data_commands": no_data,
        "skipped_by_when": skipped,
        "privilege": {n: p for n, p in privilege.items() if p is not None},
        "command_errors": cmd_errors,
        "run": timing,
    }
    if do_state:
        report["state"] = state
        report["hosts"] = hosts
    if args.health:
        report["health"] = health
    (state_dir / "last-report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps(report, indent=1))


def main():
    ap = argparse.ArgumentParser(description="Read-only multi-vendor network snapshot to git.")
    ap.add_argument("--inventory", help="inventory file (default: inventory.yaml inside the snapshot repo)")
    ap.add_argument("--repo", default="~/network-snapshots", help="git repo that holds the snapshots")
    ap.add_argument("--site")
    ap.add_argument("--device")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--health", action="store_true",
                    help="also run each profile's health_commands; saved under .snapshot/health, never committed")
    ap.add_argument("--no-state", action="store_true",
                    help="skip the state_commands (ARP, MAC tables, bindings, protocol detail) and the host table")
    ap.add_argument("--full", action="store_true",
                    help="also run the heavy state commands marked 'tier: full' (per-neighbor routes, full LSDB)")
    ap.add_argument("--set-credential", metavar="NAME",
                    help="store a password in the OS store under NAME (a username, or an inventory 'credential' name)")
    ap.add_argument("--check-profiles", action="store_true", help="load every vendor profile and exit")
    args = ap.parse_args()

    if args.set_credential:
        pw = getpass.getpass(f"Password for {args.set_credential} (stored in the OS credential store): ")
        credentials.store(args.set_credential, pw)
        print(f"stored: service '{credentials.SERVICE}', user '{args.set_credential}'")
        return
    if args.check_profiles:
        for p in sorted(PLATFORMS.glob("*.yaml")):
            try:
                prof = load_profile(p.stem)
                print(f"OK      {p.stem}: {len(prof['commands'])} snapshot + {len(prof['health_commands'])} health"
                      f" commands ({prof.get('status', 'untested')})")
            except Exception as e:
                print(f"REFUSED {p.stem}: {e}")
        return
    run(args)


if __name__ == "__main__":
    main()
