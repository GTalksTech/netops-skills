#!/usr/bin/env python3
# ============================================================
# Script:       snapshot.py
# Purpose:      Read-only, multi-vendor network snapshot. Logs in to every device
#               in an inventory over SSH, runs the read-only commands its vendor
#               profile lists, strips the lines that change on their own (clocks,
#               timers, counters), saves one text file per command, and commits the
#               run to a git repo so any two runs can be compared. Writes a JSON
#               report: failures first, reboots (uptime went down), changed files.
# Usage:        python snapshot.py --inventory inventory.yaml [--site S | --device D]
#               python snapshot.py --set-credential <username>
#               python snapshot.py --check-profiles
# Dependencies: Python 3.9+, netmiko, keyring, pyyaml, git on PATH.
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/netops-skills (plugins/network-snapshot)
# Notes:        Never changes config. Every profile command must start with a
#               read verb (show / get / display) or the profile is refused at load.
#               Passwords come from the OS credential store (keyring), never from
#               files, arguments or environment variables.
# ============================================================
import argparse
import datetime as dt
import getpass
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import keyring
import yaml

SERVICE = "netops-skills"
READ_VERBS = ("show", "get", "display")
HERE = Path(__file__).resolve().parent
PLATFORMS = HERE.parent / "platforms"
UNITS = {"year": 31536000, "week": 604800, "day": 86400, "hour": 3600, "minute": 60, "second": 1}


def load_profile(device_type):
    path = PLATFORMS / f"{device_type}.yaml"
    if not path.exists():
        raise ValueError(f"no profile for device_type '{device_type}' (expected {path.name})")
    prof = yaml.safe_load(path.read_text(encoding="utf-8"))
    prof.setdefault("health_commands", [])
    cmds = [c["cmd"] for c in prof["commands"] + prof["health_commands"]] + [prof["uptime"]["cmd"]]
    bad = [c for c in cmds if c.split()[0].lower() not in READ_VERBS]
    if bad:
        raise ValueError(f"profile {path.name} refused, not read-only: {bad}")
    prof["_strip"] = [re.compile(p) for p in prof.get("strip", [])]
    prof["_mask"] = [(re.compile(m["pattern"], re.M), m["replace"]) for m in prof.get("mask", [])]
    return prof


def slug(cmd):
    return re.sub(r"[^a-z0-9]+", "-", cmd.lower()).strip("-") + ".txt"


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
    return total or None


def is_unsupported(output, prof):
    return any(marker in output for marker in prof.get("invalid_markers", []))


def collect(dev, prof, password, health=False):
    from netmiko import ConnectHandler
    params = {"device_type": prof["netmiko_device_type"], "host": dev["host"], "username": dev["username"],
              "password": password, "timeout": 30, "fast_cli": False, **prof.get("connect", {})}
    result = {"files": {}, "health": {}, "unsupported": [], "uptime": None, "reload_reason": None}
    conn = ConnectHandler(**params)
    try:
        up_raw = conn.send_command(prof["uptime"]["cmd"], read_timeout=60)
        result["uptime"] = uptime_seconds(up_raw, prof["uptime"]["regex"])
        if prof["uptime"].get("reload_reason"):
            m = re.search(prof["uptime"]["reload_reason"], up_raw, re.I | re.M)
            result["reload_reason"] = m.group(1).strip() if m else None
        for c in prof["commands"]:
            out = conn.send_command(c["cmd"], read_timeout=c.get("timeout", 90))
            if is_unsupported(out, prof):
                result["unsupported"].append(c["cmd"])
                continue
            result["files"][slug(c["cmd"])] = normalize(out, prof, c["cmd"])
        for c in prof["health_commands"] if health else []:
            # health output is kept as the device printed it: the moving numbers are the point
            out = conn.send_command(c["cmd"], read_timeout=c.get("timeout", 90))
            if is_unsupported(out, prof):
                result["unsupported"].append(c["cmd"])
                continue
            result["health"][slug(c["cmd"])] = out.replace("\r", "").strip("\n") + "\n"
    finally:
        conn.disconnect()
    return result


def cred_key(dev):
    """Credential-store entry for a device: its 'credential' field, else its username."""
    return dev.get("credential", dev["username"])


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

    profiles, passwords, failures, results = {}, {}, [], {}
    for d in devices:
        try:
            profiles.setdefault(d["device_type"], load_profile(d["device_type"]))
        except ValueError as e:
            failures.append({"device": d["name"], "error": str(e)})
        key = cred_key(d)
        if key not in passwords:
            passwords[key] = keyring.get_password(SERVICE, key)
    for d in devices:
        if passwords.get(cred_key(d)) is None and not any(f["device"] == d["name"] for f in failures):
            failures.append({"device": d["name"],
                             "error": f"no password stored for '{cred_key(d)}' (run --set-credential {cred_key(d)})"})
    failed = {f["device"] for f in failures}
    todo = [d for d in devices if d["name"] not in failed]

    def work(d):
        try:
            return d, collect(d, profiles[d["device_type"]], passwords[cred_key(d)], args.health), None
        except Exception as e:  # keep going: one bad device never stops the run
            return d, None, (str(e).strip().splitlines() or [type(e).__name__])[0]

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for d, res, err in pool.map(work, todo):
            if err:
                failures.append({"device": d["name"], "error": err})
            else:
                results[d["name"]] = (d, res)

    reboots, recent, unsupported, health = [], [], {}, {}
    for name, (d, res) in results.items():
        folder = repo / d.get("site", "unassigned") / name
        folder.mkdir(parents=True, exist_ok=True)
        for fname, text in res["files"].items():
            (folder / fname).write_text(text, encoding="utf-8", newline="\n")
        if res["unsupported"]:
            unsupported[name] = res["unsupported"]
        prev, now = last_up.get(name), res["uptime"]
        if prev is not None and now is not None and now < prev:
            reboots.append({"device": name, "uptime_before_s": prev, "uptime_now_s": now})
        if now is not None:
            last_up[name] = now
            if now < 86400:  # catches a reboot even with no earlier snapshot to compare against
                recent.append({"device": name, "uptime_s": now, "reload_reason": res["reload_reason"]})
        if args.health:
            hdir = state_dir / "health" / d.get("site", "unassigned") / name
            hdir.mkdir(parents=True, exist_ok=True)
            for fname, text in res["health"].items():
                (hdir / fname).write_text(text, encoding="utf-8", newline="\n")
            health[name] = {"dir": str(hdir), "files": sorted(res["health"]), "uptime_s": now}
    up_file.write_text(json.dumps(last_up, indent=1), encoding="utf-8")

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
    }
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
    ap.add_argument("--set-credential", metavar="NAME",
                    help="store a password in the OS store under NAME (a username, or an inventory 'credential' name)")
    ap.add_argument("--check-profiles", action="store_true", help="load every vendor profile and exit")
    args = ap.parse_args()

    if args.set_credential:
        pw = getpass.getpass(f"Password for {args.set_credential} (stored in the OS credential store): ")
        keyring.set_password(SERVICE, args.set_credential, pw)
        print(f"stored: service '{SERVICE}', user '{args.set_credential}'")
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
