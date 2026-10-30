#!/usr/bin/env python3
# ============================================================
# Script:       push.py
# Purpose:      Push approved config to network devices the controlled way. The
#               commands are passed IN the command (a here-doc on stdin), never as a
#               file path, so the approval prompt shows every switch command right
#               where the user says yes. Stops on the first device error, saves each
#               device's commands and output in the change folder, and saves config
#               only when asked (after the post-check).
# Usage:        python push.py push DEVICE --log CHANGE_DIR <<'EOF'
#               ...commands...
#               EOF
#               python push.py batch --log CHANGE_DIR <<'EOF'
#               @DEVICE
#               ...description lines...
#               @DEVICE
#               ...
#               EOF
#               python push.py preview DEVICE <<'EOF' ... EOF     (sends nothing)
#               python push.py save DEVICE [DEVICE ...] --log CHANGE_DIR
#               python push.py --set-credential admin
# Dependencies: Python 3.9+, netmiko, keyring, pyyaml (same as network-snapshot).
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/netops-skills (plugins/network-ops)
# Notes:        Shares the network-snapshot skill's inventory, vendor profiles and
#               credential store. `push` is one device per run, so every impactful
#               push is its own approval. `batch` puts several devices under one
#               approval and is refused unless every line is an interface
#               description. Pushes only on tested profiles (cisco_ios). Refuses
#               destructive lines (reload, erase, format, delete) and a trunk
#               "allowed vlan <list>" without add/remove, which replaces the list.
# ============================================================
import argparse
import datetime as dt
import getpass
import re
import sys
from pathlib import Path

import keyring
import yaml

SERVICE = "netops-skills"
HERE = Path(__file__).resolve().parent
PLATFORMS = HERE.parent.parent / "network-snapshot" / "platforms"
PUSHABLE = {"cisco_ios"}  # tested for config pushes; other profiles are read-only here
WRAPPERS = {"configure terminal", "conf t", "end"}
ERROR_RE = re.compile(r"^\s*% ?(Invalid|Incomplete|Ambiguous|Authorization failed|Error)", re.M)
DESTRUCTIVE = re.compile(r"^\s*(reload|write erase|erase|format|delete|crypto key zeroize)\b", re.I)
BARE_ALLOWED = re.compile(r"^\s*switchport trunk allowed vlan (?!add\b|remove\b|except\b|none\b)", re.I)
BATCHABLE = re.compile(r"^\s*(interface \S.*|description .*|no description)\s*$", re.I)  # cosmetic only
STDIN_HINT = ("pass the commands in the command itself, as a here-doc on stdin "
              "(push.py push DEVICE --log DIR <<'EOF' ... EOF), so the approval shows them")


def load_device(repo, inventory, name, user):
    inv_path = Path(inventory) if inventory else Path(repo).expanduser() / "inventory.yaml"
    if not inv_path.exists():
        sys.exit(f"no inventory at {inv_path} (set it up with the network-snapshot skill)")
    inv = yaml.safe_load(inv_path.read_text(encoding="utf-8"))
    defaults = inv.get("defaults", {})
    for d in inv.get("devices", []):
        if d["name"] == name:
            dev = {**defaults, **d}
            dev["username"] = user  # pushes use the change account, never the read-only one
            dev.setdefault("device_type", "cisco_ios")
            return dev
    sys.exit(f"{name} is not in {inv_path}")


def netmiko_type(device_type):
    path = PLATFORMS / f"{device_type}.yaml"
    if not path.exists():
        sys.exit(f"no profile for device_type '{device_type}'")
    return yaml.safe_load(path.read_text(encoding="utf-8"))["netmiko_device_type"]


def read_stdin():
    if sys.stdin is None or sys.stdin.isatty():
        sys.exit(f"no commands on stdin: {STDIN_HINT}")
    return sys.stdin.read()


def clean(text):
    """The commands to send: lines minus blanks, # comments and conf t / end."""
    lines = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#") or line.strip().lower() in WRAPPERS:
            continue
        lines.append(line)
    return lines


def split_batch(text):
    """'@DEVICE' header lines start each device's block, in push order."""
    blocks, name = [], None
    for raw in text.splitlines():
        if raw.strip().startswith("@"):
            name = raw.strip()[1:].strip()
            blocks.append((name, []))
        elif raw.strip():
            if name is None:
                sys.exit("batch input must start with an @DEVICE line")
            blocks[-1][1].append(raw)
    return [(n, clean("\n".join(b))) for n, b in blocks]


def refused(lines):
    """Lines this tool will not send, with the reason."""
    out = []
    for line in lines:
        if DESTRUCTIVE.match(line):
            out.append((line, "destructive command"))
        elif BARE_ALLOWED.match(line):
            out.append((line, "replaces the trunk's VLAN list: use 'allowed vlan add <id>'"))
    return out


def show(dev, lines, sent=False):
    verb = "SENDING" if sent else "PREVIEW (nothing sent)"
    print(f"{verb} {dev['name']} ({dev['host']}), as {dev['username']}, {len(lines)} line(s):")
    for line in lines:
        print(f"  {line}")


def password_for(dev):
    pw = keyring.get_password(SERVICE, dev["username"])
    if not pw:
        sys.exit(f"no password stored for '{dev['username']}': run push.py --set-credential {dev['username']}")
    return pw


def connect(dev):
    from netmiko import ConnectHandler
    return ConnectHandler(device_type=netmiko_type(dev["device_type"]), host=dev["host"],
                          username=dev["username"], password=password_for(dev), timeout=30, fast_cli=False)


def record(log_dir, name, text):
    path = Path(log_dir) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n\n")


def do_push(dev, lines, log_dir):
    show(dev, lines, sent=True)
    stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    record(log_dir, f"{dev['name']}.txt", f"# {stamp} pushed as {dev['username']}\n" + "\n".join(lines))
    try:
        conn = connect(dev)
    except Exception as e:
        print(f"FAILED to connect to {dev['name']} ({dev['host']}): {e}. Nothing was sent.")
        record(log_dir, "push-log.md", f"## {stamp} push {dev['name']}: NOT CONNECTED ({e})")
        return 1
    try:
        out = conn.send_config_set(lines, read_timeout=90, error_pattern=ERROR_RE.pattern)
    except Exception as e:  # netmiko raises on error_pattern; anything sent before stays on the device
        out = f"{e}\n% Error: push stopped ({type(e).__name__})"
    finally:
        conn.disconnect()
    errors = [m.group(0).strip() for m in ERROR_RE.finditer(out)]
    result = "FAILED" if errors else "OK"
    record(log_dir, "push-log.md", f"## {stamp} push {dev['name']} as {dev['username']}: {result}\n\n```\n"
           + "\n".join(lines) + "\n```\n\nDevice output:\n\n```\n" + out.strip() + "\n```")
    print("\nDevice output:\n" + out.strip())
    if errors:
        print(f"\nFAILED on {dev['name']}: " + "; ".join(errors))
        print("Lines sent before the error are still on the device. Stop and re-read it before retrying.")
        return 1
    print(f"\nOK {dev['name']}: {len(lines)} line(s) applied, not saved yet (save after the post-check).")
    return 0


def do_save(dev, log_dir):
    try:
        conn = connect(dev)
    except Exception as e:
        print(f"FAILED to connect to {dev['name']} ({dev['host']}): {e}. Not saved.")
        return 1
    try:
        out = conn.save_config()
    finally:
        conn.disconnect()
    ok = "[OK]" in out or "Building configuration" in out
    stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    record(log_dir, "push-log.md", f"## {stamp} save {dev['name']}: {'OK' if ok else 'CHECK OUTPUT'}\n\n```\n{out.strip()}\n```")
    print(f"{'SAVED' if ok else 'CHECK'} {dev['name']}: {out.strip().splitlines()[-1] if out.strip() else 'no output'}")
    return 0 if ok else 1


def check(dev, lines, batch=False, pushing=True):
    """Problems that stop this device's commands from going out at all."""
    if not lines:
        return [f"{dev['name']}: no commands"]
    probs = [f"{dev['name']}: {line!r}: {why}" for line, why in refused(lines)]
    if batch:
        probs += [f"{dev['name']}: {line!r}: only interface descriptions can be batched; push this device on its own"
                  for line in lines if not BATCHABLE.match(line)]
    if pushing and dev["device_type"] not in PUSHABLE:
        probs.append(f"{dev['name']}: pushes are tested only on {sorted(PUSHABLE)}, this is {dev['device_type']}")
    return probs


def main():
    ap = argparse.ArgumentParser(description="Push approved config to network devices, commands on stdin.")
    ap.add_argument("--set-credential", metavar="NAME", help="store the change account's password in the OS store")
    ap.add_argument("action", nargs="?", choices=["preview", "push", "batch", "save"])
    ap.add_argument("devices", nargs="*", help="push/preview: one DEVICE.  save: DEVICE [DEVICE ...].  batch: none")
    ap.add_argument("--repo", default="~/network-snapshots", help="snapshot repo holding inventory.yaml")
    ap.add_argument("--inventory", help="inventory file (default: inventory.yaml in --repo)")
    ap.add_argument("--user", default="admin", help="change account (default: admin)")
    ap.add_argument("--log", help="the change folder: each device's commands and push-log.md go here")
    args = ap.parse_args()

    if args.set_credential:
        keyring.set_password(SERVICE, args.set_credential, getpass.getpass(f"password for {args.set_credential}: "))
        print(f"stored: service '{SERVICE}', user '{args.set_credential}'")
        return 0
    if not args.action:
        ap.error("give an action: preview, push, batch or save")
    if args.action != "preview" and not args.log:
        ap.error("--log CHANGE_DIR is required, so the change keeps a record of what was sent")
    load = lambda n: load_device(args.repo, args.inventory, n, args.user)  # noqa: E731

    if args.action == "save":
        if not args.devices:
            ap.error("save needs at least one DEVICE")
        return max(do_save(load(n), args.log) for n in args.devices)

    if args.action == "batch":
        if args.devices:
            ap.error(f"batch takes no device names; put @DEVICE lines in the input. {STDIN_HINT}")
        jobs = [(load(n), lines) for n, lines in split_batch(read_stdin())]
        if not jobs:
            sys.exit("batch input has no @DEVICE blocks")
        problems = [p for dev, lines in jobs for p in check(dev, lines, batch=True)]
        if problems:
            print("REFUSED, nothing sent:\n  " + "\n  ".join(problems))
            return 2
        print(f"BATCH {len(jobs)} device(s), in this order: {', '.join(d['name'] for d, _ in jobs)}\n")
        done = []
        for dev, lines in jobs:
            if do_push(dev, lines, args.log):
                left = [d["name"] for d, _ in jobs[len(done) + 1:]]
                print(f"\nBATCH STOPPED at {dev['name']}. Done: {done or 'none'}. Not sent: {left or 'none'}.")
                return 1
            done.append(dev["name"])
            print()
        print(f"BATCH OK: {', '.join(done)}. Not saved yet (save after the post-check).")
        return 0

    if len(args.devices) != 1:
        ap.error(f"{args.action} takes exactly one DEVICE (one device per run); {STDIN_HINT}")
    dev = load(args.devices[0])
    lines = clean(read_stdin())
    problems = check(dev, lines, pushing=args.action == "push")
    if problems:
        print("REFUSED, nothing sent:\n  " + "\n  ".join(problems))
        return 2
    if args.action == "preview":
        show(dev, lines)
        return 0
    return do_push(dev, lines, args.log)


if __name__ == "__main__":
    sys.exit(main())
