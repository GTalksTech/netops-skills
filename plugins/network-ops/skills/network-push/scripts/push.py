#!/usr/bin/env python3
# ============================================================
# Script:       push.py
# Purpose:      Push one approved block of config to ONE network device, the
#               controlled way: preview it first (sends nothing), push it with the
#               change account, stop on the first device error, log exactly what
#               was sent, and save the config only when asked (after the post-check).
# Usage:        python push.py preview DEVICE FILE
#               python push.py push DEVICE FILE [--log DIR]
#               python push.py save DEVICE [DEVICE ...] [--log DIR]
#               python push.py --set-credential admin
# Dependencies: Python 3.9+, netmiko, keyring, pyyaml (same as network-snapshot).
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/netops-skills (plugins/network-ops)
# Notes:        Shares the network-snapshot skill's inventory, vendor profiles and
#               credential store. One device per run, so every push is its own
#               approval. Pushes are allowed only on tested profiles (cisco_ios).
#               Refuses obviously destructive lines (reload, erase, format, delete)
#               and a trunk "allowed vlan <list>" without add/remove, which replaces
#               the list and drops every other VLAN on the trunk.
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
            return dev
    sys.exit(f"{name} is not in {inv_path}")


def netmiko_type(device_type):
    path = PLATFORMS / f"{device_type}.yaml"
    if not path.exists():
        sys.exit(f"no profile for device_type '{device_type}'")
    return yaml.safe_load(path.read_text(encoding="utf-8"))["netmiko_device_type"]


def read_lines(cfg_file):
    """The commands to send: the file's lines minus blanks, # comments and conf t / end."""
    lines = []
    for raw in Path(cfg_file).read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#") or line.strip().lower() in WRAPPERS:
            continue
        lines.append(line)
    if not lines:
        sys.exit(f"{cfg_file} has no commands")
    return lines


def refused(lines):
    """Lines this tool will not send, with the reason."""
    out = []
    for line in lines:
        if DESTRUCTIVE.match(line):
            out.append((line, "destructive command"))
        elif BARE_ALLOWED.match(line):
            out.append((line, "replaces the trunk's VLAN list: use 'allowed vlan add <id>'"))
    return out


def preview(dev, lines):
    print(f"PREVIEW {dev['name']} ({dev['host']}, {dev['device_type']}), as {dev['username']}. "
          f"{len(lines)} line(s), nothing sent:")
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


def log(log_dir, text):
    if not log_dir:
        return
    path = Path(log_dir) / "push-log.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n\n")


def do_push(dev, lines, log_dir):
    try:
        conn = connect(dev)
    except Exception as e:
        print(f"FAILED to connect to {dev['name']} ({dev['host']}): {e}. Nothing was sent.")
        return 1
    try:
        out = conn.send_config_set(lines, read_timeout=90, error_pattern=ERROR_RE.pattern)
    except Exception as e:  # netmiko raises on error_pattern; anything sent before stays on the device
        out = f"{e}\n% Error: push stopped ({type(e).__name__})"
    finally:
        conn.disconnect()
    errors = [m.group(0).strip() for m in ERROR_RE.finditer(out)]
    stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result = "FAILED" if errors else "OK"
    log(log_dir, f"## {stamp} push {dev['name']} as {dev['username']}: {result}\n\n```\n"
                 + "\n".join(lines) + "\n```\n\nDevice output:\n\n```\n" + out.strip() + "\n```")
    print(out.strip())
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
    log(log_dir, f"## {stamp} save {dev['name']}: {'OK' if ok else 'CHECK OUTPUT'}\n\n```\n{out.strip()}\n```")
    print(f"{'SAVED' if ok else 'CHECK'} {dev['name']}: {out.strip().splitlines()[-1] if out.strip() else 'no output'}")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Preview, push or save config on one network device.")
    ap.add_argument("--set-credential", metavar="NAME", help="store the change account's password in the OS store")
    ap.add_argument("action", nargs="?", choices=["preview", "push", "save"])
    ap.add_argument("targets", nargs="*", help="preview/push: DEVICE FILE.  save: DEVICE [DEVICE ...]")
    ap.add_argument("--repo", default="~/network-snapshots", help="snapshot repo holding inventory.yaml")
    ap.add_argument("--inventory", help="inventory file (default: inventory.yaml in --repo)")
    ap.add_argument("--user", default="admin", help="change account (default: admin)")
    ap.add_argument("--log", help="folder for push-log.md (default: the config file's folder)")
    args = ap.parse_args()

    if args.set_credential:
        keyring.set_password(SERVICE, args.set_credential, getpass.getpass(f"password for {args.set_credential}: "))
        print(f"stored: service '{SERVICE}', user '{args.set_credential}'")
        return 0
    if not args.action:
        ap.error("give an action: preview, push or save")

    if args.action == "save":
        if not args.targets:
            ap.error("save needs at least one DEVICE")
        rc = 0
        for name in args.targets:
            rc |= do_save(load_device(args.repo, args.inventory, name, args.user), args.log)
        return rc

    if len(args.targets) != 2:
        ap.error(f"{args.action} needs exactly one DEVICE and one FILE (one device per run)")
    name, cfg_file = args.targets
    dev = load_device(args.repo, args.inventory, name, args.user)
    dev.setdefault("device_type", "cisco_ios")
    lines = read_lines(cfg_file)
    bad = refused(lines)
    if bad:
        for line, why in bad:
            print(f"REFUSED: {line!r}: {why}")
        return 2
    if args.action == "preview":
        preview(dev, lines)
        return 0
    if dev["device_type"] not in PUSHABLE:
        sys.exit(f"pushes are tested only on {sorted(PUSHABLE)}; {name} is {dev['device_type']}")
    return do_push(dev, lines, args.log or str(Path(cfg_file).resolve().parent))


if __name__ == "__main__":
    sys.exit(main())
