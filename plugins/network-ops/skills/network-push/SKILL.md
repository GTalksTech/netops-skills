---
name: network-push
description: Use when an approved change plan is ready to go onto network devices: pushing config to a switch, router or firewall, applying a change, or saving config after a post-check. Puts every switch command in the approval prompt itself, pushes one device at a time with the change account (descriptions can batch), stops on errors and records what was sent.
---

# Network push

The only way config goes onto a device. One script, `scripts/push.py`. The commands always go
IN the command, as a here-doc, never as a file path. That way the approval prompt shows every
switch command right where the user says yes, so nobody approves a command line they can't read.

```
python <this skill>/scripts/push.py push hq-dist-sw-02 --log changes/2026-10-30-vlan40 <<'EOF'
vlan 40
 name CAMERAS
interface range Ethernet0/2, Ethernet1/0 - 3
 switchport trunk allowed vlan add 40
EOF
```

- `push DEVICE --log DIR`: one device, the change account (default `admin`, password from the
  OS credential store). Stops on the first device error.
- `batch --log DIR`: several devices under ONE approval, in order, stopping at the first
  failure. Each device starts with an `@DEVICE` line. The script refuses the whole batch unless
  every line is an interface description.
- `save DEVICE [DEVICE ...] --log DIR`: saves the running config. Only after the post-check passes.
- `preview DEVICE`: same input, sends nothing. Optional; the approval prompt already shows it all.

`--log` is the change folder. The script writes each device's commands (`DEVICE.txt`) and the
device's output (`push-log.md`) there, so the change keeps a record of exactly what was sent.

It uses the network-snapshot skill's inventory, vendor profiles and credential store. Run it the
same way you run `snapshot.py` (same Python). Pushes work on tested profiles only (`cisco_ios`
today); anything else is refused.

## Rules

- Only push from an approved change plan. If there is no plan, or the user hasn't approved it,
  stop and say so.
- Interface descriptions go in one `batch`. Everything else is one `push` per device, in the
  order the plan sets, so every impactful push is its own approval. Never loop devices in one
  command, use a file instead of the here-doc, or write your own push script.
- Before each push, say in one line which device it is and what it does. Never say a device is
  configured until its push has come back OK.
- If a push fails, stop. Lines sent before the error are on the device. Re-read the device (a
  snapshot of that device) before you suggest anything, and offer the plan's rollback.
- The script refuses destructive lines and a trunk `allowed vlan <list>` without `add`. Never
  work around a refusal; fix the commands.
- Save only when the post-check passes, with one `save` listing every device touched. A rollback
  ends with a save too.

## Setup

The change account's password goes into the OS credential store once:
`python <this skill>/scripts/push.py --set-credential admin`
