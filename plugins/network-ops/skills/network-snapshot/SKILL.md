---
name: network-snapshot
description: Take a read-only snapshot of every network device (configs and key operational state), save it to a git repo, and explain what changed since the last snapshot. Multi-vendor over SSH (Cisco IOS/IOS-XE, NX-OS, ASA, FortiGate, Arista, Juniper, Aruba AOS-CX, Palo Alto). Use when the user asks to snapshot, back up or capture the network, asks "what changed on the network", or wants a before/after around a change.
---

# Network snapshot

You run a bundled script that does all device access, then you explain the result. The script
logs in over SSH with a read-only account, runs the read-only commands listed in a vendor
profile, removes lines that change on their own (clocks, timers, counters), saves one file per
command, and commits the run to a git repo. Two snapshots in a row with no real change produce
an empty diff, so anything in the diff is a real change.

Files in this skill's folder:
- `scripts/snapshot.py`: the engine.
- `platforms/<device_type>.yaml`: one vendor profile each. `status: tested` or `untested`.
- `inventory.example.yaml`: an example inventory.
- `requirements.txt`: Python packages.

## Rules

- Read-only. Never configure a device, and never run device commands yourself (SSH, Netmiko, an
  MCP tool or anything else). All device access goes through `scripts/snapshot.py`.
- Never ask for, print or write a password. Passwords live in the OS credential store and the
  user sets them in their own terminal (see setup).
- Do not edit files inside the snapshot repo, and do not commit there yourself. The script owns it.

## First-time setup (only if the run says the inventory or a password is missing)

1. Python: find an interpreter that imports `netmiko`, `keyring` and `yaml`
   (`python3`, `python` or `py`). If none does, install from `requirements.txt` after the user
   agrees.
2. Snapshot repo: default `~/network-snapshots` (the user may pick another path; pass it with
   `--repo` on every run). Copy `inventory.example.yaml` to `<repo>/inventory.yaml` and fill it
   from the user's device list: name, host, site, device_type (a profile file name), username,
   and `credential` only when devices share a username but not a password.
3. Passwords: ask the user to run this in their own terminal, once per username or credential
   name (in Claude Code they can prefix it with `!`):
   `python <skill folder>/scripts/snapshot.py --set-credential <name>`
4. Tell the user each vendor needs a read-only account; the plugin README has the per-vendor steps.

## Run

```
python <skill folder>/scripts/snapshot.py [--repo PATH] [--site SITE | --device NAME]
```

No target means every device. The script prints a JSON report (also saved to
`<repo>/.snapshot/last-report.json`): `failures`, `reboots`, `changed` (files per device),
`unchanged`, `unsupported_commands`, `commit`, `first_snapshot`.

## Report to the user, in this order

1. **Failures first.** Each device that could not be reached or logged in to, with the error in
   plain words and the likely fix (unreachable, wrong password, account lacks rights, missing
   profile). The run kept going; say how many devices did succeed.
2. **Reboots.** Devices whose uptime went down since the last snapshot. This is often the most
   important line in the report.
3. **What changed, per device.** Read the real diff:
   `git -C <repo> diff HEAD~1 HEAD -- <site>/<device>/` and describe each change in network terms
   (a VLAN added, an OSPF neighbor gone, a route now via a different next hop, a policy edited),
   quoting the key lines. Group small related changes. Say plainly when something looks risky.
4. **Unchanged:** one line with the count.
5. **Unsupported commands:** one line per device type, only if present (routers rejecting switch
   commands is normal).

If `first_snapshot` is true there is nothing to compare yet: say the baseline is saved and how
many devices and files it holds. If `commit` is null and there are no failures, say the network
matches the last snapshot exactly.

## Before and after a change

Run a snapshot before the change and another after it, then report the diff between the two
commits (`git -C <repo> diff <before> <after>`). Profiles marked `untested` were written from
vendor docs and have not been run on real devices yet; if their output looks wrong (a command
rejected, a noisy line that changes every run), say so and suggest the profile fix.
