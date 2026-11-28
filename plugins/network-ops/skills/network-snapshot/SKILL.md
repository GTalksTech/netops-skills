---
name: network-snapshot
description: Takes a read-only snapshot of every network device over SSH (configs, routing in every VRF, neighbors, ARP and MAC tables), commits the stable part to git, builds a host table of where each IP and MAC sits, and explains what changed. Multi-vendor (Cisco, FortiGate and others). Use when the user asks to snapshot, back up or document the network, asks what changed on the network, wants a before/after around a change, or asks where a host is connected.
---

# Network snapshot

You run a bundled script that does all device access, then you explain the result. One run:

1. Logs in over SSH with a read-only account and runs the read-only commands in the device's
   platform profile.
2. Commits the **committed output** (config and stable structure: interfaces, VLANs, every VRF's
   routes, neighbors, protocols) to a git repo, with clocks, timers and counters removed. A quiet
   network gives an empty diff, so anything in the diff is a real change.
3. Saves **device state** (ARP per VRF, MAC tables, DHCP bindings, protocol detail) outside git,
   keeping this run and the one before.
4. Joins ARP, MAC tables, CDP/LLDP and DHCP into a **host table**, `.snapshot/hosts.csv`, one row
   per address with the tables that showed it.

Files in this skill's folder:
- `scripts/snapshot.py`: the engine. `scripts/fortigate_guard.py`: the read-only FortiGate login.
- `platforms/<device_type>.yaml`: one platform profile each, with its status (untested,
  lab-tested, tested).
- `inventory.example.yaml`, `requirements.txt`.
- [references/reading-results.md](references/reading-results.md): every report field and how to explain it. Read it
  before your first report in a session.
- [references/coverage.md](references/coverage.md): what a run collects and what it cannot see.
  Read it when the user asks "does it get X" or a result looks incomplete.
- [references/profiles.md](references/profiles.md): profile keys, for fixing or adding a platform.

## Rules

- Read-only. Never configure a device, and never run device commands yourself (SSH, Netmiko, an
  MCP tool or anything else). All device access goes through `scripts/snapshot.py`.
- Never ask for, print or write a password. The script finds each one itself: an environment
  variable `NETOPS_SECRET_<NAME>`, the inventory's `credentials: command:` (a vault CLI), then the
  OS credential store. The user sets them up in their own terminal (see setup).
- Do not edit files inside the snapshot repo or its `.snapshot/` folder, and do not commit there.
  The script owns it.
- Never present a host table row as more certain than its `sources` and `note` say.

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
   If they keep passwords in a vault or password manager instead, point them to the plugin
   README's Credentials section (a `credentials:` block in the inventory); never run the vault
   CLI yourself.
4. Tell the user each vendor needs a read-only account; the plugin README has the per-vendor steps.
   A FortiGate also needs its console set to standard output (the run says so if not).

## Run

```
python <skill folder>/scripts/snapshot.py [--repo PATH] [--site SITE | --device NAME] [--no-state] [--full]
```

No target means every device. `--no-state` skips device state and the host table (the faster,
config-only run). `--full` adds heavy commands (full OSPF database, crypto SAs, the FortiGate route
database); use it only when the user asks for depth. The script prints a JSON report, also saved
to `<repo>/.snapshot/last-report.json`.

## Report to the user, in this order

1. **Failures first**, with the likely fix. A FortiGate refused for paging or VDOMs is a failure
   with a one-line fix the user makes; say it plainly.
2. **Reboots.**
3. **What changed, per device**, from `git -C <repo> diff HEAD~1 HEAD -- <site>/<device>/`, in
   network terms, quoting the key lines.
4. **Hosts**: rows in the host table and the hosts new and gone since the last run.
5. **Unchanged**: one line with the count.
6. **Coverage**: rejected commands per device type (with the account's privilege level), commands
   with no data, and anything `references/coverage.md` says this run could not see. Short.

Field-by-field detail, the first-snapshot and first-run-after-upgrade cases, and how to answer
"where is host X": [references/reading-results.md](references/reading-results.md).

## Before and after a change

Run a snapshot before the change and another after it, then report the diff between the two
commits (`git -C <repo> diff <before> <after>`) and the host changes. Profiles marked `untested`
were written from vendor docs; if their output looks wrong (a command rejected, a noisy line that
changes every run), say so and suggest the profile fix (`references/profiles.md`).
