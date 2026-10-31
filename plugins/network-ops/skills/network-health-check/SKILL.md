---
name: network-health-check
description: Answer "is the network healthy right now?" for the whole network, one site or one device, read-only. Runs the network-snapshot engine with --health, then checks reachability, reboots, down interfaces, errors, link load, port-channels, OSPF, BGP, HSRP vs spanning-tree root, inconsistent STP ports, NTP, CPU, memory and logs, and writes a report: findings worst first with evidence and fix, then what checked out healthy. Use when the user asks for a health check, "is the network ok", "anything wrong at hq", or "is <device> healthy".
---

# Network health check

One question: is the network healthy right now? You collect with the network-snapshot engine,
read what it saved, run every check in `checks.md` (in this folder), and write a report.

## Rules

- Read-only. Never configure a device and never run device commands yourself (SSH, Netmiko, an
  MCP tool or anything else). All device access goes through the network-snapshot skill's
  `scripts/snapshot.py`. Its setup (Python, inventory, passwords) is in that skill's SKILL.md.
- Never edit files in the snapshot repo. The script owns it.
- Suggest fixes; never apply them. A fix that changes a device goes through the workspace's
  change process (in lab v2: `changes/`), and only when the user asks.
- Every finding and every "healthy" line names the command and file it came from.
- No data is not healthy. A check whose command is unsupported, rejected or missing for that
  vendor goes under **Not checked**, with the reason.
- Known exceptions: read the workspace instructions (AGENTS.md / CLAUDE.md) for documented lab or
  site exceptions. Matching items go in one **Known exceptions** line, never under Findings.

## Run

```
python <network-snapshot skill>/scripts/snapshot.py --health [--repo PATH] [--site SITE | --device NAME]
```

No target means every device. Use the same Python that runs snapshots. The run also takes a
normal snapshot and commits it; that is expected. The JSON report (also in
`<repo>/.snapshot/last-report.json`) gives `failures`, `reboots`, `up_less_than_24h`,
`unsupported_commands`, `commit`, and `health` (per device: the folder of raw health output).

For each device read two places:
- Health output (raw, live): `<repo>/.snapshot/health/<site>/<device>/*.txt`
- Snapshot files (just committed): `<repo>/<site>/<device>/*.txt`, including the running config.

Vendors with no `health_commands` in their profile (everything except `cisco_ios` and
`fortinet` today) get only the checks the snapshot files can answer.

## Scoped runs (one site or one device)

Some checks need the other end: HSRP and spanning-tree root (both distribution switches), OSPF
and BGP neighbors, uplinks. For a device outside the run, read its latest committed snapshot
files and say how old they are ("hq-dist-sw-01 snapshot files, last changed in d521289,
2026-10-31 08:06": `git -C <repo> log -1 --format="%h %ci" -- <site>/<device>/`). Never log in
to it. Operational state on a peer (HSRP role, OSPF state) can have moved since: say so if a
finding depends on it.

## Compare with the last report

If the reviews folder already has a `*-health.md` for the same or a wider scope, read the newest
one. Mark each finding **new** or **unchanged**, list what is **fixed**, and compare error
counters with the values recorded there (counters growing since then is what matters).

## Report

Save to the workspace's reviews folder (lab v2: `reviews/YYYY-MM-DD-HHMM-health.md`; read
`reviews/AGENTS.md` first), named from the report's `taken` time. If that name exists (two
runs in one minute), add the scope: `...-HHMM-health-<site or device>.md`. Never overwrite or
edit an older report.

When the run's `commit` is null nothing changed: cite the current HEAD
(`git -C <repo> log -1 --format="%h %ci"`) as the snapshot the files match.

```
# Health check: <scope>, <YYYY-MM-DD HH:MM>

Snapshot commit <hash> · <N> devices checked · <verdict: Healthy | N findings, worst: <one line>>

## Findings
### 1. [Critical] <device>: <what is wrong>  (new | unchanged)
- Evidence: `<command>` (<file path>): <the lines that show it, quoted>
- Fix: <what to check or change, in order>

## Healthy
- Reachable: 12/12 devices (snapshot report)
- OSPF: 9 neighbors FULL on 6 devices (show ip ospf neighbor)
- ...one line per check that passed

## Not checked
- <check> on <device>: <why> (<what would make it checkable>)

## Known exceptions
- <item> (<where it is documented>)

## Compared with <previous report file>
- New: ... · Fixed: ... · Unchanged: ...
```

Severity order: Critical, High, Medium, Low. Within a level, the device closest to the core or
the internet first. Several symptoms of one cause (an uplink down, its OSPF neighbor gone, its
port-channel member down) are one finding with all the evidence, under the worst severity.

## Tell the user

One line verdict, the worst finding if any, the report path. Say how many checks were not
checked and why, in one line.
