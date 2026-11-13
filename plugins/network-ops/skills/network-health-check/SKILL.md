---
name: network-health-check
description: Read-only, multi-vendor network health check for the whole network, one site or one device. Checks hardware, redundancy, routing, links, errors, spanning tree, CPU, logs and time, and writes a report with findings worst first and their evidence. Use for "health check", "is the network ok", "anything wrong at hq", or "is <device> healthy".
---

# Network health check

One question: is the network healthy right now? You collect with the network-snapshot engine,
read what it saved, run every check in `checks.md` (in this folder) using the files that
`vendors.md` names for each device's vendor, and write a report.

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
`unsupported_commands`, `command_errors`, `commit`, and `health`. Per device, `health` gives
`dir` (raw output of this run), `rejected` (health commands the device refused) and `previous`
(the last run's raw output and when it was taken, or null on a first run). Read the previous
output for every counter check: growth between the two runs is what matters.

For each device read two places:
- Health output (raw, live): `<repo>/.snapshot/health/<site>/<device>/*.txt`
- Snapshot files (just committed): `<repo>/<site>/<device>/*.txt`, including the running config.

Every vendor profile has health commands. Profiles marked `untested` were written from vendor
docs: read their output with care, and if it does not match what the check expects, put the check
under Not checked with what you saw, never a guessed value.

## Scoped runs (one site or one device)

Some checks need the other end: HSRP and spanning-tree root (both distribution switches), OSPF
and BGP neighbors, uplinks. For a device outside the run, read its latest committed snapshot
files and say how old they are ("hq-dist-sw-01 snapshot files, last changed in d521289,
2026-10-31 08:06": `git -C <repo> log -1 --format="%h %ci" -- <site>/<device>/`). Never log in
to it. Operational state on a peer (HSRP role, OSPF state) can have moved since: say so if a
finding depends on it.

## Compare with the last report

Two baselines, two jobs. Counters and logs compare with the previous health run (`previous` in
the report). Findings compare with the newest `*-health.md` in the reviews folder for the same or
a wider scope: read it. Mark each finding **new** or **unchanged**, list what is **fixed**, and compare error
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

Snapshot commit <hash, or "<HEAD hash> (no change)" when commit is null> · <N> devices checked · <verdict: Healthy | N findings, worst: <one line>>
Compared with the previous run at <time> (<minutes> min) | First run: counters are totals only

## Findings
### 1. [Critical] <device>: <what is wrong>  (new | unchanged)
- Evidence: `<command>` (<file path>): <the lines that show it, quoted>
- Fix: <what to check or change, in order>

## Healthy
- Reachable: 12/12 devices (snapshot report)
- OSPF: 9 neighbors FULL on 6 devices (show ip ospf neighbor)
- ...one line per check that passed

## Not checked
- <check> on <devices, grouped by vendor>: <why> (<what would make it checkable>)
  e.g. "Hardware and optics on 11 virtual devices: not applicable (virtual)", or
  "Environment on 8 IOS devices: rejected (not supported, or not permitted for claude-ro)".

## Known exceptions
- <item> (<where it is documented>)

## Compared with <previous report file>
- New: ... · Fixed: ... · Unchanged: ...
```

Severity order: Critical, High, Medium, Low. Within a level, the device closest to the core or
the internet first. Several symptoms of one cause (an uplink down, its OSPF neighbor gone, its
port-channel member down) are one finding with all the evidence, under the worst severity.

## Noise control

The report is read by someone who has to act on it. Every finding must be something they would
want to be woken for at its severity. Never a finding: blocked ports on redundant links, history in
counters that did not grow, user access ports going up and down, a device's own normal states
(2WAY/DROTHER, Idle (Admin), Simplex), anything listed as a known exception. Put each of those in
one Healthy or Known exceptions line at most. Healthy lines carry the numbers that prove it
(neighbors FULL, counters unchanged since <time>), so a reader can trust a short report.

## Tell the user

One line verdict, the worst finding if any, the report path. Say how many checks were not
checked and why, in one line.
