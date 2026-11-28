# Spec: network-snapshot collects device state and a host table

Written in place of a GitHub issue (the build ran without tracker access by design). Decisions and
their reasons: `docs/snapshot-state-decisions.md`. Research: `docs/snapshot-state-research.md`.

## Problem statement

A network engineer runs network-snapshot and gets a good config differ, but only about half a
source of truth. It sees only the global routing table (on a lab router it misses the whole MGMT
VRF), it saves no ARP, MAC table or DHCP data, so end hosts and unmanaged switches are invisible,
and on FortiGate the SSH library it uses would change the console setting if paging were on.

## Solution

One snapshot run now also collects device state (per-VRF ARP, MAC tables, DHCP bindings, protocol
detail) into a git-ignored folder with the previous run beside it, commits a wider set of stable
output (all VRFs, all BGP families, interface and OSPF detail), and joins the host data into one
host table that says which device tables saw each host. A FortiGate with paging on is refused with
the one-line fix, never changed.

## User stories

1. As a network engineer, I want one snapshot run to collect config, stable structure and device state, so that I do not run three tools.
2. As a network engineer, I want routes, ARP and routing protocols from every VRF, so that the management VRF and customer VRFs are not invisible.
3. As a network engineer, I want a second run on a quiet network to show an empty git diff, so that anything in the diff is real.
4. As a network engineer, I want ARP, MAC and DHCP tables kept outside git with the previous run beside them, so that history is not flooded with churn.
5. As a network engineer, I want `--no-state` to skip the new tables, so that I can keep the old, faster run when I want it.
6. As a network engineer, I want heavy commands only with `--full`, so that a default run is safe on a busy core.
7. As a network engineer, I want a host table with IP, MAC, VLAN, switch and port, so that I can find where a host plugs in.
8. As a network engineer, I want each host row to say which tables showed it, so that I can judge how sure it is.
9. As a network engineer, I want no host row the devices did not show, so that I can trust the table.
10. As a network engineer, I want a host seen only on uplinks to be marked as such, so that I know its port is not proven.
11. As a network engineer, I want the report to list hosts new and gone since last run, so that I see arrivals without git noise.
12. As a network engineer, I want "this VRF has no IPv6" kept apart from "command rejected", so that my coverage list is honest.
13. As a network engineer, I want the report to show the account's privilege level, so that I know whether a rejected command is missing or not permitted.
14. As a network engineer, I want switch-only commands skipped on routers when the config shows the feature is absent, so that runs are shorter and the rejected list is short.
15. As a security-minded engineer, I want every command the tool builds from device output checked as read-only, so that a strange VRF name cannot become a config command.
16. As a security-minded engineer, I want VRF names validated before they reach a command, so that device output cannot inject text.
17. As a FortiGate admin, I want the tool to refuse a box with paging on and tell me the one-line fix, so that it never writes config.
18. As a FortiGate admin with VDOMs, I want a clear refusal that says VDOM support is not built yet, so that I am not surprised.
19. As a maintainer, I want new profile keys described in the profile comments, so that contributors can add them for other platforms.
20. As a network engineer, I want the docs to say plainly what the skill still cannot see, so that I do not assume coverage it lacks.

## Implementation decisions

- Profile schema gains: `state_commands` (list, like `commands`; each may carry `tier: full`,
  `when:`, `timeout:`), `vrfs: {cmd, regex}` (VRF discovery from this run's output), `{vrf}` in
  any command, `no_data_markers`, `privilege: {cmd, regex}`, `host_table`, and `when:` on committed
  commands too.
- Load-time guard: every command and template starts with a read verb; expanded commands are
  checked again before sending.
- VRF names must match `^[A-Za-z0-9_.:-]{1,32}$`; others are reported and skipped.
- State files: `.snapshot/state/<site>/<device>/`, previous run in `.snapshot/state-prev/`. State
  is saved as the device printed it (decision D17) and never committed.
- Host table: `.snapshot/hosts.csv` (and `hosts-prev.csv`), columns
  `ip, mac, vrf, vlan, device, port, sources, note`. Built only from devices in this run.
- Table parsers in `devicefacts.tables` (pure text in, rows out); join in `hosttable`.
- FortiGate: a read-only connection class that reads the console mode with `get system console`
  and refuses (raises) when it is not `standard` or cannot be read, and whose paging and logout
  steps send no config.
- Report gains: `state` (per device: dir, files, rejected, no_data, skipped_by_when, vrfs,
  invalid_vrfs, privilege), `hosts` (file, rows, new, gone), `no_data_commands`, `privilege`.

## Testing decisions

- Highest seam: `snapshot.run(args)` with a fake netmiko connection, as the existing tests do
  (`tests/test_health.py`). Used for: state saved and never committed, `--no-state`, `--full`,
  VRF expansion end to end, guard on built commands, no-data, `when:`, empty second-run diff,
  host table written.
- `load_profile` for schema errors and the read-verb guard.
- Pure functions with literal expected values from real IOS-XE 17.16 / FortiOS 8.0.1 output:
  each table parser, each new mask, the host join.
- The FortiGate read-only class tested against a fake base connection that records every
  string sent.

## Out of scope

Size gates, FortiOS `diagnose`/`execute`, FortiOS REST, VDOMs, other platform profiles, lab
config changes.

## Slices (tracer bullets, in order)

1. **State class end to end.** Blocked by: none. `state_commands` run by default, saved under
   `.snapshot/state` with a previous copy, never committed; `--no-state`; `--full` tier; report
   `state` block. Acceptance: state files exist, git status clean, `--no-state` runs none.
2. **Per-VRF commands.** Blocked by 1. VRF discovery, validation, `{vrf}` expansion, guard on
   expanded commands, no-data markers, privilege preflight. Acceptance: a fake device with VRFs
   MGMT and `bad;name` runs `show ip arp vrf MGMT` only and reports the bad name.
3. **FortiGate paging refusal.** Blocked by none. Acceptance: mode `more` raises before any
   command and nothing containing `config`/`set` is sent; `standard` proceeds; VDOM refused.
4. **Cisco and FortiOS profile additions with masks.** Blocked by 1, 2. Acceptance: every new
   mask has a test from lab text; profiles load; two fake runs give an empty diff.
5. **Host table.** Blocked by 1. Parsers and join, `hosts.csv`, new/gone in the report.
6. **`when:` conditions.** Blocked by 1.
7. **Docs, version, lab runs.** Blocked by all.
