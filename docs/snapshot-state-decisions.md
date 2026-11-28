# network-snapshot state expansion: decision log

Build of 2026-11-28 on branch `claude/snapshot-state-expansion`. The owner was not available, so
the grill ran with the builder answering, facts looked up (code, `docs/snapshot-state-research.md`,
the installed netmiko source, the lab) and each decision cross-checked with Jev (TypeSafe), the
owner's scoring model, answering as his target viewer (Legacy Larry). Jev is a second opinion, not
the decider; every disagreement is listed with the call made and why.

Jev specs and raw scores: `2-Areas/typesafe/decisions/jev_snapshot_<topic>_2026-11-28.json` in
the G Talks Tech workspace (outside this repo). Questions on every spec: `adopt` (would Larry
install and keep using it) and `trust` (does it feel safe read-only against production), 0 to 1.

Skill format sources, fetched 2026-11-28: Agent Skills specification (agentskills.io/specification,
no revision number shown on the page; SKILL.md under 500 lines, description up to 1024 characters,
references one level deep) and Anthropic's skill authoring best practices
(platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices; third-person
what-and-when description, SKILL.md as a table of contents, deterministic work in scripts,
reference files over 100 lines get a contents list).

## Round 1: the shape of a run

### D1. Does state run by default, and is ARP committed?

Options (Jev `state`, adopt / trust):
- A. State by default, saved outside git with a previous copy, `--no-state` to skip; ARP state only: 0.64 / 0.62
- B. As A, but ARP also committed (age masked, sorted by IP): 0.67 / 0.68
- C. State only with an opt-in `--state` flag: 0.79 / 0.81
- D. Commit everything: 0.50 / 0.45

Recommendation and decision: **A**, plus a host change list in the report (hosts new and gone
since the previous run), which gives B's benefit without git noise.

Jev disagreed (it prefers C, opt-in). Went with A because the owner's goal is "one skill run builds
the source of truth", which an opt-in flag defeats, and the build brief makes state the default.
`--no-state` keeps the old behavior one flag away. Not B: an ARP entry that ages out between runs
would break the promise that a quiet network shows an empty git diff, and the host table already
shows host arrivals and departures without touching git.

### D2. Replace the global-table commands or keep both?

`show ip route` → `show ip route vrf *`, `show vrf` → `show vrf detail`, `show ip bgp summary` →
`show bgp all summary` (research 3.3, lab: the global table misses the whole MGMT VRF).

Options (Jev `rename`): A replace once, rename shows in the first diff: 0.65 / 0.57; B keep both:
0.55 / 0.63; C keep the old ones: 0.26 / 0.56.

Decision: **A**, and the README and SKILL.md say the first run after the upgrade shows those
files replaced. Jev rated B a little safer-feeling; A avoids near-duplicate committed files that
would both change on every real routing change. Agrees with Jev on adoption.

### D3. What ships in this release?

Options (Jev `scope`): A state + VRF + host table, gates and `when:` later: 0.63 / 0.55;
B state + VRF + `when:` + size gates, host table later: 0.69 / 0.65; C hold until all done:
0.49 / 0.66; D state + VRF + host table + `when:`, size gates later: 0.71 / 0.66.

My first recommendation was A. Jev preferred D, and its reason holds: `when:` is small and stops
routers running switch commands on production. Decision: **D**, built in that order (host table
before `when:`). Size gates are a follow-up; meanwhile the route, MAC and BGP-neighbor commands get
a 300 second read timeout (research 6.7).

### D4. FortiGate paging (netmiko writes config when the console is in "more" mode)

Fact, confirmed in the installed netmiko 4.8.0 `netmiko/fortinet/fortinet_ssh.py`:
`session_preparation` reads the console output mode and, when it is `more`, `disable_paging`
sends `config system console` / `set output standard` / `end`, and `cleanup` sends
`set output more` back at logout. With VDOMs on it also sends `config global` just to read the
mode. A read-only tool must do none of this.

Options (Jev `fortipaging`): A refuse before any command and explain the one-line setting; refuse
VDOM-mode boxes too, since the mode cannot be read without `config global`: 0.78 / 0.85;
B let the driver change it: 0.33 / 0.24; C refuse paging but allow `config global` for VDOM
boxes: 0.33 / 0.28; D wait for a `--More--` prompt and time out: 0.28 / 0.39.

Decision: **A**. Jev agrees. The skill reads the mode with `get system console` (a `get`), never
`config global`, and overrides the driver's paging and logout steps so neither can send config.
A VDOM-mode FortiGate is refused with a message that says why; whether and how to support VDOMs
is left to the owner (see Reserved).

### D5. Host table: format and how sure it claims to be

Options (Jev `hosttable`): A `hosts.csv` with an evidence column and a note when the port is
uncertain, rows only for what a device showed, previous copy kept: 0.79 / 0.77; B JSON only:
0.50 / 0.54; C fill in a best-guess port for every host: 0.20 / 0.25; D no join: 0.67 / 0.74.

Decision: **A**. Jev agrees, and C's low score backs the "never invent a row" rule.

## Round 2: decisions that hang off round 1

These follow from settled answers or from facts; none needed a Jev run.

- **D6. Where state lives.** `<repo>/.snapshot/state/<site>/<device>/`, the previous run moved to
  `.snapshot/state-prev/...`, exactly like health. The host table is network-wide:
  `.snapshot/hosts.csv` and `.snapshot/hosts-prev.csv`. `.snapshot/` is already git-ignored.
- **D7. Health is unchanged.** network-health-check reads `show interfaces`, `get system arp` and
  the rest from the health folder, so nothing moves out of `health_commands`. A command in both
  lists runs once per device when `--health` is on and is saved to both folders.
- **D8. VRF discovery.** Profile-driven (`vrfs: {cmd, regex}`), not Cisco code: the VRF list
  comes from this run's `show vrf detail` output. Each name must match
  `^[A-Za-z0-9_.:-]{1,32}$` before it goes into a command; a name that fails is reported and
  skipped. `{vrf}` commands expand once per valid VRF; a command with no VRFs to expand is
  skipped. Two VRFs whose file names collide (case only) keep the first and report the second.
- **D9. Read-verb guard on built commands.** The guard runs at profile load on the templates and
  again on every expanded command just before it is sent.
- **D10. "No data" is not an error.** New profile key `no_data_markers` (research 6.3). Output
  that matches is saved as usual (it is stable text) and listed under `no_data` in the report.
- **D11. `show privilege` preflight.** Profile key `privilege: {cmd, regex}`; the level goes in
  the report, and rejected commands are labeled "not supported here, or not permitted at
  privilege N". No file is saved.
- **D12. Tiers.** Per-command `tier: full` on state commands; those run only with `--full`.
- **D13. `when:`.** A regex matched against the device's saved config from this run (multiline).
  A command whose `when:` does not match is skipped and listed under `skipped_by_when`, not
  counted as rejected.
- **D14. Where the parsing lives.** Table parsers (ARP, MAC table, CDP/LLDP, DHCP snooping, DHCP
  bindings, FortiGate ARP, trunk list) go in a new module `lib/devicefacts/tables.py` so the
  network-diagram skill can reuse them; the join goes in a new package `lib/hosttable/`. No new
  dependency: small own parsers, written after reading how SuzieQ, Genie, NAPALM and
  ntc-templates model these tables (no code or templates copied).
- **D15. Edge port rule.** A host's port is a MAC-table port that is not a trunk and has no
  CDP/LLDP neighbor that is a switch or router (a phone or AP neighbor does not count). If the MAC is only seen on
  such uplinks, the port is left empty and the note says "seen only on uplinks". A MAC seen on two
  edge ports gets both, with a note. Rows are keyed by (VRF, IP) for ARP-backed hosts and by MAC
  for MAC-only sightings.
- **D16. Version.** network-ops plugin 0.2.1 → 0.3.0 (new behavior, default run changes).

- **D17. State is saved raw.** Like health, state keeps the output as the device printed it;
  the host table is the stable, derived view. (The spec first proposed masking and sorting state;
  dropped as needless: nothing diffs state files.)
- **D18. Timer masks absorb padding.** On Cisco, `00:41:07`, `1d02h` and `2w3d` all become `--`
  with the padding after them shrunk to one space, so an age that changes width does not shift the
  line. Costs a one-time diff on upgrade (said in the README).

## After the build: review and lab findings

An independent review (a fresh agent given the diff, not my conclusions) found no path to a write.
Fixed from it: NX-OS `>`, `>>` and `;` refused by the guard; phone and AP neighbors no longer make
a port an uplink; CSV cells from device text cannot start a spreadsheet formula; DHCP bindings
without a MAC match only within their VRF; a host-table error can no longer cost the run its commit.
Not fixed: an access (non-trunk) port-channel whose CDP neighbor sits on a member port is not seen
as an uplink (MAC table shows Po1, CDP shows the member); FortiOS 6 (no `get system console`) is
refused by the guard.

The lab runs found two profile issues, both fixed with a test: FortiOS 8 route ages over a week
(`01w6d19h`) had no mask (a gap that predates this build), and the `does not exist` no-data marker
also matched `show boot` (`BOOT variable does not exist`); markers are now specific.

## Follow-ups (not in this release)

- Access port-channels with CDP on members (see above).
- BGP per-neighbor advertised and received routes (`--full`): need a `{neighbor}` template
  validated like `{vrf}`.
- network-health-check runs `--health`, which now also collects state; it could pass `--no-state`
  for speed.

- Size gates before `show ip route vrf *` and `show mac address-table` (research 6.6, suggested
  20,000 entries, per-device override).
- Commit ARP in masked form, if the host change list proves too weak.
- Interface facts (MAC, MTU, speed) parsed from `show interfaces` into a committed derived file.
- The other 12 platform profiles: same two gaps (research 6.13).

## Reserved for the owner (nothing built depends on these)

1. FortiOS `diagnose` / `execute` commands, even as an exact allowlist (research 4.2, 7.4).
2. A FortiOS REST API source (research 4.5).
3. FortiGate VDOM support (today a VDOM-mode box is refused, see D4).
4. Any lab configuration change, including new `privilege exec level 5` lines.
5. Pushing, publishing, PRs.
6. The other 12 platform profiles.
