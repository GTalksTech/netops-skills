---
name: network-diagram
description: Draw an editable draw.io network diagram from the show output network-snapshot already saved (CDP, LLDP, interface addresses, VLANs, trunks, port-channels) and/or a spreadsheet of links. One file with a page per layer (physical L1, subnets L3, VLANs L2), finds firewalls and tunnels that neighbor discovery can't see, and keeps the diagram in git next to the snapshots. Read-only. Use when the user asks for a network diagram, topology map, L1/L2/L3 drawing, "draw my network", or a diagram from a spreadsheet of links.
---

# Network diagram

You run a bundled script, then explain its report. The script never touches a device: it reads
the snapshot repo network-snapshot keeps (the one the user chose on first use), and any
spreadsheet of links the user gives. It writes one draw.io file with three pages, a Markdown and a JSON report,
and a links CSV into `<repo>/diagrams`, and commits them there.

Files in this skill's folder:
- `scripts/diagram.py`: the engine (`run`, `tag`).
- `scripts/drawio.py`: draws the pages. Parsers and link finding live in the plugin's shared
  library (`lib/topology`, `lib/devicetags`), shared with the other network-ops skills.

## Rules

- Read-only. Never configure a device and never connect to one (no SSH, API or MCP calls to
  devices). Fresh data comes from network-snapshot: if the snapshot is old or missing, offer to
  run that skill first, then run this one.
- Never change `inventory.yaml` yourself. The `tag` command shows a role change; it is written
  only with `--write`, after the user approved that exact change.
- Don't move devices or redraw in the .drawio file by hand: the next run overwrites it. Tell the
  user to fix a device's place with its role tag, and a missing link with the spreadsheet.

## Run

```
python <skill folder>/scripts/diagram.py run [--network NAME | --repo PATH] [--links links.csv ...]
       [--site SITE] [--no-subnet] [--out DIR] [--no-export] [--no-commit] [--title TEXT]
```

- Snapshot repo: with no `--network` or `--repo`, the one network-snapshot uses (same settings).
  The run prints `Snapshot repo: <path> (network: <name>)` on stderr and `repo` in the report;
  tell the user where the diagram went. If it exits with `"error": "no_snapshot_repo"`, none is
  set up yet: follow network-snapshot's first-time setup (ask the user where to keep it, then
  `snapshot.py --set-repo PATH`), and run this again.

- `--links`: a CSV of links, repeatable. Columns `device, port, port, device` (header row
  optional); with a header, the columns `description`, `vlan`, `speed` and `site` are read too.
  With no snapshot repo set up, a spreadsheet alone is enough (`--out` then picks the folder).
- `--no-subnet`: neighbor and spreadsheet links only. Shows what CDP/LLDP alone miss.
- PDF and `.drawio.svg` copies are made when draw.io Desktop is installed; otherwise the report
  says so. The `.drawio` file needs nothing installed: app.diagrams.net, File > Open from > Device.

The script prints a JSON report (also `<out>/report.json`): `links_by_kind`, `subnet_links`,
`port_channels`, `roles`, `roles_to_confirm`, `roles_missing`, `unlinked_devices`,
`unknown_neighbors`, `coverage_gaps`, `files`, `exports`, `git`.

## What the pages show

- **Physical (L1)**: every device by site, top to bottom by device role (provider, edge,
  firewall, core, distribution, access). Interface names at each end; a port-channel is one thick
  link with its member count. Hover a link for both interface descriptions.
- **Subnets (L3)**: each subnet as a node, with the interface and host address that joins it.
- **VLANs (L2)**: trunks labelled with their allowed VLANs, each switch's VLANs under its name.
  Only drawn when the snapshot has VLAN output (Cisco IOS/IOS-XE today).

Link kinds (CONTEXT.md): a **neighbor link** is one a device reported by CDP or LLDP (solid
blue). A **subnet link** is two interfaces sharing a /30 or /31 that no neighbor protocol saw
(red dashed), a **tunnel** the same over tunnel interfaces (purple dashed). Spreadsheet links are
green. Firewalls and tunnels usually show up only as subnet links: say so, it's expected.

## Report to the user, in this order

1. One line: devices, links by kind, the pages written, and where the file is.
2. **Links neighbor discovery can't see** (`subnet_links`): which devices only appear through
   shared addresses, and that turning on LLDP where the device supports it would confirm them.
3. **Coverage gaps**: devices with no CDP/LLDP output, LLDP off, or no snapshot, with the fix.
4. **Unknown neighbors** (in CDP/LLDP, not in the inventory) and **unlinked devices** (in the
   inventory, no link found): both are drawn, never dropped.
5. **Device roles to confirm**: each guessed role with the reason, and the tag command to accept
   it. Ask before running any of them with `--write`:
   `python <skill folder>/scripts/diagram.py tag --device NAME --role ROLE [--network NAME | --repo PATH] [--write]`
   Roles are shared with every network-ops skill: a device is described once (docs/adr/0002).
6. Exports and git: whether the PDF/SVG copies were made, and whether the run was committed.

## Unattended runs

Run it right after the scheduled network-snapshot, so the diagram in git is always as current as
the last snapshot. A scheduled run never prompts, so it names the same network (or folder) as the
snapshot job: `--network NAME` or `--repo PATH`, never the default, which can change. The user
adds it to their own scheduler; show them the line, never install it:

- Linux or macOS cron, every day at 06:15:
  `15 6 * * * python3 <skill folder>/scripts/diagram.py run --network NAME`
- Windows Task Scheduler: `schtasks /Create /SC DAILY /ST 06:15 /TN network-diagram /TR
  "py <skill folder>\scripts\diagram.py run --network NAME"`

A scheduled run never changes the inventory: guessed roles are only listed in the report.

## Platforms

Neighbor links read Cisco CDP and LLDP (IOS, IOS-XE, NX-OS) and Arista-style LLDP. Addresses come
from Cisco configs and FortiOS. VLANs, trunks and port-channels: Cisco IOS/IOS-XE. Other
platforms' devices are still drawn, with their missing pieces listed as coverage gaps. To add
one, add its parser to `lib/topology/parsers.py` and a test with real (redacted) output.
