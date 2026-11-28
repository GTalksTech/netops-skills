# Reading the snapshot results

## Contents
- Result fields
- The host table
- Answering "where is host X"
- Special cases: first snapshot, first run after an upgrade, nothing changed

## Result fields

`snapshot.py` prints this JSON and saves it to `<repo>/.snapshot/last-report.json`.

| Field | Meaning | How to report it |
|---|---|---|
| `failures` | Devices not reached, not logged in to, or refused | First, each with the error in plain words and the fix: unreachable, wrong password, account lacks rights, missing profile, FortiGate console paging (the user sets `config system console` / `set output standard` / `end` once) or VDOMs on (not supported yet) |
| `reboots`, `up_less_than_24h` | Uptime went down since last run; booted in the last day (with reload reason) | Second; often the most important line |
| `commit`, `first_snapshot` | The git commit for this run (null when nothing changed) | See special cases |
| `changed` | Committed files changed, per device (`M` / `A` / `D` plus file) | Read the real diff and explain it in network terms |
| `unchanged` | Devices with no committed change | One line with the count |
| `unsupported_commands` | Committed commands the device rejected | Group by device type. Routers rejecting switch commands, and virtual images rejecting hardware commands, is normal |
| `no_data_commands` | Committed commands accepted with nothing to show (`% BGP not active`) | Coverage line only; not an error |
| `skipped_by_when` | Commands not run because the config does not use that feature | Usually not worth mentioning; say so if the user asks why a feature's output is missing |
| `privilege` | The account's privilege level per device (Cisco) | With rejected commands: "not supported here, or not permitted at privilege N" |
| `command_errors` | Commands that timed out or broke; the rest of the device still ran | Name them; suggest a longer `timeout:` in the profile if it is a big table |
| `retired_files` | Per device: committed files removed because no command in the profile makes them any more (a command dropped or renamed in an upgrade, or a VRF the device no longer has) | Say they were removed and why; they show as deleted in the diff, not as a network change |
| `run` | Seconds and commands sent per device | Only if asked, or if a device is unusually slow |
| `state` | Per device: `dir`, `files`, `rejected`, `no_data`, `vrfs`, `invalid_vrfs`, `previous` | Mention `invalid_vrfs` (VRF names refused because they contain characters a command must never carry) every time |
| `hosts` | `file`, `rows`, `kinds` (host / network-device / virtual), `changes` (`new`, `gone`, or null on the first run) | Count, then the new and gone hosts |
| `health` | Only with `--health` (network-health-check) | Not part of a snapshot summary |

The state folder holds each command's output as the device printed it, under
`.snapshot/state/<site>/<device>/`, with the previous run in `.snapshot/state-prev/`. It is never
committed. To compare one table between runs, diff the two folders' files directly.

## The host table

`.snapshot/hosts.csv` (previous run: `hosts-prev.csv`). One row per address seen, built only from
the devices in this run. Columns:

| Column | Meaning |
|---|---|
| `ip`, `mac` | Either may be empty: a MAC seen only in a MAC table has no IP; an interface address a FortiGate lists may have no MAC |
| `vrf` | The VRF the ARP entry was in (`default` for the global table). VRFs are matched across devices by name |
| `vlan` | From the MAC table or DHCP snooping; for a VLAN interface address, the interface's VLAN |
| `device`, `port` | For a `host`: the edge port its MAC was learned on. For a `network-device`: the device and interface that own the address |
| `kind` | `host`; `network-device` (an address of a device in the run, or a CDP/LLDP neighbor); `virtual` (an HSRP, VRRP or GLBP virtual MAC) |
| `sources` | Every table that showed the row: `arp:<dev>`, `arp-self:<dev>`, `if-self:<dev>`, `mac:<dev>:<port>`, `dhcp-snoop:<dev>:<port>`, `dhcp-server:<dev>` |
| `note` | Why a port is missing or uncertain: `seen only on uplinks: ...`, `no MAC table entry; ARP on ...`, `seen on more than one edge port` |

An **edge port** is a MAC-table port that is not a trunk and has no CDP/LLDP neighbor. A host
whose MAC appears only on uplinks has no port in the table: say it sits behind something the
snapshot does not log in to (an unmanaged switch, a hypervisor, a device not in the inventory).

## Answering "where is host X"

Search `hosts.csv` for the IP, MAC or a MAC prefix. Answer with the device and port, the VLAN, and
the sources, then say how sure it is: an edge port from a MAC table plus an ARP or DHCP match is
strong; ARP alone (no MAC table entry) says only which routed interface reaches it. If the row is
missing, say the snapshot did not see it, and list why that can happen (the host was silent, its
ARP entry aged out, it is behind a device not in the inventory, or on a platform whose host tables
are not read yet: see `coverage.md`).

## Special cases

- **First snapshot** (`first_snapshot` true): nothing to compare. Say the baseline is saved, how
  many devices and committed files it holds, and the host table row count.
- **First run after upgrading to network-ops 0.3.0**: the diff shows `show-ip-route.txt`,
  `show-vrf.txt` and `show-ip-bgp-summary.txt` deleted and `show-ip-route-vrf.txt`,
  `show-vrf-detail.txt` and `show-bgp-all-summary.txt` added (every VRF and address family now),
  plus new committed files, and timer columns written as `--` everywhere. Say this is the upgrade,
  not a network change, and that the next run is back to normal. The old files are removed by
  network-ops 0.3.1 and later (`retired_files`); a repo snapshotted with 0.3.0 has them removed on
  its next run.
- **`commit` null with no failures**: the network matches the last snapshot exactly. Still report
  host changes if there are any.
