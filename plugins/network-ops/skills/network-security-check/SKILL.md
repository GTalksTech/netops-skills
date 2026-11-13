---
name: network-security-check
description: Read-only security check from network-snapshot files. Finds CVEs on the versions you run, risky router, switch and firewall config, and IPS event spikes, scored by real risk (KEV, EPSS, exposure). Use for security checks, CVE reviews, firewall audits, or what to patch first.
---

# Network security check

You run a bundled script, then explain its report. The script never touches a device. It reads:

1. **The snapshot repo** that network-snapshot keeps (default `~/network-snapshots`): each
   device's saved config and version output.
2. **A local advisory cache** (default `~/network-security/advisories`) built from public
   sources: CVE.org, NVD, CISA KEV, FIRST EPSS, Palo Alto's advisory JSON.
3. **Firewall event exports** the user gives you (optional): PAN-OS threat log CSV, FMC
   intrusion event CSV, FortiGate IPS logs, Suricata/OPNsense eve.json, most SIEM CSV exports.

Files in this folder:
- `scripts/seccheck.py`: the entry point. The other scripts are its modules.
- `settings/platforms.yaml`: per-vendor version, config and advisory settings.
- `settings/checks.yaml`: every check, with its source, score inputs, plane, NIST SP 800-53
  controls and `validated` (lab-v2 = checked on real devices, fixture = sample configs only).
- `exceptions.example.yaml`: format for accepted risk (copy to `exceptions.yaml` in the snapshot repo).
- `settings/segments.yaml`: names that mark IoT/guest/OT segments, and risky ports.
- `SCORING.md`: the scoring method. `research/sources.md`: the source behind every check.

## Rules

- Read-only. Never configure a device and never connect to one (no SSH, API or MCP calls to
  devices). If the snapshot is missing or old, ask the user to run network-snapshot first.
- Don't send device names, addresses, configs or versions to any outside service. The fetch
  step only asks public sources about products and CVE IDs.
- The report names real weaknesses on the user's network. Keep it local. Don't paste configs
  or credentials into the chat. Community strings and password hashes are masked in findings;
  keep them masked when you quote.
- Never change a score by hand. If a score looks wrong, find the input that is wrong (see
  "Wrong score?" below) and tell the user.

## Run

```
python <skill folder>/scripts/seccheck.py fetch [--repo ~/network-snapshots]
python <skill folder>/scripts/seccheck.py run   [--repo ~/network-snapshots] [--events FILE ...] [--site S | --device D]
```

- `fetch` needs internet access and refreshes the advisory cache for the vendors in the
  inventory. Run it if the cache is missing or `run` says it is over 7 days old. The first
  fetch for a vendor takes several minutes (NVD allows 5 requests per 30 seconds without a
  key). If the user has an NVD API key, they can set `NVD_API_KEY` in their own shell to make it
  faster. Never ask them for the key.
- `run` works offline. It prints a short JSON summary and writes the full report to
  `~/network-security/reports/` (`<date>.json` and `<date>.md`, plus `last-report.json`).
- Python 3.9+ with `pyyaml`. No other packages.

## Report to the user, in this order

Read `last-report.json`. Each finding has `score`, `deadline`, `inputs` (the four answers)
and `why` (where each answer came from). Each device also has `results`: one entry per config
check with `status` pass, fail, n/a (doesn't apply) or not-visible (the config section it needs
was missing), plus `evidence` (short config lines, secrets masked). Only fails are scored.

1. **One line on scope:** devices checked, advisory cache date, event window if any.
2. **Fix within 3 days + check for compromise** (score 90+). For each: what it is, which
   devices, and why it is urgent, in plain words (e.g. "CVE-2024-3400 on pa-fw-01: in CISA KEV,
   GlobalProtect is on the internet-facing interface, attempts seen in your logs, 20 not
   blocked"). Say plainly that "check for compromise" means looking for signs someone already
   got in (the vendor advisory usually lists indicators), not just patching.
3. **3 days, then 14 days:** grouped by device or by theme when that reads better (all the
   exposed-management findings together).
4. **60 days and next upgrade:** counts plus one line each for the top few. Don't list every
   low finding unless asked.
5. **What passed:** one line from `result_counts` (for example "79 checks passed, 40 did not
   apply"), and name a few passes that matter (web UI off, SSH v2 only, VTY ACLs in place).
6. **Accepted risk:** findings waived in `exceptions.yaml`, each with its reason and expiry.
   They are still open, just not counted against a deadline. Say if a waiver expired or matches
   nothing (the report notes both).
7. **What the check couldn't see:** devices with no version found, vendors with no config
   checks, `not-visible` results, the coverage notes, and anything marked "assumed".

For each CVE, give the fixed version only if you can read it from the vendor advisory linked in
`refs`. Otherwise say "see the vendor advisory" and link it. Don't guess a fixed release.

## Wrong score?

The score comes from four inputs. Find the one that is wrong:

- **Exposure wrong** (a device that faces the internet shows as internal, or the reverse): add
  `exposure: public` or `exposure: internal` to that device in the inventory.
- **A segment not recognised** (an IoT VLAN named "SENSORS"): add the word to
  `settings/segments.yaml`.
- **A feature shown on or off wrongly:** the config parser for that vendor needs a fix. Say so.
- **A check that doesn't fit the network** (a known lab exception): tell the user. If they
  accept the risk, they add it to `exceptions.yaml` in the snapshot repo (format in
  `exceptions.example.yaml`: check, device or "*", reason, expires, owner). Never write that file
  for them without asking, and never drop a finding from the report silently.

Config findings in the lowest band say "Fix in the next maintenance window"; CVEs there say
"Fix at the next planned upgrade". Same band and score.

## Vendor coverage

| Vendor | CVE matching | Config checks |
|---|---|---|
| Cisco IOS / IOS-XE | yes | 21 checks, tested (IOS-XE 17.16) |
| Cisco ASA | yes | 6 checks, untested |
| FortiGate (FortiOS) | yes | 9 checks, tested (FortiOS 8.0) |
| Palo Alto PAN-OS | yes | 7 checks, untested |
| Juniper Junos | yes | 3 management checks, untested (no SRX policy checks yet) |
| Arista EOS, Cisco NX-OS, HPE Aruba AOS-CX, Dell OS10, Extreme EXOS, HPE ArubaOS-Switch (ProCurve) | yes | none yet |
| Huawei VRP, Nokia SR OS | version only: their CVE records are free text, so the report says to check by hand and links the PSIRT | none yet |

"Tested" means run against real devices in the G Talks Tech lab and the results checked by hand.
Which checks that covers is recorded per check in `checks.yaml` (`validated: lab-v2`).
Checks that found nothing there (segmentation, VIPs, telnet) are covered by sample configs.
"Untested" means written from vendor docs and tested on sample configs, not yet run on real
devices. If the output looks wrong for a device, say so and suggest the parser fix. Other
vendors (Check Point, SonicWall, Sophos, pfSense/OPNsense, Ubiquiti) are not covered yet. Say
so if the inventory has them.
