# Roadmap (advisor pass, 2026-11-13)

Written by the advisor at the start of the 2026-11-13 improvement run. Status per item is kept
at the bottom. URLs and STIG IDs here are leads: each is verified and recorded in sources.md
before a check that uses it ships.

## Weak or wrong today

1. Checks only emit failures: no "what's good", no coverage, no control mapping.
2. Report is a flat list, one bullet per finding per device, no grouping, evidence or source link.
3. "Next planned upgrade" reads wrong for config findings: relabel them "next maintenance window".
4. No accepted-risk mechanism (lab exceptions, isp-rtr-01): needs a waiver file with reason and
   expiry, shown in the report, never hidden.
5. An absent config line is not always an absent feature (defaults are not shown). Every check
   states the platform default and its source.
6. Snapshot gaps: no show ntp associations, show logging, show ip interface, show policy-map
   control-plane, show port-security, show ip dhcp snooping; no FortiOS policy hit counts.
   Adding them touches network-snapshot (owner decision).
7. "Tested" is claimed per vendor but is true per check: move to a per-check `validated` field.

## Build order

| Id | Item | Size |
|---|---|---|
| R1 | Result model (pass/fail/n-a/not-visible + evidence), checks.yaml fields (plane, controls, validated), exceptions file, module split, relabel config "upgrade" band | M |
| R2 | IOS-XE management plane: AAA, console, timeouts, login block-for, accounting, banner, vty ranges | M |
| R3 | IOS-XE NTP auth, logging depth, SNMP version | S |
| R4 | IOS-XE control plane: CoPP, edge interface hygiene, unused services, CDP/LLDP on edge | M |
| R5 | Edge anti-spoofing and BGP hygiene (RFC 7454, 8212, 5082, BCP 38/84) | M |
| R6 | IOS-XE layer 2 and first hop: BPDU guard, DHCP snooping, DAI, port security, DTP, native VLAN, VTP, HSRP auth | M |
| R7 | FortiOS hardening: lockout, timeouts, strong-crypto, TLS, 2FA, log forwarding, local-in, unused VIPs | M |
| R8 | End-of-support check (CISA BOD 26-02), settings/lifecycle.yaml | M |
| R9 | Report rebuild: summary, grouped findings, what's good, posture grid, NIST 800-53 / CISA ZTMM map, accepted risk, HTML grid | L |
| R10 | Scoring and test hardening: Table 1, source integrity, secret-leak test | S |
| R11 | NX-OS and Arista EOS management-plane checks (fixtures) | M |
| R12 | Junos depth incl. SRX policy (fixtures) | M |
| R13 | Key lifetimes, OSPFv3/IS-IS auth, ASA twice NAT, PAN-OS negate rules | S each |

## Owner decisions

- Add the snapshot commands in weakness 6 to network-snapshot.
- isp-rtr-01: `exposure: internal` or a waiver.
- Confirm the R8 house rule (score cap for end-of-support with no known exploit).

## Status

(updated as items land)

- R1 done 2026-11-13: result model (pass/fail/n-a/not-visible, masked evidence), checks.yaml plane/validated/controls/zt_pillar, exceptions.yaml waivers, ios_routing.py split, maintenance-window label. See review-log Round 5.
- R2 and R3 done 2026-11-13: ten IOS checks in ios_mgmt.py (timeouts, lockout, central AAA, lines with no authentication, accounting, banner, NTP auth and redundancy, syslog depth, SNMP v1/v2c). IOS-VTY-RANGES dropped (covered per range by existing checks). See review-log Round 6.
- R4 and R5 done 2026-11-13: nine IOS checks in ios_cp.py and ios_edge.py (CoPP, edge ICMP/ARP services, CDP/LLDP on external interfaces, legacy services, anti-spoofing, eBGP policy, maximum-prefix, GTSM, inbound prefix-list content), peer-group and template resolution. See review-log Round 7.
- R7 done 2026-11-13: FortiOS hardening, 10 checks (review-log Round 8).
- R8 done 2026-11-13: end-of-support check, lifecycle.yaml (review-log Round 9). Open: FortiOS 7.0/7.2/8.0 dates.
- R9 done 2026-11-13: report.py renders md and a self-contained HTML report (summary with top actions grouped by fix, posture grid, grouped findings, what is good, coverage, control map); JSON gains summary, posture, controls, snapshot (review-log Round 10).
- R6 done 2026-11-13: layer 2 and FHRP, 9 checks (review-log Round 11).
