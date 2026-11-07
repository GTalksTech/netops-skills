# network-health-check: why each check is in

Backend record for `plugins/network-ops/skills/network-health-check/checks.md`. The skill text
holds the rules; this file holds the reasons and the sources. Researched 2026-11-07.

Source tiers: **T1** vendor docs, command references, TAC/KB articles, vendor training.
**T2** practitioner material that shows method. **T3** forums and marketing: direction only,
never the only support. **Op** = an operational reason stated in full, used where the check is
the device reporting on itself (its own alarm, its own state word) and no threshold is invented.

Per-vendor detail, with the commands, healthy states, noise and source of every row, is in
`docs/health-check-research/`. Those notes were gathered by research agents and say for each row
whether the source was read ([V]) or cited from knowledge ([C]/[K]); rows of the second kind are
not relied on alone below.

## Principles

| Principle | Basis |
|---|---|
| Report the device's own alarm and state words before any threshold of ours | Op: the vendor's alarm logic knows its hardware; Juniper documents Major (red) and Minor (yellow) classes in `show chassis alarms` and that alarms clear only when the cause is fixed (T1, juniper.net show-chassis-alarms reference, QFX/PTX troubleshooting guides) |
| Counters are totals: judge growth between two runs | Op: interface counters accumulate since clear or reload; a non-zero total on a long-running device is history. Universal in the vendor notes (Cisco, Juniper, Aruba) |
| A rejected command is not a pass | Op: IOS prints "% Invalid input" both for a missing command and one the account may not run (seen on lab v2 claude-ro, privilege 5); FortiOS read-only profiles refuse `diagnose`/`execute` (T1, Fortinet admin-profile docs, see fortinet notes) |
| Virtual images have no hardware sensors | Op + observed: IOL returns nothing for `show environment all` and transceivers on lab v2; vendor notes list the same for vEOS/cEOS, vJunos, NX-OSv, ASAv |
| Blocked ports are not findings | Op: blocking is how STP keeps redundant links loop-free; counting them flags the design working |

## Checks

| # | Check | Thresholds | Basis |
|---|---|---|---|
| 1 | Reachable | any failure | Op |
| 2 | Hardware alarms, PSU, fans, temperature | device's state words | T1 Juniper show chassis alarms; Cisco `show environment` (cisco notes S3, S11); Huawei `display alarm active` / `display device` Abnormal (T2 hi-network daily maintenance list) |
| 3 | Redundancy (HA, stack, vPC/MLAG/VSX/VLT, SSO) | peer/sync state, Type-1 vs Type-2 | T1 Cisco TAC 217989 (Type-1 suspends the vPC, Type-2 does not); ASA command reference `show failover`; Dell VLT KB; Op for the rest (state words) |
| 4 | Reboots and crashes | uptime < 24 h; crash reasons | Op: an unplanned reload is the most important single fact; reload-reason commands per vendor in notes (T1 ASA ref, NX-OS troubleshooting guide) |
| 5 | Routing adjacencies, flaps, route count | not FULL/Established; uptime < 24 h / 1 h | T1 Cisco OSPF neighbor states and BGP states tech notes (EXSTART/EXCHANGE = MTU); Op for flap windows |
| 6 | FHRP and STP root alignment | one Active, one Standby, root = Active | Op: Active away from the root sends traffic across the inter-switch link while the direct uplink blocks (campus design guidance; lab v2 design doc) |
| 7 | Should-be-up interfaces, err-disabled | down; any err-disabled | T1 Cisco errdisable recovery tech note (reason decides the fix) |
| 8 | Port-channels | member not bundled | T1 Cisco etherchannel flags in `show etherchannel summary`; Op: bundles degrade while the logical link stays up |
| 9 | Errors and discards | growth; 0.01% of packets with no baseline; collisions on full duplex | T1 Cisco 12768 Troubleshooting Ethernet Collisions (late collisions); Cisco IE 4010 guide: alignment, FCS, late collisions point to speed/duplex mismatch; T2 practitioner guides (computingforgeeks): CRC without collisions = cabling, late collisions on switched links = duplex mismatch |
| 10 | Load | 80% / 90% of BW over the load interval | Op: queues build and drops start well before 100%; one reading is one moment, never a trend |
| 11 | Flaps | ≥ 3 in an hour; last flapped < 1 h | Op; NX-OS `Last link flapped`, Junos `Last flapped` fields (T1 command references) |
| 12 | STP inconsistent ports and topology changes | any inconsistent; last change < 1 h | T3+T2: Cisco Community answer by Cisco staff showing `show spanning-tree detail` "Number of topology changes … last change occurred … from <port>"; Op: each TCN flushes MAC tables and floods |
| 13 | Optics | optic's own warning/alarm flags | T1 Cisco command reference (Cat4500) legend `++` high alarm, `+` high warning, `-` low warning, `--` low alarm; thresholds come from the optic |
| 14 | CPU, memory, sessions, storage | 80/90% CPU, 85/90% memory, interrupt > 30% | T1 Cisco TAC 222469 (above 80% treated as high), TAC 213549 (interrupt CPU = punted traffic); T1 Fortinet KB conserve mode (green 82%, red 88%, extreme 95%, model dependent) |
| 15 | Logs | severity 0-3 plus named mnemonics | T1 Cisco system message guides for mnemonics (`%CDP-4-DUPLEX_MISMATCH`, `%CDP-4-NATIVE_VLAN_MISMATCH`, `%SW_MATM-4-MACFLAP_NOTIF`); Op for grouping |
| 16 | NTP | unsynced, stratum 16, reach | Op: log correlation, certificates, VPN and AAA need time; lab v2 lesson (IOS takes ~15 min to sync after boot) |
| 17 | Hygiene | unsaved config, debug on | Op: unsaved changes vanish on the next reload; debugs load the CPU |

## Left out on purpose

- Version and PSIRT checks: a version is only "bad" against an advisory database the skill does
  not have. It reports the version in Healthy and leaves the judgement to the engineer.
- TCAM / forwarding resources: commands differ per ASIC and release (see cisco notes §15), and
  no single safe read-only command exists across platforms. Candidate for a later version.
- Thresholds as hard facts: every number above is a default the workspace can override.

## Credits

The method follows vendor TAC and best-practice material cited above. No third-party skill or
script was copied; third-party "device health" skill pages seen during research were treated as
T3 and not used.

## Test rounds (2026-11-07)

Lab v2 was powered off during this work, so each round ran the skill (a fresh agent following
SKILL.md) on recorded output: lab v2's real 2026-10-31 health run, with faults planted by editing
copies, and real vendor output from ntc-templates test fixtures. Engine changes have offline unit
tests (`skills/network-snapshot/tests/test_health.py`); every profile's uptime regex was checked
against 27 ntc-templates fixtures (Arista, Junos, AOS-CX, ASA, Huawei, ArubaOS-Switch, PAN-OS).

| Round | Data | Caught | Fixed after |
|---|---|---|---|
| 1 | lab v2 HQ + CRC growth planted on hq-dist-sw-01 | CRC growth (and that the packet counter did not move); old collision totals demoted to Healthy | rule precedence (growth beats totals); empty list output means none; change-in-progress explains route moves; only this run's devices; two baselines (counters vs findings); IP SLA and `show track` added |
| 2 | lab v2 HQ + uplink down with its OSPF neighbor, STP topology change, MAC-flap log flood, CRC cleared | all four, ranked Critical / High / High, CRC reported fixed | sources that disagree; device clock for log windows; unsaved config during an open change is not a finding |
| 3 | Arista leaf + Junos core (ntc-templates output, first run, a timed-out command) | MLAG peer-link down (Critical), PEM Major alarm, first-run totals, command error listed | old reload records are history; config alarms are Low; files not collected; optics without thresholds are not judged (Arista profile now uses `transceiver detail`) |

Still to do: a live run on lab v2 with the new profiles, and a first run on real hardware for
each untested vendor.
