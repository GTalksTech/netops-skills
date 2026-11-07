# Read-only health check: Aruba/HPE, Extreme, Huawei, Dell (research, 2026-11-07)

## Evidence quality (read first)
Web search was thin: vendor reference pages mostly did not return content or are login/JS-gated. What was actually verified vs. not:

- VERIFIED (fetched, tier 2): hi-network.com Huawei daily-maintenance command list (command names and what each checks only; it gives NO thresholds except memory >80% sustained and Alarm field not "Abnormal" in `display device`). https://www.hi-network.com/essential-display-commands-for-daily-maintenance-of-huawei-switches.html
- VERIFIED (search snippet, tier 1): AOS-CX `show system` (hostname, version, uptime, CPU, memory; CPU = average across cores; `vsx-peer` option; operator or manager context) https://support.hpe.com/techhub/eginfolib/aruba/os-cx_10.03/5200-5950/GUID-619E372C-212E-4908-A970-7B56C4A11001.html ; `show environment led` https://support.hpe.com/techhub/eginfolib/aruba/os-cx_10.03/5200-5950/GUID-F7AFDEBC-B3A9-487A-B6DA-81F3A1D8F239.html
- VERIFIED (search snippet, tier 1): EXOS `show system` aggregates show switch, show version, show temperature, show power, show fans, show odometers (EXOS 16.1+) https://documentation.extremenetworks.com/exos_commands_32.2/GUID-0935DF30-52CC-4897-B94E-24989FD69B05.shtml ; `show temperature` https://documentation.extremenetworks.com/ExtremeXOS%20v33.1.1%20Command%20References/GUID-0D9E728E-FD74-41A3-8D31-E23E1410AB53.shtml ; `show tech-support` is for use with TAC only (long, heavy) https://documentation.extremenetworks.com/exos_commands_22.1/EXOS_21_1/EXOS_Commands_All/r_show-tech-support.shtml
- VERIFIED (search snippet, tier 1/2): Dell OS10 user guide index lists `show environment`, `show system`, `show inventory`; `show vlt <id>` and `vlt-port-detail` https://dell.com/support/kbdoc/000102901/dell-emc-networking-os10-how-to-set-up-virtual-link-trunking-vlt ; Ansible os10 vlt_validate uses `show vlt N | display-xml` https://docs.ansible.com/ansible/6/collections/dellemc/os10/vlt_validate_module.html
- Huawei official troubleshooting guide exists (https://support.huawei.com/enterprise/en/doc/DOC1000060766/b9a04cb4/common-display-commands, CloudEngine 16800..5800) but the page body returned empty (JS gated).
- EVERYTHING ELSE below is marked "[engineer-knowledge, unverified in this session]" = operational reason, command names from vendor CLI conventions. Treat as candidates to confirm on a real device/lab before shipping; thresholds are generic engineering defaults, not vendor-published, unless stated.

Severity key: CRIT = page/act now, WARN = review, INFO = record only.

---
## 1. Aruba/HPE AOS-CX
Privilege: all show commands work in operator (`>`) or manager (`#`) context (tier 1 above). `vsx-peer` suffix on many show commands queries the peer; empty if ISL down/VSX unconfigured.
Virtual image (AOS-CX OVA/simulator): no real PSU/fan/temp/transceiver; `show environment ...` and `show system resource-utilization` may be empty or partial; do not treat empty as a finding [engineer-knowledge].

| Area | Command(s) | Healthy | Finding | Noise |
|---|---|---|---|---|
| Hardware | `show environment power-supply`, `show environment fan`, `show environment temperature`, `show environment led` | PSU "ok", fans "ok", temp "normal" status | any status not ok/normal = CRIT (PSU/fan fault), temp "max"/"critical" CRIT, "high" WARN; PSU absent in redundant model WARN | empty empty-slot PSU on single-PSU models |
| Optics DOM | `show interface transceiver detail` (older: `show interface <if> transceiver`) | Rx/Tx power and temp within vendor alarm/warn thresholds shown in output | output flags alarm/warning high/low = WARN, alarm = CRIT; Rx near -30 dBm / no light on admin-up port = WARN | DAC/copper show no DOM; some 3rd-party optics report none |
| CPU/mem | `show system` (CPU avg, mem), `show system resource-utilization` | CPU sustained <70%, mem <80% | CPU >85% across 2 samples WARN; mem >90% CRIT [generic thresholds] | CPU spikes during config/boot |
| Version/uptime/crash | `show version`, `show system` (uptime), `show images`, `show boot-history`, `show core-dump` (if available) | version in approved list, no recent reboots | uptime <24h unexplained WARN; abnormal reboot reason in boot-history WARN; core dump present CRIT | planned maintenance reboot |
| Logs | `show events -s warning` / `show events -r -n 100` (`-s` = severity filter; severities emer, alert, crit, err, warn, notice, info, debug) | no entries >= warning in 24h | err/crit/alert/emer = WARN/CRIT by count | repeated identical warnings; dedup by message |
| Interfaces | `show interface brief`, `show interface <if>` (RX/TX errors, CRC, drops), `show interface error-counters`? [verify name] | zero or static counters | CRC/FCS rising between two polls WARN; any rx/tx error on trunk WARN | counters since boot; use delta between two polls |
| Flaps | `show events -c lldp`/`-c ... link` filtered by "Interface ... changed state" | none | >3 link transitions/24h per port WARN | access ports with end-user PCs |
| Utilization | `show interface <if>` rate or `show interface utilization` [verify] | <70% of speed | >80% sustained WARN | |
| STP | `show spanning-tree`, `show spanning-tree detail` (topology change count, last change) | stable root, TC count static | TC increasing across polls WARN; unexpected root CRIT | |
| OSPF/BGP | `show ip ospf neighbor`, `show bgp all summary` / `show bgp ipv4 unicast summary` | OSPF Full; BGP Established with prefix count >0 | any neighbor not Full/Established CRIT; recent uptime (<1h) WARN | |
| VRRP | `show vrrp` | exactly one Master per VRID, expected master | no master/two masters CRIT; unexpected backup holding master WARN | |
| VSX / stacking | `show vsx status`, `show vsx brief`, `show vsx config-consistency`; VSF: `show vsf` | ISL in-sync, keepalive established, config-consistency no diffs | ISL down CRIT, keepalive failed CRIT, config inconsistency WARN | |
| LAG | `show lacp interfaces`, `show lacp aggregates` | all members collecting/distributing | member out of sync WARN | |
| NTP | `show ntp status`, `show ntp associations` | synchronized, stratum <16 | unsynchronized WARN | |
| Unsaved config | `show running-config` vs `show startup-config` (diff), or `show checkpoint` | identical | differ WARN | timestamp/comment lines |
| Err-disable equiv | `show port-access ...` / `show loop-protect`/`show interface` "reason" ; `show rate-limit`; `show port-security` [verify] | none blocked | loop-protect/port-security disabled port CRIT | |
| PoE | `show power-over-ethernet` / `show power-over-ethernet brief` | Available > Reserved; no faults | usage >85% of budget WARN; "fault"/"denied" ports WARN | |

Sources: tier 1 for `show system`, `show environment led`; remainder [engineer-knowledge] to be confirmed against the AOS-CX CLI guide (https://www.arubanetworks.com/techdocs/AOS-CX/ ; gated).

## 2. ArubaOS-Switch (ProVision/ProCurve/older HPE)
Privilege: `show` in operator or manager; paging `no page`/`terminal length 1000`. Virtual: none common. [engineer-knowledge for all rows]

| Area | Command | Healthy / finding |
|---|---|---|
| HW | `show system power-supply`, `show system fans`, `show system temperature`, `show system information` | status "Good"/"OK"; "Failed"/"Absent" CRIT |
| Optics | `show interfaces transceiver detail` | alarm/warn flags on Rx/Tx power |
| CPU/mem | `show cpu`, `show system information` (CPU util, mem), `show system` | CPU >85% sustained WARN |
| Version/uptime | `show version`, `show system information` (Up Time), `show flash` | recent boot WARN |
| Logs | `show logging -r` (newest first), `show logging -e` (errors), `show logging -m` (major) | Major/Error/Warning entries; ignore "Information"/"Debug" |
| Interfaces | `show interfaces brief`, `show interfaces <port>` (FCS/Drops/Collisions/Giants), `show interfaces port-utilization` | FCS rx rising WARN; drops rising WARN |
| STP | `show spanning-tree`, `show spanning-tree instance <n>` (topology changes) | TC count rising WARN |
| OSPF/BGP | `show ip ospf neighbor`, `show ip bgp summary` | not Full/Established CRIT |
| VRRP | `show vrrp` | state Master/Backup expected |
| Stack/VSF/mesh | `show stacking`, `show vsf`, `show vsf link` | member not Ready/Standby CRIT |
| Trunk | `show lacp`, `show trunks` | member not "Up/Collecting" WARN |
| NTP | `show sntp`, `show timesync` | not synchronized WARN |
| Unsaved | `show config status` (also "show running-config status"), `show running-config` vs `show config` | "running differs from startup" WARN |
| Err-disable equiv | `show loop-protect`, `show port-security`, `show errdisable`? (not on all) , `show interfaces brief` "Intrusion Alert" | loop-protect "Disabled by LP" / intrusion alert CRIT |
| PoE | `show power-over-ethernet brief`, `show power-over-ethernet` | Power remaining <15% WARN; Denied/Fault ports WARN |

## 3. HPE Comware (H3C-derived, HP A-series/FlexFabric)
Privilege: `display` works in user view and system view (`<sw>`), some in any view; Comware 7 allows `display` from user view. IRF stack. Virtual: HP VSR/vSwitch may lack device/power/fan. [engineer-knowledge]; H3C Chinese doc references alarm commands: https://www.h3c.com/cn/d_202511/2697264_30005_0.htm (tier 1, only snippet reviewed).

| Area | Command | Notes |
|---|---|---|
| HW | `display environment`, `display fan`, `display power`, `display device`, `display device verbose` | State Normal; Absent/Fault = CRIT for PSU/fan |
| Optics | `display transceiver diagnosis interface`, `display transceiver alarm interface` | alarm output not "none" WARN |
| CPU/mem | `display cpu-usage`, `display memory` | CPU >85% / mem free <10% WARN |
| Version/uptime | `display version` (uptime), `display boot-loader`, `display reboot-info` (some models) | |
| Logs | `display logbuffer` (+`reverse`, `severity warning`) / `display logbuffer summary` | Severity 0-7 (0 emergency .. 7 debug); act on 0-4 |
| Interfaces | `display interface brief`, `display counters error inbound interface`, `display counters rate inbound/outbound interface` | CRC/Input errors rising WARN |
| STP | `display stp`, `display stp tc` | TC rising WARN |
| OSPF/BGP | `display ospf peer`, `display bgp peer ipv4` | not Full/Established CRIT |
| VRRP | `display vrrp` / `display vrrp verbose` | |
| IRF | `display irf`, `display irf topology`, `display irf link`, `display mad verbose` | topology ring/chain per design; member missing CRIT; MAD faults |
| NTP | `display ntp-service status` | |
| Unsaved | `display current-configuration` vs `display saved-configuration`; `display configuration changes` ("startup config not saved" flagged by newer versions) | |
| Err-disable | `display shutdown`/`display port-security`, `display loopback-detection`, `display interface brief` "ERPD/STP/LBK" reason | |
| PoE | `display poe device`, `display poe pse` | |

## 4. Extreme EXOS
Privilege: `show` OK at user level; no `debug`. Paging off: `disable clipaging` (changes session only). Virtual: EXOS VM (Switch Engine VM / ExtremeXOS-VM) has no fans/PSU/temps; those will show absent. Tier 1 verified: `show system`, `show temperature`; the rest [engineer-knowledge].

| Area | Command | Healthy / finding |
|---|---|---|
| HW | `show system` (aggregates switch, version, temperature, power, fans, odometers) or individually `show power`, `show fans`, `show temperature` | PSU "Powered On", fans "Operational", temp "Normal"; "Failed"/"Empty on redundant PSU"/"Over temp" CRIT |
| Optics | `show ports transceiver information detail`, `show ports <p> transceiver information detail` | alarm/warn flags |
| CPU/mem | `show cpu-monitoring`, `show memory`, `show process` (cpu column) | |
| Version/uptime | `show switch` (Boot time, uptime, Current Time), `show version`, `show odometers` | |
| Logs | `show log` / `show log severity warning` / `show log messages severity error` / `show log messages chronological`; severities critical, error, warning, notice, info, debug-* | act on Critical/Error; Warning review |
| Interfaces | `show ports <p> rxerrors no-refresh`, `show ports txerrors no-refresh`, `show ports stat no-refresh` | rising CRC/Align/Over/Under WARN (rxerrors name verified in feature matrices via ipfabric snippet) |
| Flaps | `show log match "link"` / `show log match "Port"` | |
| STP | `show stpd detail`, `show stpd <n> ports` | topology change counter |
| OSPF/BGP | `show ospf neighbor`, `show bgp neighbor` | |
| VRRP | `show vrrp` | |
| Stack/MLAG/SMLT | `show stacking`, `show stacking stack-ports`, `show mlag peer`, `show mlag ports`, `show vsm`? | stack node state Active/Standby/Backup; ISC down CRIT |
| LAG | `show lacp lag` | |
| NTP | `show sntp-client`, `show ntp` (if enabled) | |
| Unsaved | `show configuration` vs `show switch` ("Config Selected/Modified" flag appears in `show switch`) | "Config Modified" WARN |
| Err-disable | `show elrp`, `show ports <p> information detail` (disabled reason), `show lldp`, `show vlan` , `show ip-security ...` | ELRP/loop-protect blocked CRIT |
| PoE | `show inline-power`, `show inline-power stats` | |

## 5. Extreme VOSS (Fabric Engine, VSP)
Privilege: privileged exec (`enable`) required for most show; `terminal more disable`. Virtual: VOSS VM lacks HW sensors. [engineer-knowledge].

| Area | Command | Notes |
|---|---|---|
| HW | `show sys power`, `show sys fan`, `show sys temperature`, `show sys-info`, `show sys-info card` | |
| Optics | `show pluggable-optical-modules detail` (alias `show interfaces gigabitEthernet transceiver`) | |
| CPU/mem | `show khi cpu`, `show khi memory`, `show khi performance` | |
| Version/uptime | `show sys software`, `show sys-info`, `show khi info` | |
| Logs | `show logging file tail`, `show logging file severity warning` | severities INFO WARNING ERROR FATAL |
| Interfaces | `show interfaces gigabitEthernet error`, `show interfaces gigabitEthernet statistics` | |
| STP | `show spanning-tree mstp status`, `show spanning-tree mstp statistics` | |
| Fabric | `show isis adjacency`, `show isis spbm`, `show isis int-l1-circuit`, `show isis lsdb` | adj not UP CRIT |
| OSPF/BGP | `show ip ospf neighbor`, `show ip bgp summary` | |
| VRRP | `show ip vrrp` | |
| SMLT/vIST | `show virtual-ist`, `show smlt`, `show mlt` | vIST not up CRIT |
| NTP | `show ntp`, `show ntp statistics` | |
| Unsaved | `show config` compared to boot config; `show boot config` | |
| PoE | `show poe-main-status`, `show poe-port-status` | |

## 6. Huawei VRP (CloudEngine / S series)
Privilege: `display` works in user view `<HUAWEI>` and system view (with `display` prefix; `do display` in config sub-views). Verified list (hi-network) shows names; thresholds from there: memory >80% sustained caution; `display device` Alarm field should not be "Abnormal". Disable paging per session: `screen-length 0 temporary` (session only). Virtual: eNSP/CloudEngine simulated images (CE12800V/NE40E-VM, eNSP) lack real `display device/power/fan/temperature/health`; commands error or return placeholders; `display transceiver` empty. [engineer-knowledge].

| Area | Command | Healthy / finding | Source |
|---|---|---|---|
| Overall | `display health` | CPU/mem/temp/power/fan all normal | hi-network (tier 2) |
| HW | `display device`, `display device fan`, `display device power`, `display device temperature all`, `display environment`, `display alarm active` | Alarm field not "Abnormal"; no active alarms of severity critical/major = clean; CRIT for critical/major alarms, WARN for minor | hi-network |
| Optics | `display transceiver interface <if> verbose` (CE: `display transceiver verbose`) | Rx/Tx within thresholds | [engineer-knowledge] |
| CPU/mem | `display cpu`, `display memory-usage`, `display memory` | memory >80% sustained WARN | hi-network |
| Version/uptime/crash | `display version` (uptime), `display startup`, `display patch-information`, `display reset-reason`, `display diagnostic-information` (heavy; avoid unless needed), `dir` for `*.dmp`/`*.zip` crash files | reset-reason abnormal (power/exception) WARN | hi-network; reset-reason [eng-knowledge] |
| Logs | `display logbuffer` (`display logbuffer level warnings`? varies), `display trapbuffer`; severity numbering 0 emergency .. 7 debug (`level 4`=warning) | act on levels 0-4 | hi-network |
| Interfaces | `display interface brief`, `display errors interface`, `display interface <if>` (CRC, input/output errors, drops) | rising CRC WARN | hi-network |
| Flaps | `display logbuffer` match "UPDOWN" / `LINK_STATE` | |
| STP | `display stp`, `display stp topology-change` | TC count |
| OSPF/BGP/IS-IS | `display ospf peer`, `display bgp peer`, `display isis peer` | Full/Established | hi-network |
| VRRP | `display vrrp brief` | |
| Stack/CSS/iStack | `display stack`, `display stack topology`, `display css status` (CE12800), `display m-lag` (CE) / `display dfs-group 1 m-lag` | |
| NTP | `display ntp status`, `display clock` | clock status synchronized | hi-network |
| Unsaved config | `display current-configuration` vs `display saved-configuration`; `display configuration` ... and `compare configuration` | differ WARN | hi-network |
| Err-disable | `display error-down recovery`, `display error-down record` | |
| PoE | `display poe power`, `display poe power-state`, `display poe information` | |

## 7. Dell EMC OS10 (SmartFabric OS10)
Privilege: `show` in EXEC; some commands require `system`/admin role. Virtual: OS10 Virtualization (VM) shows no environment sensors. Tier 1 list: show environment, show system, show inventory, show version (user guide index). VLT: Dell KB above.

| Area | Command | Healthy / finding |
|---|---|---|
| HW | `show environment`, `show inventory`, `show system` | fan/PSU "up"; "fail" CRIT; temp states |
| Alarms | `show alarms` (OS10 supports `show alarms`, `show alarms details`, `show alarms history`) [eng-knowledge] | no active major/critical |
| Optics | `show interface transceiver`, `show interface ethernet 1/1/x phy-eth`? ; `show qsfp`? | verify |
| CPU/mem | `show processes cpu`? / `show processes node-id 1 memory`, `show system` | |
| Version/uptime | `show version`, `show uptime`, `show boot` (some) | |
| Logs | `show logging log-file` (`show logging`); syslog severity per `logging` config; entries with %Node.. severities | |
| Interfaces | `show interface ethernet 1/1/x` (CRC, input errors), `show interface status`, `show queuing statistics interface` | |
| STP | `show spanning-tree brief`, `show spanning-tree active` | TC |
| OSPF/BGP | `show ip ospf neighbor`, `show ip bgp summary` / `show bgp ipv4 unicast summary` | |
| VRRP | `show vrrp brief` | |
| VLT | `show vlt <domain-id>`, `show vlt <id> mismatch`, `show vlt <id> backup-link`, `show vlt <id> vlt-port-detail` | Status up; backup destination reachable; "Mismatch" empty |
| NTP | `show ntp associations`, `show ntp status` | |
| Unsaved | `show running-configuration` vs `show startup-configuration`; OS10 flags unsaved with `show configuration` ? | |
| PoE | `show power-over-ethernet`? limited (only PoE models N-series ON) | |

## 8. Dell OS9 / PowerConnect / OS6 (legacy)
OS9: `show environment` (or `show environment pem/fan/stack-unit`), `show system brief`, `show hardware stack-unit`, `show processes cpu`, `show processes memory`, `show logging`, `show interfaces`, `show vlt brief`, `show vlt detail`, `show ip ospf neighbor`, `show vrrp brief`, `show ntp status`, `show running-config` vs `show startup-config`, `show alarms`. OS6 (PowerConnect): `show system`, `show system fans/temperature/power`, `show logging`, `show switch`, `show spanning-tree`, `show interfaces counters`. [engineer-knowledge, unverified].

## Cross-platform design notes
1. Counters are cumulative: poll twice (60-300 s apart) and use the delta; never alert on absolute since-boot values (operational reason).
2. Dedup logs by message template; ignore informational/link-up/duplex-negotiation noise on access ports, NTP step messages, config-session login messages, SNMP auth fails from monitoring.
3. Treat empty/"not supported" output on virtual images as UNKNOWN, not PASS or FAIL.
4. Do not run: `show tech-support`, `display diagnostic-information`, EXOS `debug`, OS10 `show tech-support` in loops (CPU heavy, slow; Extreme says TAC only).
5. Thresholds not vendor-published here: CPU 70/85, mem 80/90, util 70/80, PoE 85, per generic practice; make them configurable.
6. Next step: confirm each [engineer-knowledge] command in a lab or against the CLI guides: AOS-CX (HPE Aruba Networking Support Portal), ArubaOS-Switch Management and Configuration Guide, Comware 7 CLI reference, EXOS/Switch Engine command reference (documentation.extremenetworks.com), Fabric Engine/VOSS commands reference, Huawei CloudEngine Command Reference (support.huawei.com), Dell OS10 CLI reference (dell.com/support/manuals).
