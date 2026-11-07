# Read-only health check: Junos, Arista EOS, Nokia SR OS / SR Linux

## Provenance and confidence (read first)
Research was thin on live fetches: Arista's manual returned 403, the SR Experts lab returned 404, vendor pages are mostly JS/blocked. What I actually saw via search/fetch:
- Juniper command reference pages (show chassis alarms, show system alarms) and the Juniper hardware troubleshooting pages: tier 1 (URLs below).
- Nokia SR OS 26.3 show-command docs and interface guide: tier 1 (search listing only, not deep-read).
- forwardingplane.net SR OS useful commands: tier 2 (fetched).
- sharedcontext.ai / vibehackers "device health" skills: tier 3 (directional; third-party skills, thresholds unvetted).
Everything marked **[ops]** is from standard operational practice / my knowledge of the platform, with the stated operational reason; verify the syntax on a lab box before the skill relies on it. Thresholds are defaults for a skill to flag, not vendor-mandated numbers, unless noted.

Severity key: CRIT = service-affecting or imminent, WARN = degraded/needs ticket, INFO = note.

---
## 0. Generic degradation rules for the skill
- Run each command independently; treat "syntax error", "unknown command", "not supported", "error: the ... subsystem is not running" as `N/A` for that check, never as a finding.
- Virtual platforms (vJunos-switch/router/evolved, vSRX, vMX, cEOS, vEOS, SR OS vSIM, SR Linux containerlab): no real PSU/fan/temperature/optics. Expect empty or error output from `show chassis environment`, `show chassis fpc` (vMX/vJunos-router do show a virtual FPC), `show interfaces diagnostics optics`, `show system environment *`, `show interfaces transceiver`. Detect platform first (`show version` / `show chassis hardware`, `show version`, `show system information`) and skip hardware sections with INFO "virtual platform".
- Pager: Junos `| no-more`; EOS `terminal length 0`; SR OS (classic) `environment more false`, MD-CLI `environment more false` equivalent is `/environment more false` (use `| no-more` is not valid in SR OS). SR Linux `environment cli-engine type basic` / `| as table` helps; output via `info from state`.
- Never run commands that clear counters (`clear interfaces statistics`, `clear counters`). Counter-based checks should be delta-based (two samples 30-60 s apart) or compared to prior snapshot; absolute counters on a long-uptime box are mostly historical.
- Write operations never needed. `show | display set`, `show configuration | compare rollback 0`, `show | compare` are read-only.

---
## 1. Hardware alarms and environment

### Junos (EX/QFX/MX/SRX)
Commands:
- `show chassis alarms` and `show system alarms` (two different alarm sets; run both). Source: https://www.juniper.net/documentation//en_US/junos/topics/reference/command-summary/show-chassis-alarms.html and https://juniper.net/documentation/en_US/junos13.2/topics/reference/command-summary/show-system-alarms.html (tier 1)
- `show chassis environment` (temps, fans, PSU status, per FRU), `show chassis fpc` (state, temp, CPU, memory, heap/buffer), `show chassis routing-engine` (temp, CPU, memory, uptime, last reboot reason, load averages), `show chassis hardware` (inventory; detects missing/failed FRUs), `show chassis fan`, `show chassis power` (MX/QFX/EX4xxx). Source: https://www.juniper.net/documentation/us/en/hardware/ptx10016/topics/topic-map/ptx10016-alarm-messages.html (tier 1, alarm severities); command list corroborated by https://sharedcontext.ai/skills/external/vahagn-madatyan/juniper-device-health (tier 3).
Healthy: `No alarms currently active` on both; all environment items `OK`; FPC `Online`; RE `Master`/`Backup` states consistent.
Findings:
- Any **Major (red)** alarm = CRIT (e.g. FRU failed, fan failure, PSU failure/input lost, temperature). Any **Minor (yellow)** = WARN. Juniper classes color red = major, yellow = minor (tier 1 source above).
- Environment item not `OK` (`Failed`, `Check`, `Absent` when it should be present) = CRIT for fan/PSU in a redundant pair loss-of-redundancy, WARN if redundancy remains. **[ops]**
- Temperature: flag >= 70 C ambient/inlet WARN, >= 85 C CRIT, or whatever the platform's own "high/ shutdown" threshold shows. **[ops]**; platform specifics vary, prefer an alarm over a number.
- FPC state `Offline`/`Present`/`Dead`/`Fault` when config expects `Online` = CRIT. FPC memory/heap util > 80% WARN, > 90% CRIT. **[ops]**
- RE: `Mastership` mismatch on dual-RE, backup RE `Absent` on dual-RE chassis = WARN.
Noise: "Rescue configuration is not set" (system alarm, Minor): standard, INFO. "YELLOW: Autorecovery information needs to be saved" INFO/WARN. License alarms on lab gear ("Missing license") INFO; see section 14. `Management Ethernet link down` alarm on boxes without a mgmt cable = INFO. EX/QFX non-modular: `show chassis fpc` shows FPC 0 only.
Platform failures: vJunos/vMX have no environment/fans/PSU; EX2300/EX3400 have `show chassis environment` limited; SRX branch (SRX3xx) has `show chassis environment` but no FPC redundancy; `show chassis routing-engine` on QFX VC shows per-member. `show chassis power` not on all EX. Use `show chassis environment | display xml` if parsing.

### Arista EOS
Commands: `show system environment all` (EOS 4.2x; older: `show environment all`), `show system environment temperature | cooling | power`, `show environment power|cooling|temperature` (legacy aliases), `show inventory`, `show module` (modular: linecards/supervisors), `show version`.
Source: Arista EOS user manual hardware environment section (https://www.arista.com/en/um-eos/eos-hardware-environment-commands, could not be fetched; tier 1, unverified); health-check pattern corroborated by https://vibehackers.io/claude-code/skills/arista-device-health (tier 3) and https://github.com/ksator/arista_eos_audit/blob/master/input.yml (tier 2, runs `show system environment temperature transceiver`, reload cause, environment commands).
Healthy: `System temperature status is: Ok`, `System cooling status is: Ok`, `System power status`: all PSUs `Ok`, each fan `Ok`, each temp sensor `Ok` with `Alert`/`Critical` thresholds not exceeded.
Findings: any sensor status `Alert` WARN, `Critical` or `Shutdown` CRIT; PSU `Failed`/`Absent`/`Unknown` (when slot populated) CRIT/WARN by redundancy; fan `Failed` or fan speed 0% WARN; supervisor `redundancy status` not `Active/Standby` with standby `Not present` = WARN on dual-sup. `show module` state != `Ok`/`Active`/`Standby` CRIT.
Noise: Unpopulated PSU slots listed `Not Inserted/Absent` on single-PSU designs = INFO. Fixed-fan speed varies; do not flag speed alone.
Platform failures: cEOS has no environment output ("no data" / blank); vEOS prints minimal or errors. `show module` only on modular chassis.

### Nokia SR OS
Classic CLI / MD-CLI (`show` in MD-CLI is the same text under `show` from any context):
- `show card state`, `show card detail` (admin/oper, hardware failure reason), `show mda`, `show chassis` / `show chassis environment` / `show chassis environment power-supply`, `show system alarm`? Not a thing: use `show log log-id 99` (default event log) and `show alarm` where configured.
Source: https://forwardingplane.net/post/nokia-sros-useful-commands/ (tier 2: show card, show chassis environment [power-supply]); https://documentation.nokia.com/sr/26-3/7750-sr/books/services-configuration-reference/show-commands.html (tier 1); https://infocenter.nokia.com/public/7705SAR234R1A/topic/com.nokia.interface-config-guide/show_card_comma-ai9kfynxiz.html (tier 1, show card summary admin/oper columns).
Healthy: every provisioned card/MDA `up/up`; CPM `up/active` and `up/standby` (redundant); fans/PSU `up`.
Findings: Oper State != `up` where Admin = `up` CRIT; `provisioned-but-not-installed`/`failed` CRIT; single CPM where standby expected WARN; PSU/fan `failed` WARN/CRIT; ` Temperature` over threshold: the table includes "Temperature threshold" fields; flag within 5 C of it WARN.
Noise: lab vSIM shows "virtual" chassis; empty card slots show `-`.

### Nokia SR Linux
`info from state platform chassis` / `show platform chassis`? Prefer state paths: `info from state /platform/chassis`, `/platform/control`, `/platform/fan-tray`, `/platform/power-supply`, `/platform/linecard` (oper-state, temperature). Healthy: `oper-state up`, temperature `instant` below `alarm-status` false. Containerlab SR Linux: hardware leafs empty -> N/A. Source: https://documentation.nokia.com/srlinux/ (tier 1; QRC PDF listed https://documentation.nokia.com/srlinux/23-3/books/pdf/SR_Linux_Command_QRC_23.3.pdf).

---
## 2. Optics DOM (digital optical monitoring)

### Junos
`show interfaces diagnostics optics <ifd>` (or no arg for all optics-equipped ports; on MX `show interfaces diagnostics optics` per-port).
Output includes: module temperature, voltage, laser bias current, Tx output power, Rx power (dBm), and per-reading alarm/warning flags for high/low alarm and warning thresholds, plus threshold values.
Healthy: all flags `off`; Rx power within [low warn, high warn].
Findings: any `Rx loss of signal`/`Laser rx power low alarm` = CRIT if port is admin up and expected up; any `warning` flag on an up port = WARN; Rx power within 2 dB of the low-warning threshold WARN **[ops]**; Tx power low alarm WARN/CRIT; bias current high warning WARN (aging laser). Rx power change of > 3 dB vs prior snapshot WARN **[ops]**.
Noise: unplugged/admin-down ports report LOS and alarms: only evaluate admin-up ports with link up OR admin-up ports that are down but expected up (separately). Copper/DAC/AOC: DOM absent or only partial (`N/A`). Some EX/QFX output "Diagnostics not supported" for non-DOM optics.
Platform failures: vJunos, vSRX, built-in copper ports: errors/empty. QFX5k DAC: "Optical diagnostic data not available".
Source: Juniper docs show interfaces diagnostics optics (tier 1; command exists, thresholds layout from knowledge) - no URL fetched. Stated operational reason: degraded light precedes CRC/flaps.

### Arista EOS
`show interfaces transceiver` (summary DOM), `show interfaces <Et> transceiver detail` (thresholds high/low alarm & warn per metric), `show interfaces transceiver hardware`, `show system environment temperature transceiver`.
Healthy: Rx/Tx within thresholds; detail output shows `Rx Power`, thresholds columns. Findings: value past `Low/High Warn` WARN, past `Alarm` CRIT; `-inf`/`N/A` Rx on an up port = copper or not DOM; Rx below roughly -10 dBm on 10G SFP+ often a degraded link, but thresholds are optic-specific, so prefer the transceiver's own threshold columns (third-party figure from https://vibehackers.io/claude-code/skills/arista-device-health, tier 3). Transceiver temp above its warn threshold WARN.
Noise: passive DAC/copper, 1000BASE-T SFP, QSFP breakout lanes (lane 1-4 individual). Unsupported transceiver messages in logs are not DOM faults.
Platform failures: cEOS/vEOS have no transceivers.

### Nokia
SR OS: `show port <port> optical` (tier 2: https://forwardingplane.net/post/nokia-sros-useful-commands/); `show port detail` also; output contains Rx/Tx power, temperature, bias, and `Low Alarm / Low Warn / High Warn / High Alarm` thresholds plus flags. MD-CLI: same `show port 1/1/c1/1 optical`. SR Linux: `info from state /interface ethernet-1/1 transceiver` (includes `laser-bias-current`, `output-power`, `input-power`, `module-temperature`, thresholds under `/interface/transceiver/...`). Same thresholds logic; DAC/virtual = N/A.

---
## 3. CPU and memory

- Junos: `show chassis routing-engine` (CPU `Idle %`, `Memory utilization %`, 1/5/15 load), `show chassis fpc` (FPC CPU, heap, buffer), `show system processes extensive | no-more` (top consumers), `show system memory` (some platforms), `show task memory` (rpd), `show system statistics`. Source: sharedcontext juniper-device-health (tier 3); RE spikes at commit are normal - cross-check `show system commit` (tier 3 note).
  Finding: RE idle < 20% sustained over two samples WARN, < 5% CRIT; memory util > 85% WARN, > 90% CRIT **[ops]** (Junos RE memory util often reports high from caches; use `show system memory` free/inactive pages on Evolved/FreeBSD where possible). rpd or chassisd/mgd high CPU alone is a hint, not a conclusion. Noise: commit, large `show route` sessions, SNMP polling spikes, `kernel` process high on EX during MAC learning storms.
- Arista: `show processes top once` (or `show processes top memory once`), `show version` (total/free memory), `show system resources`? not present; use `show processes top once` header `%Cpu(s)` `MiB Mem`. Finding: CPU idle < 20% sustained WARN; free memory < 10% (note Linux caches: use `avail Mem`, not `free`) WARN; any process in D-state / `Sysdb` or `ribd` high. Source: Arista manual (tier 1, unfetched) + ksator audit (tier 2).
- Nokia SR OS: `show system cpu` (classic; per-task breakdown, `Idle`), `show system memory-pools`, `show system information` (CPU/mem on CPM), `show card state` for IOM; `show system resource-usage`? not standard. Finding: `show system cpu` idle < 20% WARN. MD-CLI same commands. Platform-specific: vSIM CPU reads high (software forwarding) INFO. (tier unverified; search found no authoritative page for `show system cpu`, so verify on box.)
- SR Linux: `info from state /platform/control A cpu` and `/platform/control A memory` (utilization, free, used). Healthy < 70%.

---
## 4. Software version, uptime, reload cause, core dumps

- Junos: `show version` (+ `show version invoke-on all-routing-engines` on dual RE), `show system uptime` (system booted / last configured), `show system core-dumps` (and `file list /var/crash/ detail`, `file list /var/tmp/*core*`), `show system boot-messages` (some), `show chassis routing-engine` (Last reboot reason). `request support information` is heavy: not read-only-light, skip.
  Findings: core files present = WARN (CRIT if recent, within 24h, or on RE after a reboot); `Last reboot reason: 0x...` other than normal (power cycle `0x200`? `Router rebooted after a normal shutdown` = INFO) unexpected = WARN; uptime < 24h unexpected = WARN, < 1h CRIT; EOL/old version flag against policy/known-good list (needs customer input, INFO by default). Core-dump source: sharedcontext (tier 3) + command reference tier 1 (show system core-dumps in System Basics).
  Noise: old cores from months ago: report with age. ISSU/maintenance reboots: correlate with change windows.
- Arista: `show version` (also `show version detail`), `show uptime`, `show reload cause` (also `show reload cause all`? use `show reload cause`), `show agent logs crash` , `bash ls /var/core` is not CLI read-only-clean (bash shell); use `show agent logs crash` and `dir core:` (EOS `dir core:` lists core files, read-only). Findings: reload cause `Kernel panic`, `Watchdog`, `Power loss`, `Hardware` or agent crash = CRIT/WARN; `User requested` / `Reload requested by ...` INFO; cores present WARN. Source: Arista manual (tier 1, unfetched); vibehackers arista-device-health (tier 3) lists kernel panic/watchdog/power loss as unexpected.
- Nokia SR OS: `show version`, `show system information` (includes "Up Time", "Last Booted"), `show system boot-bof`? not needed; `show log log-id 99` for crashes; `file dir cf3:\` for crash files (`file dir` is read-only; look for `*.dump`/`crash*` ). Findings: crash files or `Last boot reason` abnormal WARN. SR Linux: `show system information`, `info from state /system/information`, `info from state /system/app-management` (app restarts).

---
## 5. Logs
- Junos: `show log messages | last 200`, `show log messages | match "error|crit|alert|emerg|fail|down|flap"`, `show log chassisd | last 50`, `show log jam`? not. Findings: severity >= error recent (last 24h) WARN; chassisd / fpc / pfe / kernel / `ksyncd` / `RPD_*_DOWN` messages. Known noise: SSH scanner `sshd` auth failures (INFO/security), `UI_CMDLINE_READ_LINE` command logging, `LIBJNX`/SNMP trap noise, NTP step messages.
- Arista: `show logging last 24 hours`, `show logging | include (ERR|CRIT|ALERT|EMERG)`, `show logging threshold`? skip. Findings: `%SYS-3-`, `%LINEPROTO-5-UPDOWN` flaps, `%ETH-4-` , `%PLATFORM`, `%OSPF-`, `%BGP-3-NOTIFICATION`.
- Nokia SR OS: `show log log-id 99` (default log, ring buffer) and `show log log-id 100` (main); `show log event-control` to see suppression (tier 2 above). SR Linux: `show system logging`? Use `bash tail /var/log/srlinux/debug/messages` is not CLI-only; use `info from state /system/logging` and `show system logging buffer messages` (varies).
Source note: tier 3/ops. Operational reason: logs are the first place flaps, parity errors, ECC, power events appear; rate-limit output to last N lines/24h and group by message ID.

---
## 6. Interface errors, discards, CRC, flaps, utilization

- Junos: `show interfaces extensive <ifd>` or `show interfaces terse` for state, `show interfaces extensive | match "Physical interface|Input errors|Output errors|CRC|Last flapped|Carrier transitions|drops|Policed|Bit rate"`, `show interfaces queue`, `show interfaces statistics`, `show interfaces detail`. Findings: input errors/CRC (`CRC/Align errors`, `Framing errors`, `Runts`, `Giants`) increasing between two samples = WARN (CRIT if rate > ~0.1% of packets or link is flapping); `Carrier transitions` increasing or `Last flapped` < 24 h on an up non-access link WARN, < 5 min CRIT; output drops/`Queue drops` increasing WARN; input `Policed` normal for CoPP. Utilization from `Input rate/Output rate` vs speed: > 80% sustained WARN, > 95% CRIT **[ops]** (instantaneous only; need a second sample or telemetry). Noise: counters historic since last clear; access ports connected to PCs flap by design; `Resource errors` on some EX; unplugged admin-up ports. Source: Juniper docs show interfaces extensive (tier 1 command), thresholds ops.
  Also check duplex/speed mismatches (`Link-mode: Half-duplex`, speed lower than expected) = WARN; `MTU` mismatch on both ends shows up as giants/drops.
- Arista: `show interfaces counters errors` (FCS, Align, Symbol, Rx runts/giants, Tx errors), `show interfaces counters discards` (in/out discards), `show interfaces counters rates` (in/out Mbps, pct), `show interfaces status` (connected/notconnect/errdisabled), `show interfaces <Et>` (has `Last link state change`/ flaps via `show interfaces | grep -i "changes"`), `show interfaces counters queue` / `show qos interfaces ... counters`. Findings: any non-zero error counter that grows WARN; `errdisabled` ports CRIT unless expected (`show interfaces status errdisabled`); `Last link state change` < 24 h WARN; `show interfaces counters rates` pct > 80 WARN. Noise: discards on Arista include policy/ACL/unknown-VLAN drops; Rx discards on trunk toward host often benign. Source: Arista manual (tier 1, unfetched).
- Nokia SR OS: `show port` (summary state), `show port <p> detail` (errors, FCS, `Input errors`, `Output errors`, `Last State Change`), `show port statistics`, `monitor port <p> interval 5 repeat 3 rate` (live rates; tier 2 mention). Findings same: increasing errors/FCS, `Link Down` on admin-up. SR Linux: `show interface ethernet-1/1 detail`, `info from state /interface ethernet-1/1 statistics`.

---
## 7. STP topology changes
- Junos: `show spanning-tree bridge` (look at `Topology change count`, `Time since last topology change`, root bridge identity), `show spanning-tree interface`, `show spanning-tree statistics`; for RSTP/MSTP `show spanning-tree mstp configuration`. Findings: topology change count rising, last change < 15 min ago WARN (< 1 min CRIT during storm); unexpected root bridge (not the intended root) WARN; ports in `BLK` unexpected. Edge ports flapping is the usual cause.
- Arista: `show spanning-tree` (root, `Topology changes`), `show spanning-tree topology status`, `show spanning-tree blockedports`, `show spanning-tree counters`. Same rules.
- Nokia SR OS: `show service id <id> stp detail`; SR Linux uses `show network-instance <ni> protocols bridge-table`/STP states.
Source: ops reasoning; STP TCN rates flush MAC tables causing flooding.

---
## 8. Routing adjacency and flaps (OSPF, IS-IS, BGP) and BFD
- Junos: `show ospf neighbor` (state Full; flag Init/2Way/ExStart; 2Way is normal on broadcast between non-DR/BDR), `show isis adjacency` (Up), `show bgp summary` (State/Pfxrcvd column: numeric = Established; `Active`/`Connect`/`Idle` = down; Flaps and `Last Up/Down` columns), `show bgp neighbor | match "Peer:|State|Last State|Flaps|Last Error"`, `show bfd session`, `show route summary`. Findings: configured neighbor not in Established/Full/Up = CRIT (WARN if known standby); `Flap Count` > 0 with `Last Up/Dwn` < 24 h WARN; neighbor up < 5 min CRIT/WARN; prefixes received dropped to 0 or by > 50% vs snapshot WARN. Noise: `Idle (Admin)` is deliberately disabled; BGP peers with `inactive` family; dampening. Source: https://juniper.net/documentation/en_US/junos12.3/topics/task/operational/junos-cli-router-status-checking.html (tier 1 router status checking).
- Arista: `show ip ospf neighbor`, `show isis neighbors`, `show ip bgp summary` (also `show bgp summary` for multi-AF), `show bgp neighbors <ip>`, `show bfd peers`. Same logic. Columns: `Up/Down` time, `State`, `InMsgQ`/`OutQ` (non-zero persistent queue = WARN).
- Nokia SR OS: `show router ospf neighbor`, `show router isis adjacency`, `show router bgp summary` (tier 2 listed), `show router bgp neighbor <ip>`, `show router bfd session`, `show router mpls lsp` (LSP Oper state). SR Linux: `show network-instance default protocols bgp neighbor`, `... ospf neighbor`, `... isis adjacency`.
Operational reason: adjacency state and uptime are the direct reachability signal; short uptime = recent flap.

---
## 9. VRRP / first-hop redundancy
- Junos: `show vrrp summary`, `show vrrp brief`, `show vrrp detail` (state master/backup, `Priority`, `Master router`, `Down` state). Findings: group in `Init`/`Down` WARN; two masters across pair (check both devices) CRIT; master != intended priority (preempt not taking) INFO/WARN; master transitions count high (`Master transitions` in detail) WARN. 
- Arista: `show vrrp`, `show vrrp brief`, `show ip virtual-router` (virtual-router, not VRRP). 
- Nokia SR OS: `show router vrrp instance`, `show router vrrp statistics`.
Noise: lab single-box groups stay Master.

---
## 10. MLAG / VC / Chassis cluster
- Arista MLAG: `show mlag` (state Active; `negotiation status: Connected`; `peer-link status: Up`; `local-interface status: Up`), `show mlag detail`, `show mlag config-sanity` (compares local/peer: lists inconsistent global/interface config, e.g. VLAN mismatch, STP mode mismatch), `show mlag interfaces` (State `active-full`; `active-partial`/`disabled` = problem), `show mlag issu`? skip. Findings: state != Active CRIT; `config-sanity` any `Inconsistent` WARN; mlag interfaces `active-partial` WARN; `peer-address heartbeat` Inactive WARN. Source: Arista manual MLAG chapter (tier 1, unfetched); tier 3 vibehackers.
- Junos Virtual Chassis (EX/QFX): `show virtual-chassis status` (member Prsnt, role Master/Backup/Linecard, Mixed), `show virtual-chassis vc-port` (Up), `show virtual-chassis protocol` . Findings: member `NotPrsnt` or `Inactive` CRIT; vc-port Down WARN/CRIT; two masters in same VC = split-brain CRIT; mastership priority different from intended INFO. Platform: QFX VC (QFX5100) and EX; not on MX/SRX. Junos MC-LAG/ICCP (MX/QFX): `show iccp`, `show interfaces mc-ae`.
- Junos ESI-LAG/EVPN: `show evpn instance`, `show bgp summary group evpn`.
- SRX chassis cluster: `show chassis cluster status` (redundancy group 0 and 1+: one node `primary`, one `secondary`; priorities; `Monitor-failures: None`), `show chassis cluster interfaces` (control/fabric Up), `show chassis cluster statistics` (heartbeat/probe counts), `show chassis cluster information` (failover reason history), `show chassis cluster status redundancy-group 1`. Findings: node `lost` or `unavailable`/`ineligible` or `disabled` CRIT; both `primary` split-brain CRIT; `secondary-hold` persistent WARN; `Failover count` increasing/recent failover reason in `information` WARN; control/fabric link Down CRIT; `Monitor-failures` other than None WARN; mixed software versions between nodes CRIT. Noise: `secondary-hold` is transient after a node boot (about 5 min). Not present on non-clustered SRX: error "Chassis cluster is not enabled" -> N/A. Source: Juniper SRX chassis-cluster docs (tier 1, https://juniper.net/documentation/software/junos-security/junos-security96/junos-security-admin-guide/monitoring-alarms.html adjacent; command from knowledge, verify).
- Nokia: `show redundancy synchronization` (CPM standby sync state), `show system redundancy`? use `show redundancy`. Findings: not `synchronized`/standby not ready WARN. Multi-chassis LAG: `show lag`, `show redundancy multi-chassis sync`.

---
## 11. Commit / configuration state
- Junos: `show system commit` (last 5 commits with user/time/method; flag recent commits from unknown user/or `confirmed` commits pending), `show system commit revision`, `show system users` (anyone in config mode: `show system users` and `show configuration | compare rollback 0` only within a config session), `show system alarms` ("Autorecovery"/"commit confirmed pending" ), `show | compare rollback 1` requires config mode; use `show system rollback compare 0 1` (operational mode). Findings: a **pending `commit confirmed`** CRIT (will roll back); config database locked/exclusive edit by another user WARN (`show system configuration database usage`; `show configuration database` variants), `Another user is configuring` / uncommitted candidate changes (`show system users` shows `[edit]`) WARN. Noise: automation users commit frequently.
- Arista: `show running-config diffs` (running vs startup; non-empty = unsaved changes WARN), `show configuration sessions` (pending sessions: pending commit-timer sessions CRIT), `show startup-config`, `show archive`? , `show configuration sessions detail`. Finding: running != startup WARN (config lost on reload). Timer-based session `commit timer` pending CRIT.
- Nokia SR OS: classic `admin display-config` too heavy; use `show bof` (boot options), `show system information` (configuration modified/saved timestamps: "Last Modified", "Last Saved", "Last Admin Save"), `admin save` is a write: avoid. MD-CLI: `show system configuration`? use `info /configure system name` ... and `compare summary`: needs candidate. `show system information` prints "Configuration Modified/Saved" fields; modified > saved = unsaved config WARN. SR Linux: `info from state /system/configuration` ... `diff` against baseline; `show system configuration` unsure; flag `candidate` datastore with uncommitted changes (`info from state /system/configuration/commit`).

---
## 12. NTP
- Junos: `show ntp associations` (leading `*` = selected sync peer, `+` candidate; `st` stratum, `reach` 377 octal = last 8 polls OK, `delay`, `offset` ms, `jitter`), `show ntp status` (`system peer`, `stratum` < 16, `leap`, `offset`). Findings: no `*` peer CRIT/WARN; stratum 16 = unsynchronized CRIT; reach < 377 sustained WARN (0 = unreachable); offset > 100 ms WARN, > 1 s CRIT **[ops]** (Kerberos/cert/log correlation fail beyond that). Junos NTP can take ~5-15 min after boot to sync: do not flag uptime < 15 min. Also check via mgmt routing instance (`show ntp associations routing-instance mgmt_junos`).
- Arista: `show ntp status` (`synchronised to NTP server`/`unsynchronised`), `show ntp associations` (`*` peer, `reach`, `offset`). Same.
- Nokia SR OS: `show system ntp` (`show system ntp all`), `show system ntp servers`. SR Linux: `show system ntp server`.
Source: ops reasoning; tier 3 sharedcontext Juniper/Arista health skills list NTP.

---
## 13. Storage
- Junos: `show system storage` (Mounted on `/`, `/var`, `/config`, `/tmp`; `Capacity` %). Flag any filesystem > 85% WARN, > 95% CRIT; `/var` full common (logs, cores, upgrade images) -> `request system storage cleanup` is a write: only suggest, never run. Noise: `/dev/md*` read-only images at 100% (`/packages`, `/junos`, `/dev/gpt/*` jbundle mounts) always 100% = ignore (mounted `ro`). Source: sharedcontext (tier 3) + Junos system basics (tier 1 command).
- Arista: `dir flash:` (free bytes), `bash df -h` is shell; use `show file systems` (Size/Free). Flag flash free < 15% WARN, < 5% CRIT. Also check `dir core:` and `dir log:`. 
- Nokia SR OS: `file dir cf3:` + `file vol cf3:`(shows free space on compact flash), `show system information`. Flag cf3: < 10% free WARN.
- SR Linux: `info from state /platform/linecard` ... or `show file systems`? use `bash` no; `info from state /system/...`; leave N/A if unavailable.

---
## 14. License
- Junos: `show system license` (installed licenses, `Licensed features` used vs. installed, `Valid until`, expired), `show system license usage`, `show system alarms` ("Missing license" alarms). Findings: expired or `Used > Installed` WARN; evaluation/grace license expiring < 30 d WARN, < 7 d CRIT; EX/QFX feature (e.g. `bgp`, `mpls`, `vc` ) used without license is a Minor alarm. Noise: lab/eval boxes. SRX: `show system license` plus `show security idp ... ` skip; AppSecure/IDP signature license `Expires` matters.
- Arista: EOS has no feature license for most platforms. CloudVision/virtual (vEOS) `show license` may exist on cEOS/vEOS (CloudEOS): mark N/A if error. 
- Nokia SR OS: `show system license` (feature licences, expiry); SR Linux: `info from state /system/license`? (platform-dependent).

---
## 15. Clearly harmful misconfigurations to flag (config checks, read-only via `show configuration | display set | match ...` / `show running-config`)
Each is a flag because of a concrete failure mode **[ops]** unless noted:
- Junos: no `system ntp`/`time-zone` set; no `system syslog` remote host; `root-authentication` using plain `$1$` MD5 or missing; `system services telnet` / `ftp` enabled; no `snmp` v3 and community `public` with write; missing `system login retry-options`; `protocols rstp/vstp` not set on trunk-heavy switch with no BPDU guard on edge ports (`bpdu-block-on-edge` missing); `set interfaces ... mtu` mismatch with neighbor; `routing-options autonomous-system` missing while BGP configured; BGP without `hold-time`/BFD; `commit synchronize` missing on dual-RE (`system commit synchronize` and `chassis redundancy graceful-switchover` + `routing-options nonstop-routing` missing = RE failover drops routes); `ge-0/0/0` management in default instance conflicts with in-band routing; no `system arp aging-timer`. 
- Arista: `spanning-tree mode none` on L2 with loops; no `ntp server`; `logging host` missing; `service routing protocols model multi-agent` vs `ribd` mismatch; MLAG `peer-link` not in `spanning-tree` portfast/`no spanning-tree` correct; MLAG with `domain-id` mismatch -> reported by `show mlag config-sanity` (tier 1); port-channel `lacp mode` mismatch; mtu mismatch; `ip routing` missing on L3 switch; default `enable` without password / `username admin nopassword`.
- Nokia SR OS: system `time`/NTP missing; `snmp` default community; BGP without `authentication-key`/`bfd` ; ports `mtu` mismatches; `show system security` / `show system security management-access-filter` absent = management plane exposed; MPLS LSP `shutdown`.

---
## 16. Suggested skill structure (output)
For each check: command, parse rule, severity, `N/A` conditions (above), and a "needs second sample" flag for counter checks. Group findings: CRIT, WARN, INFO; list N/A checks separately so a clean-looking report is not mistaken for coverage.

## 17. Known gaps (not verified)
- No fetched Arista manual page; syntax like `show system environment all` vs `show environment all` is release dependent (EOS 4.x accepts both on most). Re-verify.
- Nokia `show system cpu`, SR Linux state paths: from memory; confirm in lab.
- Numeric thresholds in this doc are operational defaults, not vendor limits, except where a device's own alarm/threshold column is used (preferred).
