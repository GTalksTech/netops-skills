# Cisco read-only health check research (IOS/IOS-XE, NX-OS, ASA)

Date: 2026-11-07. Method: three web searches confirmed the URLs marked [V] below. Everything else is drawn from standard Cisco command behavior and operational practice; those rows carry a stated operational reason and a canonical Cisco doc URL marked [C] (cited from knowledge, not re-fetched this session). Thresholds are conventional engineering defaults, not Cisco-mandated numbers, unless noted. Tune per site.

Platform codes: XE = IOS-XE (Cat 9000, ISR, ASR, Cat8k); IOS = classic IOS / IOL / IOSv; NX = NX-OS 9000; ASA.

## Sources
- S1 [V, tier 1] Cisco TAC 213549 Troubleshoot high CPU in Catalyst 9000 (IOS XE 16.x): https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xe-16/213549-troubleshoot-high-cpu-usage-in-catalyst.html
- S2 [V, tier 1] Cisco TAC 222469 Reporting problems effectively to TAC (lists `show platform resources`, `show processes cpu platform sorted`, QFP utilization; >80% treated as high): https://www.cisco.com/c/en/us/support/docs/technical-details/222469-reporting-problems-effectively-to-tac-se.html
- S3 [V, tier 1] Cisco Live BRKTRS-3090 Catalyst 9000 troubleshooting: https://www.ciscolive.com/c/dam/r/ciscolive/emea/docs/2025/pdf/BRKTRS-3090.pdf
- S4 [V, tier 1] Cisco TAC 217989 Troubleshoot vPC inconsistency issues on Nexus: https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/nx-os-software/217989-troubleshoot-vpc-inconsistency-issues-on.html
- S5 [V, tier 1] ASA command reference (show failover, show conn count, show resource usage): https://www3-realm.cisco.com/en/US/docs/security/asa/command-reference/s7.html
- S6 [V, tier 3] Cisco Community ASA failover troubleshooting (`show failover history`): https://community.cisco.com/t5/network-security/asa-5525-failover-troubleshooting/td-p/4546058
- S7 [V, tier 3] Cisco Community ASA conns/resource usage: https://community.cisco.com/t5/network-security/asa-5585-maximum-number-of-connections/m-p/2516357
- S8 [C, tier 1] Cisco TAC 29807 Troubleshooting switch port and interface problems (CRC, runts, giants, late collisions, duplex): https://www.cisco.com/c/en/us/support/docs/lan-switching/ethernet/12768-arptable-12768.html is NOT this one; use search "Troubleshooting Switch Port and Interface Problems cisco 17) doc 12768" -- verify id before citing. Fallback canonical: https://www.cisco.com/c/en/us/support/docs/lan-switching/ethernet/10561-3.html (Configuring and Troubleshooting Ethernet 10/100/1000Mb Half/Full Duplex Auto-Negotiation).
- S9 [C, tier 1] Cisco TAC Understanding Spanning Tree topology changes (STP TCN troubleshooting): https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/28943-170.html
- S10 [C, tier 1] Cisco Transceiver Module DOM / `show interfaces transceiver` command reference (IOS XE Catalyst 9000 Interface and Hardware Components command reference): https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/command_reference/b_179_9300_cr.html
- S11 [C, tier 1] NX-OS Troubleshooting guide (system resources, vPC, hardware): https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/102x/troubleshooting/cisco-nexus-9000-nx-os-troubleshooting-guide-102x.html
- S12 [C, tier 1] Cisco IOS XE Catalyst 9000 Stacking (StackWise) configuration guide: https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/stck_mgr_ha/b_179_stck_mgr_ha_9300_cg.html
- S13 [C, tier 1] Cisco Nexus 9000 NX-API vpc command reference: https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/vpc-commands [V search hit]
- Tier-3 caution: third-party "device health skill" pages surfaced in search (sharedcontext.ai, clawhub.ai) propose a CPU>70% threshold; opinion only, not used as authority.

## General rules for the skill
- Run as privilege 15 / network-operator; every command below is read-only. Avoid `debug`, `clear`, `show tech-support` on production (large, CPU-heavy) unless asked. `terminal length 0` (IOS/XE/NX) / `terminal pager 0` (ASA) is a session setting, not a config change.
- Rates, not totals: counters are cumulative since last `clear counters`/reload. Judge errors as a delta between two snapshots or as ratio to packets (errors / total packets), and by "last clearing of counters". Reason: lifetime counters on a 2-year-uptime switch carry stale history (S8 principle).
- Always capture `show clock` and `show version | include uptime` first so ages in other outputs can be interpreted.

## 1. Hardware: PSU, fans, temperature
| Platform | Commands |
|---|---|
| XE Cat9k | `show environment all` (also `show environment power`, `show environment temperature`, `show environment fan`); `show platform hardware chassis power-supply` varies; `show inventory` |
| XE ISR/ASR/Cat8k | `show environment all`; `show platform` (slot/state); `show platform hardware slot ... ` not needed |
| IOS older | `show environment all` |
| NX | `show environment` (power, fan, temperature); `show environment power`, `show environment fan`, `show environment temperature`; `show module`; `show inventory` |
| ASA | `show environment` (hardware ASA only; fans, power, temp, CPU/chassis temp) |

Healthy: PSU "Good/OK", fans "OK"/"Normal", temperature state "Normal"/"OK"/"GREEN", all modules "ok/active/ha-standby".
Findings: any PSU in Fail/Absent/"No Input" when it should be present (High if redundancy lost; Critical if sole PSU); fan "Fail"/"Fan Fail" (High); temperature state "Yellow/Minor/Major/Critical" or reading above the device's own minor threshold (Medium at minor, High at major); module state not ok/active/standby (High). NX-OS `show module` status "powered-dn", "failure", "testing" (High).
False positives: empty PSU bay on a single-PSU design (compare to `show inventory`, an unpopulated optional bay is Info); "Not Present" fan tray on fixed fanless models; N/A sensors; Cat9200L fanless.
Not supported: IOL/IOSv/CML virtual images give empty or "not supported" `show environment` -> mark "n/a (virtual)", not a finding. ASAv has no `show environment`. Some Cat9k models omit `show environment all` sub-keywords (try `show environment` bare). Reason: sensors are physical.
Source: S11 (NX), S3 (Cat9k), S2; stated reason: vendor environment state is the device's own alarm logic, so reporting its states is authoritative.

### Optics DOM
Commands: XE `show interfaces transceiver detail` (older IOS `show interfaces transceiver detail`; `show interfaces <int> transceiver detail`); NX `show interface transceiver details` (also `show interface ethernet x/y transceiver details`); ASA hardware: `show interface detail` (limited); not generally available.
Output has Tx/Rx power (dBm), temperature, voltage, bias current, each with high/low alarm and warning thresholds, and in many releases a flag column (HA/HW/LW/LA).
Healthy: all values between low-warn and high-warn.
Finding: any value flagged at/beyond a warning threshold (Medium); beyond alarm threshold (High); Rx power below low-warn on a link that is up means marginal fibre/dirty connector (High if errors co-occur). Rx power "N/A" or "-40.0 dBm" with link down is simply no light (finding only if port should be up).
False positives: copper/DAC/passive cables and non-DOM optics show "N/A" or "Transceiver is not DOM capable" (ignore); third-party optics may report nonstandard thresholds; unused/shutdown ports show no data; Rx on 10G LR in short patches can read high-warn legitimately (verify with Tx/Rx pair).
Source: S10 [C]; operational reason: DOM thresholds are set by the optic manufacturer, so comparing readings to those thresholds is the standard degradation check.

## 2. CPU and memory
| Platform | Commands |
|---|---|
| XE | `show processes cpu sorted` (shows "five seconds: X%/Y%": total/interrupt), `show processes cpu history`, `show processes cpu platform sorted` (Linux-level, Cat9k/ASR), `show platform resources`, `show processes memory sorted`, `show platform software status control-processor brief` |
| IOS | `show processes cpu sorted`, `show processes memory sorted`, `show memory statistics` |
| NX | `show system resources`, `show processes cpu sort`, `show processes cpu history`, `show processes memory` |
| ASA | `show cpu usage`, `show memory`, `show processes cpu-usage sorted`, `show blocks` (low-water marks on 1550/9472 blocks) |

Healthy: 5-min CPU below ~50%; interrupt portion (value after the slash in "X%/Y%") low (<10%); memory used <80% and stable (free memory not trending down).
Findings: 5-min average >80% sustained (High; S2 treats >80% as high), 60-70% sustained (Medium, convention); interrupt CPU large share (e.g. >30% of total) means traffic punted to CPU or loop (High; S1 explains interrupt-driven CPU such as ARP storms); `show platform resources` shows state not "Healthy" or "Critical" (High); memory used >85-90% (High) or "Low" memory logs %SYS-2-MALLOCFAIL (Critical); NX `show system resources` memory <10% free or load average >> cores. ASA: `show blocks` low-water of 0 on 256/1550 (High: dropped packets).
False positives: short spikes (5-sec) right after SSH login, `show tech`, routing convergence or config save; IOS-XE reports total system memory including Linux cache so "used" appears high -- use `show platform resources` Healthy status rather than raw percent; CPU "Healthy" state name differs by release. Compare 1-min/5-min, not only 5-sec.
Source: S1, S2, S3 (tier 1); NX S11; ASA S5.
Not supported: IOL/IOSv give `show processes cpu` but not `show platform resources`/`show processes cpu platform` (degrade to IOS-style commands). NX `show system resources` is universal on N9K. ASAv: `show cpu usage` works.

## 3. Software, uptime, reload reason, crashes, logs
Commands: XE/IOS `show version` (uptime, "System returned to ROM by", image, last reload reason), `show reload`, `show logging | include %SYS|%PLATFORM|%CRASH`, `dir crashinfo:` / `dir flash: | include crash`, `show platform software ... ` skip; XE also `dir bootflash:core`, `show redundancy` (switchover reason). NX `show version`, `show system reset-reason`, `show cores`, `show core`, `show processes log`, `show logging last 100`, `show logging logfile | include "ERR|CRIT|ALERT|EMERG"`. ASA `show version`, `show crashinfo`, `show failover history`.
Healthy: uptime large and consistent with change calendar; reload reason "Reload Command"/"Power On" expected; no core files; no EMERG/ALERT/CRIT logs recently.
Findings: reload reason "Reload due to power failure"/"Watchdog"/"Kernel panic"/"Crash" or "System returned to ROM by error - a SPURIOUS_INTERRUPT/bus error" (High); uptime less than ~24 h without known change (Medium, Info if recent change window); core/crashinfo files present with recent timestamp (High); severity 0-2 log lines (High-Critical), severity 3 (Medium); software version on Cisco end-of-life/known-vulnerable train (Info/Medium; skill should only flag versions it can verify, flag "check PSIRT" otherwise). Mixed versions across stack members or HA pair (High).
False positives: single old crashinfo/core with old date; `%SYS-5-CONFIG_I` and other severity 5-6 noise; logs buffer rolled over so absence of logs is not evidence of health; logging buffer disabled (note the gap).
Source: S3, S11, S5; operational reason: reload reason and cores are the device's own post-mortem record.
Not supported: IOL has no ROM-reason or crashinfo; `show system reset-reason` absent on some older NX-OS and Nexus 3k on virtual NX-OSv.

## 4. Interface errors, discards, CRC, drops
Commands: XE/IOS `show interfaces` (or `show interfaces counters errors`, `show interfaces | include line protocol|input errors|CRC|output drops|collisions|runts|giants`, `show interfaces status`, `show interfaces counters`), Cat9k `show platform hardware fed switch active fwd-asic drops` skip detail; NX `show interface counters errors`, `show interface`, `show interface status`; ASA `show interface`, `show interface detail`, `show traffic`.
Healthy: CRC/input errors/runts/giants/frame = 0 or tiny relative to packets; output drops 0 or <0.01% of output packets.
Findings (judge on rate/ratio, per S8 and standard practice):
- CRC/FCS or input errors increasing between two snapshots, or CRC > 0.001% of input packets (Medium); >0.1% or CRC counting on an uplink (High) -> cabling, optics, duplex.
- Late collisions/collisions on a full-duplex link (High, duplex mismatch).
- Runts/giants: giants may be jumbo traffic if MTU>1500 (compare to MTU), else Medium.
- Output drops > 0 steadily increasing, or `Total output drops` ratio >0.5% of output packets (Medium; High if >2% or on uplink); input queue drops/flushes (Medium).
- Overruns/ignored (Medium; buffer pressure).
False positives: counters are lifetime; check "Last clearing of counters"; CRC on interfaces connected to IP phones/APs that were flapped once; output drops on tail-drop QoS queues from microbursts when utilization low (Info unless growing); runts counted from link negotiation events; dropping counters on SPAN destination ports; "input errors" includes giants/overruns so avoid double counting; NX `show interface` "input error" also counts discards on some platforms.
Source: S8 (fallback https://www.cisco.com/c/en/us/support/docs/lan-switching/ethernet/10561-3.html), S11. Platform: Cat9k `show interfaces counters errors` columns Align-Err FCS-Err Xmit-Err Rcv-Err UnderSize OutDiscards.
Virtual (IOL/IOSv) interfaces show zeros: not a finding.

## 5. Port flaps
Commands: `show logging | include UPDOWN|LINK-3|LINEPROTO|link status changed|%PM-4|ETHPORT` ; `show interfaces <x>` -> "Last input", "Last output", "output hang", "Last clearing", "carrier transitions" (on routed/serial/some Ethernet), "Interface resets"; NX `show interface <x>` has "Last link flapped", "Last clearing of show interface counters", `show logging | include ETHPORT-5-IF_DOWN|IF_UP`; XE also `show interfaces <x> | include flapped|resets|transitions`.
Healthy: last flap long ago (days) unless access port to user; resets 0.
Finding: >3 up/down events in 1 hour on same port (Medium), >10 or continuous (High, esp. uplink/port-channel member); "Interface resets" non-zero and increasing (Medium); Last input "never" on link that should be active is info. NX-OS `Last link flapped` < 1 hour on uplink (Medium).
False positives: access ports to PCs/laptops/phones powering on/off, desk phones rebooting; maintenance window flaps; %LINEPROTO changes on shutdown/no shutdown by admin (cross-check recent config).
Source: operational reason: UPDOWN messages and flap timestamps are the primary flap record (S8, S11).

## 6. Utilization
Commands: `show interfaces | include rate|^[A-Z].*is` (input/output rate, load) ; XE `show interfaces summary`; NX `show interface | include "rate|^Eth"`, `show interface counters`.
Finding: 5-minute input or output rate >70% of bandwidth sustained (Medium), >85-90% (High) on uplinks; txload/rxload 200+/255 (≈80%). Asymmetry on a port-channel members (one member >> others) = poor hash (Info/Medium).
False positives: default load interval is 5 min (30s/300s), so bursts are hidden; `bandwidth` command mismatches the real speed on subinterfaces/tunnels; port-channel member rate vs. aggregate; backup/replication windows.
Source: operational reason; skill must say a single snapshot cannot establish a trend.

## 7. Err-disabled
Commands: XE/IOS `show interfaces status err-disabled`, `show errdisable recovery`, `show errdisable detect`, logs `%PM-4-ERR_DISABLE`; NX `show interface status err-disabled`, `show errdisable recovery`... (NX-OS: `show interface status err-disabled`); ASA n/a.
Healthy: none. Finding: any port err-disabled (Medium; High if uplink, trunk, or port-channel member). Report reason (bpduguard, psecure-violation, link-flap, loopback, udld, storm-control) because remediation differs.
False positives: intentional shutdown by admin is "disabled" not "err-disabled"; unused ports with portfast+bpduguard tripped long ago (Low, but note).
Source: S11, S3; Cisco "Errdisable Port State Recovery" [C]: https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/69980-errdisable-recovery.html

## 8. STP topology changes
Commands: XE/IOS `show spanning-tree summary`, `show spanning-tree detail | include ieee|occurred|from|is exec|Number of topology`, `show spanning-tree root`, `show spanning-tree inconsistentports`; NX `show spanning-tree summary`, `show spanning-tree detail`, `show spanning-tree inconsistent`.
Healthy: "Number of topology changes N" small and "last change occurred" many hours/days ago; the "from <interface>" points to a known port; single root bridge as designed.
Finding: topology change within the last hour (Medium); repeated TCNs, count rising between snapshots (High; usually flapping edge port without portfast/loop); root not where design expects or root bridge priority is default 32768 across the domain (Medium); "inconsistent" ports (root/loop/type-inconsistent) (High); STP mode PVST vs MST mismatch (High); no portfast on access ports generating TCNs (Medium).
False positives: TCNs from user ports with portfast enabled are not generated; one TCN after maintenance; counts are since boot so use "last change occurred" age plus delta.
Source: S9 [C]; S11.

## 9. Routing: OSPF/EIGRP/BGP, route table
Commands:
- OSPF XE/NX: `show ip ospf neighbor` (state FULL/2WAY for DR/BDR-other pairs; "Dead Time"), `show ip ospf interface brief`, `show ip ospf | include SPF|LSA`; NX `show ip ospf neighbors`.
- EIGRP: `show ip eigrp neighbors` (Uptime, SRTT, Q Cnt, Hold), `show ip eigrp topology | include Active|stuck` ; NX `show ip eigrp neighbors`.
- BGP: `show ip bgp summary` (State/PfxRcd, Up/Down time), `show bgp ipv4 unicast summary`, `show ip bgp neighbors <x> | include BGP state|Last reset|Connection state|resets`; NX `show bgp ipv4 unicast summary`, `show bgp sessions`.
- Table: `show ip route summary`, `show ip route | include ^S\*|0.0.0.0` (default route exists), `show ip route <expected prefix>`.
Healthy: neighbors in FULL/Established; uptime older than the last change; Prefixes received non-zero and stable; default route present where expected.
Findings: neighbor not FULL, stuck in INIT/EXSTART/EXCHANGE/2WAY where FULL expected (High, usually MTU mismatch); BGP state Idle/Active/Connect (High; Critical for sole upstream); neighbor uptime < 1 hour unexplained (Medium) and repeating resets (High); `Last reset` reason (Hold timer expired = underlay issue); EIGRP Q Cnt non-zero persistently or SIA logs (High); route count change large vs. previous snapshot (Medium); missing default route (High); BGP PfxRcd 0 on a neighbor expected to advertise (High), max-prefix reached (High, `%BGP-3-MAXPFX`).
False positives: OSPF 2WAY between DROTHERs is normal; passive interfaces have no neighbors by design; BGP "Idle (Admin)" is an intentional shutdown; neighbors recently reset by maintenance; uptime ordering.
Source: S11 [NX]; Cisco OSPF/EIGRP/BGP troubleshooting docs: OSPF neighbor states https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/13685-13.html [C]; BGP states https://www.cisco.com/c/en/us/support/docs/ip/border-gateway-protocol-bgp/13753-25.html [C].

## 10. HSRP / VRRP / FHRP
Commands: `show standby brief`, `show standby` (state changes, "Active router is", "Standby router is", "last state change"); `show vrrp brief`; NX `show hsrp brief`, `show vrrp`; `show glbp brief`.
Healthy: exactly one Active and one Standby per group, preferred router is Active, priorities as designed, preempt as designed, matching virtual IP.
Findings: both routers Active (split-brain, High); no Standby (Medium, lost redundancy); state "Init"/"Listen" (High); group's active router is not the intended/preferred one (Info/Medium); "state changes" count recent (Medium: "last state change" within the last hour, `%HSRP-5-STATECHANGE` repeated = flapping, High); tracked object down.
False positives: after planned failover test; HSRP version 1 vs 2 differences in group numbering; priority intentionally equal.
Source: operational reason (FHRP state is the redundancy truth); Cisco HSRP troubleshooting [C]: https://www.cisco.com/c/en/us/support/docs/ip/hot-standby-router-protocol-hsrp/9234-hsrp-support.html

## 11. vPC (NX-OS)
Commands: `show vpc` (peer status, peer-link status, keep-alive status, per-vPC consistency status, "Type-2 consistency status", Configuration consistency status), `show vpc brief`, `show vpc consistency-parameters global`, `show vpc consistency-parameters interface port-channel <id>`, `show vpc consistency-parameters vlans`, `show vpc peer-keepalive`, `show vpc role`, `show port-channel summary`.
Healthy: "Peer status: peer adjacency formed ok", "vPC keep-alive status: peer is alive", "Configuration consistency status: success", "Per-vlan consistency status: success", "Type-2 consistency status: success", all vPCs "up", peer-link up, roles one primary / one secondary.
Findings: peer adjacency not formed (Critical), keepalive "suspended"/"peer is not alive" (High), peer-link down (Critical), Type-1 inconsistency, which suspends the vPC (High, S4), Type-2 inconsistency which is reported but does not suspend (Medium, S4), vPC "down" with reason (High), orphan ports unexpectedly many (Medium), `show vpc` shows "auto-recovery" absent (Info), role-priority not set deterministically (Info/Medium), keepalive running over peer-link or mgmt VRF issue (Medium).
False positives: after a reload, vPC reaches consistent state after delay-restore timer (typically 30-240 s) - do not alarm if uptime < timer; "Type-2" mismatches such as differing STP port cost are informational; sample outputs differ across NX-OS releases.
Source: S4 [V], S13 [V search hit].

## 12. Stack and redundancy
Stack (Cat9k StackWise / 3850 / 2960X): `show switch`, `show switch detail` (role Active/Standby/Member, state Ready, priority, Stack Port Status, neighbors), `show switch stack-ports summary`, `show switch stack-mode`, `show redundancy`.
Healthy: all members "Ready", one Active, one Standby, both stack ports "OK" on each member, no version mismatch.
Findings: member in "Removed"/"Provisioned"/"V-Mismatch"/"HA-Mismatch" (High), stack port "Down"/one ring side missing = stack ring is a chain not a ring (High: no redundancy), Active role changed recently (Medium, see `show redundancy` last switchover), no Standby (High).
SSO/RP redundancy (ASR/Cat8k/Cat9400/9600/dual-sup): `show redundancy` (Operating mode SSO, Current state ACTIVE/STANDBY HOT, "Peer state", "Last switchover reason"), `show redundancy states`, `show module` on NX (sup active/ha-standby).
Healthy: Configured SSO, Operating SSO, standby "STANDBY HOT".
Findings: Standby not HOT / "Not Ready"/"Peer not present" (High), operating mode RPR not SSO (Medium), recent "Last switchover reason" other than user-forced (High).
False positives: single-supervisor chassis (no redundancy by design) shows "Simplex" (Info), single-member stack.
Not supported: fixed non-stack, ISR1k, IOL: `show switch` returns "Invalid input"; treat as n/a. NX-OS has no `show switch`; use `show module` / `show redundancy`... (NX: `show system redundancy status`).
Source: S12 [C], S3.

## 13. NTP / clock
Commands: XE/IOS `show ntp status`, `show ntp associations` (sync marker `*`, stratum, reach 377, offset ms, delay), `show clock detail`; NX `show ntp peer-status`, `show ntp peers`, `show clock`; ASA `show ntp status`, `show ntp associations`.
Healthy: "Clock is synchronized", stratum <= ~4-6 (lower is better), reach 377 (octal), offset <~10-50 ms, at least 2 servers.
Findings: "Clock is unsynchronized" (Medium; High if logs/certs/IPsec/Kerberos depend on time), no NTP configured (Medium), only one NTP server (Low/Medium), reach 0 or low (e.g. 1, 3, 7) = servers unreachable (Medium), stratum 16 (unsync), offset > 100 ms (Medium) or >1 s (High). Configure check: `show running-config | include ^ntp|clock timezone`.
False positives: freshly booted device takes up to ~5-10 min to sync; reach grows from 1,3,7,17,37,77,177,377 after startup; IOL/virtual may have no NTP master by design (use `ntp master` in labs, which shows stratum 8 as expected).
Source: operational reason (log correlation, certificates); Cisco NTP docs [C]: https://www.cisco.com/c/en/us/support/docs/ip/network-time-protocol-ntp/116161-technote-ntp-00.html

## 14. Port-channel / uplink health
Commands: `show etherchannel summary` (flags: P bundled, s suspended, D down, I stand-alone, H hot-standby, w waiting, U in use, f failed), `show etherchannel detail | include ...`, `show lacp neighbor`, `show lacp counters` ; NX `show port-channel summary`, `show lacp neighbor`, `show vpc` (above).
Healthy: all expected members flagged (P), group (SU).
Findings: member (s) suspended or (I) stand-alone (High: bundle partially down, typically LACP/mode mismatch; or STP/vPC consistency); group (SD) down (High/Critical on uplink); fewer members than design (Medium; compare to description/inventory); LACP PDUs not received; `%EC-5-CANNOT_BUNDLE2` / `%EC-5-L3DONTBNDL1`/`%PM-4-ERR_DISABLE` logs.
False positives: intentionally unused members in `D`; mode "on" (static) port-channels do not show LACP; NX min-links settings.
Source: S11, S3; operational reason: bundles degrade silently while the logical link stays up.

## 15. TCAM / hardware resource exhaustion
Commands: XE Cat9k `show platform hardware fed switch active fwd-asic resource tcam utilization`, `show platform resources`, `show sdm prefer` (template), `show platform software fed switch active ... ` skip deeper; older Cat3k/2k `show platform tcam utilization`, `show platform hardware tcam utilization` ; ISR/ASR `show platform hardware qfp active infrastructure exmem statistics`, `show platform hardware qfp active resource` (limited); NX `show hardware capacity forwarding`, `show hardware capacity interface`, `show hardware capacity module`, `show system internal ... ` not read-only-safe to guess; `show tcam resource` n/a, use `show hardware access-list resource utilization`; `show ip route summary`, `show mac address-table count`, `show ip arp summary`.
Healthy: each TCAM/resource region used <70-80%.
Findings: >90% used (High), 100% (Critical; look for %PLATFORM-3-ELEMENT / "TCAM full" / `%FED_L3_ES-3-...` / "ACL could not be programmed" logs); MAC table near limit; route/ARP count near hardware limit; SDM template wrong for role (Medium).
False positives: TCAM regions (e.g. unused PBR, NetFlow) reserved by SDM template; reported "used" for static carve-outs; format differs per release.
Source: S3 [V] (Cat9k hardware resources); S11; Cisco Cat9k SDM docs [C].
Not supported: IOL/IOSv none; Cat9k commands use `fed switch active` (stack aware); ISR/ASR do not have switch TCAM; NX per-line-card capacity varies.

## 16. Unsaved config, config sanity
Commands: XE/IOS `show running-config | include Last configuration change|NVRAM config last updated`, `show archive config differences nvram:startup-config system:running-config` (can be heavy) , or `show startup-config | include Last` ; NX `show running-config diff` (read-only) and `show startup-config | include Time`; ASA `show running-config | include Cryptochecksum`, `write` is NOT read-only (never run). Prefer comparing the two "last change" timestamps.
Finding: running config newer than startup config (Medium: lost on reload; Info if change window active).
False positives: IOS-XE prints "NVRAM config last updated" even if only timestamps differ; some platforms (virtual) store config oddly; checking `show running-config` is read-only but large.
Source: operational reason; skill shall not run `write`/`copy`.

## 17. Log rate and noise
Commands: `show logging | include %`, `show logging | count %` (XE/IOS/NX; `| count` supported), `show logging summary`/ `show logging` header (counters: messages logged, severities); ASA `show logging` / `show logging queue`.
Finding: dominant message repeating >N per hour (e.g. >100/hour a single mnemonic) (Medium: flapping, loop, MAC flapping `%SW_MATM-4-MACFLAP_NOTIF`, `%ARP-4`, ACL log); logging buffer full of one message hides other events.
Noise to ignore: %SYS-5-CONFIG_I, %SYS-6-LOGGINGHOST_STARTSTOP, %LINK-3-UPDOWN of user ports, %SEC_LOGIN-5/6 successful logins, %PARSER-5-CFGLOG_LOGGEDCMD (command accounting).
Source: S11; operational reason.

## 18. Misconfigurations with health impact (log patterns)
- Duplex mismatch: `%CDP-4-DUPLEX_MISMATCH: duplex mismatch discovered on <int> (half duplex), with <peer> <int> (full duplex)`; confirm by late collisions on the half side and FCS/runts on the full side; `show interfaces status` shows "a-half" / "half" on a port that should be full (High). Source: S8 fallback link (10561-3).
- Native VLAN mismatch: `%CDP-4-NATIVE_VLAN_MISMATCH: Native VLAN mismatch discovered on <int> (X), with <peer> <int> (Y)` and STP `%SPANTREE-2-RECV_PVID_ERR` / `%SPANTREE-2-PVSTP_INCONSISTENCY` (Medium-High; traffic leaks and STP-inconsistent block). Check `show interfaces trunk`.
- MTU mismatch: OSPF stuck EXSTART/EXCHANGE; `%OSPF-4-ERRRCV: ... mtu` ; `show interfaces | include MTU`; `show ip interface | include MTU`; also `%CDP-...`; Jumbo drops as giants (Medium-High).
- Trunk allowed-VLAN mismatch / VLAN not in database; `%SW_MATM-4-MACFLAP_NOTIF` (MAC flapping, loop symptom, High); `%PM-4-BAD_VLAN_...`.
- UDLD: `%UDLD-4-UDLD_LINK_RESET` / err-disabled by UDLD (High).
- Missing NTP, no syslog destination, no SNMP/AAA logging: config checks; severity Low-Medium.
- Management: `ip domain-lookup` without DNS (CLI delays; Info), no `service timestamps log datetime msec` (logs lack time; Low), default STP priority; no BPDU guard on edge (Low).
- Native debug or `logging console` debug level left on (Medium: CPU), `debug` active: `show debugging` (should be empty; Medium if not).
- Mgmt interface counters: NX `mgmt0` errors.
Source: S8, S9 principle; log message names are in Cisco System Message Guides [C]: https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-17/products-system-message-guides-list.html

## 19. ASA specifics
Commands: `show failover` (This host: Primary/Secondary - Active/Standby Ready; Other host: Standby Ready/Active; Interface monitoring state; Stateful Failover Logical Update Statistics: failures), `show failover history` (S6), `show failover state`, `show conn count` and `show conn` summaries (S5/S7), `show resource usage` (current/peak/limit/Denied columns; `show resource usage resource conns`, `show resource rate`), `show cpu usage`, `show memory`, `show blocks`, `show interface ip brief`, `show xlate count`, `show vpn-sessiondb summary`, `show asp drop` (accelerated security path drop reasons, counters since boot/clear), `show ntp status`, `show license` (capacity/feature limits, expired), `show crashinfo`.
Healthy: Active/Standby Ready, same software version, config sync "Normal", no "Failed" monitored interfaces, stateful link failures 0; conns well below platform limit; resource "Denied" = 0.
Findings: This host or Other host "Failed"/"Disabled"/"Standby Failed"/"Cold Standby" (High-Critical); "Not Detected" for other host (Critical); failover history shows recent state change (Medium-High); monitored interface "Failed" (High); stateful link errors rising (Medium); `show resource usage` Denied > 0 (High: limit hit, e.g. conns, xlates, hosts, ASDM); `show conn count` current >80% of max (Medium) or >90% (High), peak near max (Medium); xlate exhaustion; license expired/platform limit; asp-drop counters like `tcp-not-syn`, `acl-drop`, `no-route`, `invalid-ip-header` growing: informational unless unexpected; block `low-water mark` near 0 (High).
False positives: standby unit's conn count mirrors active (stateful) and must not be summed; ASP drops for `acl-drop` and `tcp-not-syn` are normal in firewall use; `show resource usage` "Denied" value may be historical since last clear (check "Context"); in multiple-context mode run per context (`changeto context` is not read-only-risky but changes session context; use `show resource usage context all`).
Not supported: ASAv has no `show environment`; multi-context needs `changeto system`; FTD is a different CLI (`show failover` works via `system support diagnostic-cli`); ASA `terminal pager 0` equivalent to `terminal length 0`.
Source: S5 [V], S6 [V tier 3], S7 [V tier 3].

## 20. Graceful degradation matrix
| Check | IOL/IOSv (virtual IOS) | Cat9k XE | ISR/ASR/Cat8k | NX-OS 9k (hardware) | NX-OSv 9000v | ASA / ASAv |
|---|---|---|---|---|---|---|
| show environment | empty / unsupported | yes | yes | yes | partial/none | ASA yes, ASAv no |
| transceiver DOM | none | yes | yes (SFP ports) | yes | none | limited |
| show platform resources | no | yes | yes | no (use show system resources) | no | no |
| show processes cpu platform | no | yes | yes | no | no | no (show processes cpu-usage) |
| show switch / stack | no | yes (stackable models) | no | no | no | no |
| show redundancy | usually "not supported" | yes (dual-sup only meaningful) | yes (ASR dual RP) | `show system redundancy status` | limited | failover instead |
| show vpc | n/a | n/a | n/a | yes | yes | n/a |
| TCAM util | no | yes | no (QFP) | `show hardware capacity ...` | none | no |
| crashinfo/cores | no | yes | yes | `show cores` | `show cores` | `show crashinfo` |
Rule for the skill: when a command returns "% Invalid input", "% Incomplete command", "not supported", "feature not enabled" or empty, record the check as `SKIPPED (not supported on <platform>)`, not a pass and not a fail; also never infer health from an empty result of a feature that is not enabled (e.g. `show vpc` -> "feature vpc not enabled" means n/a).

## 21. Severity convention used above
Critical = outage or redundancy gone on sole path (peer-link down, sole PSU fail, TCAM full, active/standby both failed). High = degraded redundancy or active fault (err-disabled uplink, CRC on uplink, BGP down, STP inconsistency). Medium = trend or hygiene issue likely to bite (NTP unsync, TCNs, unsaved config). Low/Info = hygiene or context. Always attach evidence line (the raw output line) and platform/command so the engineer can verify.
