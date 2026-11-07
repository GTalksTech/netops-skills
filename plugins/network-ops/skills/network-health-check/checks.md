# Health checks

Run every check on every device in scope, in this order. The order is the order a senior engineer
reads a network: is it up, is the hardware sound, is redundancy intact, is routing stable, are the
links clean, then the slower problems. Each check says what healthy looks like, when it is a
finding and how bad, and the fix to suggest. Which file answers each check on each vendor is in
`vendors.md`.

File names are the command with spaces as dashes: `show ip ospf neighbor` →
`show-ip-ospf-neighbor.txt`. **H** = this run's health folder (`.snapshot/health/<site>/<device>/`),
**P** = the previous health run (`.snapshot/health-prev/...`, from the report's `previous`),
**S** = the committed snapshot folder (`<site>/<device>/`).

Thresholds are defaults. If the workspace instructions set others, use those.

## Severity

- **Critical**: traffic is down or one failure from down. Device unreachable, routing adjacency
  down, internet link down, the only uplink down, both members of a pair failed, PSU failed on a
  device with only one, a hardware alarm the device itself calls major/critical.
- **High**: redundancy lost or a fault that is growing. A redundant link or member down, HA/stack
  /vPC/MLAG degraded, FHRP wrong, STP inconsistent or topology changing now, crash or unplanned
  reboot, errors growing on an uplink, ≥ 90% load, CPU or memory.
- **Medium**: degraded, not urgent. Errors growing on an access port, optic at a warning
  threshold, NTP unsynced, adjacency that flapped in the last 24 h but is up now.
- **Low**: worth a look. Unsaved config, debug left on, a single old crash file.

Within a level: closest to the core or the internet first.

## Rules for every check

- **Counters are totals since the last clear or reboot.** A non-zero error counter is history,
  not a fault. A finding needs one of: the counter grew between P and H (say how much in how many
  minutes), or no P exists and the total is above the ratio in the check. When P is missing say
  "first run, totals only; run again to see growth".
- **Rejected is not healthy.** A command in the report's `rejected` (or `unsupported_commands`)
  list was refused: the platform lacks it, or the account is not allowed to run it. The device
  prints the same error for both, so say "rejected (not supported, or not permitted for this
  account)". Empty output, `(no output)`, or a feature that is not enabled is also not data. All
  of these go under Not checked, grouped by vendor, never one line per device. But a list
  command that ran and printed only headers or nothing (`show interfaces status err-disabled`,
  `show spanning-tree inconsistentports`) is data: it means none.
  A file vendors.md names that is neither in the health folder nor rejected was not collected
  (older profile or a custom one): Not checked, "not collected".
- **Virtual platforms** (IOL, IOSv, CSR/Cat8kv, vEOS/cEOS, vJunos/vMX/vSRX, NX-OSv, FortiGate-VM,
  ASAv, VM-Series) have no fans, PSUs, temperature or optics. Say "hardware: not applicable
  (virtual)" once for those devices; never a finding.
- **Change in progress.** Log lines within a minute of a config change (`%SYS-5-CONFIG_I`, Junos
  `UI_COMMIT`, a FortiGate config log) are a change being made. Name who changed what in Healthy.
  The same change also explains route-count moves, interface up/down and FHRP state changes in
  that minute: one Healthy line ("Change in progress: <who> <what> <when>"), no findings.
- **Growth beats the per-counter rules.** When P exists, a counter that did not grow is never a
  finding, whatever the check says about its total (collisions included). Put the totals in
  Healthy so the next run can compare.
- **Only this run's devices.** Check the devices in the report's `health` and `devices_ok`. For a
  device outside the run, use its committed snapshot files only, with their age (SKILL.md, Scoped
  runs).
- **Device time for log windows.** Log lines carry the device's clock; read windows against its
  `show clock` (or equivalent), not the run time, and say so if they differ by more than a minute.
- **Sources disagree.** Snapshot and health commands run seconds apart. When two outputs disagree
  (one says the link is down, another up), report the worse state, quote both, and say "changing
  during the run: re-run to confirm".
- **One cause, one finding.** An uplink down, the OSPF neighbor gone over it and the port-channel
  member down are one finding with all the evidence, at the worst severity.

---

## 1. Reachable
- Finding: device in the report's `failures`. **Critical.**
- Fix, by error: timeout / no route → management reachability, then is the device up (console);
  authentication → the stored password (`--set-credential`); missing profile → the inventory's
  `device_type`. A device that failed gets no other checks: Not checked, "unreachable".
- A device in `command_errors` was reached but some commands timed out or broke: list them under
  Not checked with the error. If more than half failed, say the device was only partly checked.

## 2. Hardware alarms, power, fans, temperature
The device's own alarm logic is the authority. Report its state words; do not invent thresholds.
- Finding: any active alarm the device lists (Junos `show chassis alarms` / `show system alarms`,
  Huawei `display alarm active`, Nokia `show system alarms`, Dell `show alarms`): **Critical** for
  major/critical, **Medium** for minor. A PSU not OK/Good/Normal: **High**, **Critical** if it was
  the only PSU (count installed PSUs). A fan not OK: **High**. A temperature sensor at
  warning/minor: **Medium**, at critical/major or shutdown: **Critical**. A line card or module
  not ok/online/active/standby: **High**.
- Alarms about configuration, not hardware (Junos "Rescue configuration is not set", licence
  reminders): **Low**.
- Not a finding: an empty PSU bay on a model that ships with one PSU; "Not present" fan trays on
  fanless models; sensors reading N/A.
- Fix: replace the failed unit; for temperature check the room, airflow direction and fan state
  first.

## 3. Redundancy state: HA pairs, stacks, vPC / MLAG / VSX / VLT, supervisors
Only when the feature is in use (configured, or the snapshot shows it).
- Firewall HA (FortiGate `get system ha status`, PAN-OS `show high-availability all`, ASA
  `show failover`): healthy is one active, one passive/standby that is in sync. Peer missing,
  out of sync, or a failover in the last 24 h: **High**. Standalone by design: say so.
- Stacks and virtual chassis (Cisco `show switch detail`, Junos `show virtual-chassis`, Huawei
  `display stack`, EXOS `show stacking`, ArubaOS-Switch `show vsf`): every member Ready/Prsnt,
  one master/active, a standby; stack ring closed (both stack ports up). Member missing or not
  ready, no standby, ring open: **High**.
- vPC / MLAG / VSX / VLT (`show vpc`, `show mlag detail`, `show vsx status`, `show vlt all`):
  peer adjacency up, peer-link up, keepalive alive, consistency success. Peer link down or peer
  not formed: **Critical**. Keepalive down, Type-1 / config-sanity inconsistency: **High**.
  Type-2 inconsistency: **Medium**. Within delay-restore after a reload (uptime < 5 min): say so,
  no finding.
- Supervisor / route processor redundancy (`show redundancy`, NX-OS `show module`, Junos
  `show chassis routing-engine`): standby not STANDBY HOT / not ready: **High**. A switchover in
  the last 24 h: **High**, quote the reason. Simplex on a single-supervisor chassis: not a finding.
- Fix: from the state the device prints (peer-link members, keepalive path, version mismatch).

## 4. Recent reboots and crashes
- Finding: device in `reboots` (uptime went down since the last snapshot), or in
  `up_less_than_24h`. **High.** Quote uptime and the reload reason (`show version` Last reload
  reason, NX-OS `show system reset-reason`, Arista `show reload cause`, Huawei
  `display reboot-info`, AOS-CX `show boot-history`).
- Reason is a crash, watchdog, kernel panic, power loss or "error" and it belongs to the current
  boot (its reload time is about now minus uptime): **High**, even if that was more than 24 h ago.
  A reload record older than the current boot is history: **Low**, one line. Core or crash files dated in the last 30 days
  (`show cores`, `show system core-dumps`, ASA `show crashinfo`): **High**; older ones: **Low**.
- Reason is a planned reload (`Reload Command`, `reload`, user) inside a known change window:
  **Low**, say so.
- Fix: read the logs (check 14) and the crash file; open a vendor case with them for a crash.

## 5. Routing adjacencies and route stability
Expected neighbors: every neighbor in the previous commit's neighbor file, plus every non-passive
routing interface with an inventory device on the other end.
- OSPF / IS-IS: an expected neighbor missing or not FULL/Up: **Critical**. `2WAY/DROTHER`
  between two DROTHERs on a broadcast segment is normal. Stuck `EXSTART`/`EXCHANGE` → MTU
  mismatch; `INIT` → one-way hellos (ACL, area, timer or subnet mismatch).
- BGP: a configured neighbor whose state/PfxRcd column is a state word (`Idle`, `Active`,
  `Connect`, `OpenSent`) rather than a prefix count: **Critical**. `Idle (Admin)` / admin
  shutdown that is in the config: not a finding, note it. Established with 0 prefixes received
  where P or the previous snapshot had some: **High**. Max-prefix reached: **High**.
- EIGRP: neighbor missing, or Q Cnt non-zero and not draining, or SIA in the logs: **High**.
- **Flaps**: adjacency uptime (OSPF detail "up for", BGP Up/Down, EIGRP Uptime) shorter than
  the device uptime and under 24 h: **Medium**, the neighbor reset recently; under 1 h, or BGP
  "connections established" / "dropped" counters grew between P and H: **High**. Quote the last
  reset reason (BGP `Last reset`, hold timer expired = underlay loss).
- IP SLA / tracked objects (`show ip sla statistics`, `show track`): a probe whose latest return
  code is not OK: **High** if it drives a route or FHRP track, else **Medium**.
- Route table: a missing default route on a device that had one in the previous commit:
  **High**. Total routes changed by more than 10% against the previous commit: **Medium**, name
  the protocol that moved.
- Fix: follows from the state; check the link (check 7) and the far end's snapshot.

## 6. First-hop redundancy (HSRP / VRRP) and the spanning-tree root
For each group across the switches that run it:
- Healthy: exactly one Active/Master and one Standby/Backup; the Active is the switch the config
  intends (higher priority with preempt; equal priority → higher interface IP); that switch is
  also the spanning-tree root for the same VLAN.
- **High**: no Active, or two (split brain); no Standby (redundancy lost); Active on the wrong
  switch; Active and STP root on different switches (traffic crosses the inter-switch link while
  the access uplink that should forward is blocked). A state change in the last hour, or
  repeated state-change logs: **High** (flapping).
- STP root per VLAN: in `show spanning-tree root` the root's own line has no Root Port and cost 0.
  If no in-scope switch is root, name the root's MAC and which device it is if a snapshot shows it.
- Fix: put STP root and FHRP Active on the same switch per VLAN (raise priority on the intended
  one, through a change); Standby missing → the peer's SVI and the link between them.

## 7. Interfaces that should be up but are down, and err-disabled ports
An interface **should be up** when it is admin up AND any of: it has a description, it is a trunk,
it is routed with an IP, it is a port-channel or member, or the snapshot shows a CDP/LLDP neighbor
on it (look in the previous commit if the neighbor is gone now).
Access ports with no description and no neighbor that are down are unused: ignore them.
- Finding: should-be-up and oper down. **Critical** if it is the only uplink or the internet
  link, **High** for other uplinks, routed links and tunnels, **Medium** otherwise.
- err-disabled (or the vendor equivalent: Arista errdisabled, AOS-CX / ArubaOS-Switch
  loop-protect or port-access blocked, Huawei `error-down`): always a finding, **High** on an
  uplink, **Medium** on an access port. Quote the reason (bpduguard, psecure, link-flap, udld,
  loopback, storm-control), because each has a different fix.
- Fix: check the far end (its snapshot), the cable and optic, then `shutdown`/`no shutdown`
  through a change. For err-disabled: clear the cause first; the reason names it.

## 8. Port-channels and LAGs
- Finding: a port-channel that is not up, or a member not bundled (Cisco not `(P)`: `(D)` down,
  `(s)` suspended, `(I)` stand-alone, `(H)` hot-standby when not intended; others: member
  not collecting/distributing, LACP not in sync). **High.** Port-channel itself down: **Critical**
  if it is the only uplink. Fewer members up than configured: **High**.
- Fix: the member's link (check 7), then LACP mode on both ends; speed, duplex and VLANs must
  match or the member suspends.

## 9. Interface errors and discards
On up interfaces only. Use P vs H growth (see the counter rule).
- CRC / FCS, input errors, runts, frame, alignment, symbol errors **growing**: **High** on uplinks
  and the internet link, **Medium** on access ports. With no P: total above 0.01% of input packets
  since `Last clearing of counters` is **Medium**, else history (put the totals in Healthy so the
  next run can compare).
- Late collisions, or any collisions on a full-duplex port: duplex mismatch, **High** (on real
  hardware). On a virtual lab node (IOL `%AMDP2_FE-6-EXCESSCOLL` and similar) it is the emulated
  NIC: say so and suggest adding it to the known exceptions.
- Giants: only a finding if the interface MTU is 1500 (jumbo traffic on a jumbo link is normal).
- Output drops / discards growing by more than 0.1% of output packets between P and H: **Medium**
  (congestion or microbursts); **High** with load ≥ 80% (check 10). Input queue drops, overruns,
  ignored, no buffer growing: **Medium**.
- Interface resets or carrier transitions growing: **Medium**, it is flapping (check 11).
- Fix: CRC → cable, optic or dirty fibre first, then the far end's optic (check 13 for light
  levels); duplex → hard-set or auto on both ends, never one of each; drops → load, QoS, buffers.

## 10. Uplinks and the internet link near capacity
Uplinks: trunks and routed links to other inventory devices, port-channels, tunnels, and the
edge's link toward the ISP.
- Finding: input or output rate ≥ 80% of the interface bandwidth over the device's load interval
  (Cisco 5-minute rate vs `BW`, or txload/rxload ≥ 204/255). **High** at ≥ 90%, else **Medium**.
  One reading is one moment: say "at <time>" and never call it a trend.
- Port-channel members carrying very uneven load (one > 2× another): **Low**, the hash.
- Fix: top talkers (NetFlow, the firewall's sessions), add capacity or a member, QoS at the edge.

## 11. Link flaps
- Finding: an interface with 3 or more down/up events in the logs within an hour, or still
  flapping (events in the last 15 minutes): **High** on an uplink, **Medium** on an access port to
  infrastructure (AP, phone switch). Interface `Last flapped` / `Last link flapped` under 1 h on
  an uplink: **Medium**.
- Not a finding: user access ports (PCs and phones come and go), and an interface brought up
  or down by a logged config change.
- Fix: the cable and optic (check 9 and 13), the far end's logs; UDLD or link-flap err-disable
  stops a bad link taking the network with it.

## 12. Spanning tree: inconsistent ports and topology changes
- Inconsistent ports (root, loop, PVID, type): any > 0. **High.**
- Topology changes: the last change was under 1 hour ago, or the count grew between P and H:
  **High**, name the port it came from (`from <interface>` in the detail output); 1 to 24 h ago:
  **Low**, note it. A TCN source on an access port means that port lacks portfast/edge.
- Blocked ports are normal on redundant uplinks. **Never** report blocked ports, their count, or
  a change in their count as a finding. A blocked port is a finding only when it is the switch's
  only path (that switch has no forwarding uplink left: say which).
- Fix: root inconsistent → root guard sees a better bridge, find who sends it; loop inconsistent
  → unidirectional link; type/PVID → native VLAN or trunk mismatch (also logged as
  `%CDP-4-NATIVE_VLAN_MISMATCH`); repeated TCNs → portfast/edge on the access port named.

## 13. Optics (transceiver light levels)
Report against the optic's own thresholds; the transceiver ships them, and the output prints them
or flags the value (`++`/`--` high/low alarm, `+`/`-` warning, Junos `alarm`/`warning` lines).
- Finding: Rx or Tx power, temperature, voltage or bias at a warning threshold: **Medium**; at an
  alarm threshold: **High**. Rx low on a link that also has growing CRC: **High**, one finding.
- Output with readings but no thresholds or flags cannot be judged: Not checked, never a guess.
- Not a finding: copper, DAC and non-DOM optics (N/A); no light on a port that is down and not
  should-be-up (check 7).
- Fix: clean the fibre both ends, check patch loss, replace the optic.

## 14. CPU, memory and resource exhaustion
- CPU 5-minute (or the vendor's longest average) ≥ 80%: **Medium**, ≥ 90%: **High**. Name the top
  process. Cisco interrupt CPU (after the `/`) above 30%: **High**, traffic punted to the CPU
  (loop, ARP storm, glean).
- Memory used ≥ 85%: **Medium**, ≥ 90%: **High**. IOS-XE `show platform resources` state not
  Healthy: **High**. FortiGate conserve mode or memory above its red threshold: **Critical**
  (it stops inspecting new sessions). Allocation failures in the logs (`%SYS-2-MALLOCFAIL`):
  **Critical**.
- Firewall session table ≥ 80% of the platform limit, ASA `show resource usage` Denied > 0, ASA
  `show blocks` low count 0: **High**. Disk or storage ≥ 90% (Junos `show system storage`, PAN-OS
  `show system disk-space`): **Medium**; logs stop being written when full.
- Fix: the top process names the cause (routing churn, a loop, logging to console, SNMP polls);
  memory → compare with the previous report for a leak.

## 15. Errors in the logs
Read the log from the previous health report's time, or the last 24 hours if there is none.
- Report messages at severity 0 to 3 (Cisco `%FAC-0-` … `%FAC-3-`, Junos/Arista/Huawei error and
  above, FortiGate/PAN-OS critical/high system events), and these at any severity: routing
  adjacency down (`%OSPF-5-ADJCHG ... to DOWN`, `%BGP-5-ADJCHANGE ... Down`, `%DUAL-5-NBRCHANGE`),
  FHRP state changes, `%SPANTREE-2-`, `%SW_MATM-4-MACFLAP_NOTIF` (MAC flapping, a loop symptom,
  **High**), `%CDP-4-DUPLEX_MISMATCH` and `%CDP-4-NATIVE_VLAN_MISMATCH` (**High**: misconfiguration
  causing faults now), `%PM-4-ERR_DISABLE`, `%UDLD-`, `%EC-5-CANNOT_BUNDLE`, power, fan and
  temperature messages. Default **Medium**; by what the message says.
- Group by message: one line per kind with count, first and last time, and one quoted line.
  One message repeating > 100 times is its own finding: it hides everything else in the buffer.
- Not faults on their own: an interface coming up, successful logins, `%SYS-5-CONFIG_I`, command
  accounting, and severity 3 lines within a minute after a config change.
- Leave out documented known exceptions (lab v2: `%CRYPTO-0-SELF_TEST_FAILURE ... Bypassed` at
  boot) and list them under Known exceptions.
- If the buffer starts after the window (rolled over) say so: "logs only cover since <time>".

## 16. Time (NTP)
- Finding: clock not synchronized, no peer selected (`*` / sys.peer), or stratum 16: **Medium**
  (log times, certificates, VPN and AAA all depend on it). Reach not 377 on the selected server:
  **Low**. Clock more than 1 s off the other devices (`show clock` vs the run time): **Low**.
- Not a finding: a device booted less than 20 minutes ago (IOS takes about 15 minutes to sync).
- Fix: reachability of the server from the device's source interface or VRF, ACLs, `ntp server`
  config. A device pointing at its own address never syncs.

## 17. Hygiene that causes faults later
- Running config not saved: Cisco `show running-config view full` differs from
  `show startup-config` beyond timestamps; Huawei current vs saved; Arista/NX-OS/Dell the same
  way; Junos uncommitted changes. Not a finding when the config changed in the last 30 minutes
  (a change still being worked): say so in Healthy. Otherwise **Low**, **Medium** if the device rebooted unexpectedly before
  (the change will be lost on the next one).
- Debugging left on (`show debugging` lists anything): **Medium**, it loads the CPU.
- Logging buffer disabled or tiny (fewer than an hour of messages): **Low**, the next incident
  will have no evidence.
- Fix: save through the change process; `undebug all` through a change.
