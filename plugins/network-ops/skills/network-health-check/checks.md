# Health checks

Run every check on every device in scope. Each check says what healthy looks like, when it is a
finding and how bad, where to look, and the fix to suggest. File names are the command with
spaces as dashes: `show ip ospf neighbor` → `show-ip-ospf-neighbor.txt`. **H** = health folder
(`.snapshot/health/<site>/<device>/`), **S** = snapshot folder (`<site>/<device>/`).

Thresholds are defaults. If the workspace instructions set others, use those.

Severity: **Critical** = traffic is down or about to be (device unreachable, routing adjacency
down, internet link down). **High** = redundancy lost or a fault that will grow (uplink or
port-channel member down, HSRP wrong, STP inconsistent, recent reboot, ≥90% load or CPU).
**Medium** = degraded, not urgent. **Low** = worth a look.

Snapshot-only vendors (`cisco_nxos`, `cisco_asa`, `arista_eos`, `juniper_junos`,
`aruba_aoscx`, `paloalto_panos`) have no health commands. Their checks use the S files listed
under each check; anything else is **Not checked: no health commands in the <vendor> profile**.

---

## 1. Reachable
- Finding: device in the report's `failures`. **Critical.**
- Evidence: the error from the report.
- Fix, by error: timeout / no route → check management reachability and that the device is up
  (console); authentication → password in the credential store (`--set-credential`); missing
  profile → inventory `device_type`. A device that failed gets no other checks: list it under
  Not checked as "unreachable".

## 2. Recent reboot
- Finding: device in `reboots` (uptime went down since the last snapshot), or in
  `up_less_than_24h`. **High.** Quote uptime and the reload reason.
- If the reload reason is a planned reload (`Reload Command`) inside a known change window,
  say so and drop to **Low**.
- Fix: read the logs (check 13) and crash info for the cause; confirm it was planned.

## 3. Interfaces that should be up but are down
An interface **should be up** when it is admin up (not `shutdown` / `administratively down`)
AND any of: it has a description, it is a trunk, it is routed with an IP, it is a port-channel
or port-channel member, or the snapshot shows a CDP/LLDP neighbor on it (look in the previous
commit if the neighbor is gone now: `git -C <repo> show HEAD~1:<site>/<device>/show-cdp-neighbors-detail.txt`).
Access ports with no description and no neighbor that are `notconnect` are unused: ignore them.
- Finding: should-be-up and oper down / notconnect. **High** for uplinks, routed links,
  tunnels and the internet link; **Medium** otherwise. `err-disabled` is always a finding
  (**High**), with the reason from `show interfaces status err-disabled`.
- Where: IOS S `show-ip-interface-brief.txt`, `show-interfaces-status.txt`,
  `show-interfaces-description.txt`, `show-interfaces-trunk.txt`, running config; H
  `show-interfaces-status-err-disabled.txt`. FortiGate S `get-system-interface-physical.txt`
  (`status: down`) + `show.txt` for `set status down`. NX-OS / Arista: S
  `show-interface-brief.txt` / `show-interfaces-status.txt`; Junos `show-interfaces-terse.txt`
  (admin up, link down); AOS-CX `show-interface-brief.txt`; ASA `show-interface-ip-brief.txt`;
  PAN-OS `show-interface-all.txt`.
- Fix: check the far end (its snapshot), cable/optic, then `shutdown`/`no shutdown` through a
  change. For err-disabled: clear the cause first (the reason names it).

## 4. Interface errors
- Finding: on an up interface, CRC, input errors, output errors, runts, giants, frame or
  late collisions **growing since the previous health report**, or totalling more than 0.01%
  of packets since counters were last cleared (`Last clearing of "show interface" counters`).
  **High** on uplinks and the internet link, **Medium** elsewhere. Input drops/queue drops
  alone: **Low** unless the link is also near capacity.
- Record the counter values per interface in the report evidence, so the next run can compare.
- Where: IOS H `show-interfaces.txt`, `show-interfaces-counters-errors.txt`. FortiGate: not
  in its health commands → Not checked (needs `diagnose hardware deviceinfo nic`, outside the
  read-only account). Snapshot-only vendors: Not checked.
- Fix: CRC/input errors → cable, optic, or duplex/speed mismatch (compare both ends); output
  errors / late collisions → duplex mismatch. Collisions on a port that shows `full` duplex
  can't happen on real hardware: on a virtual lab (IOL `%AMDP2_FE-6-EXCESSCOLL`) say it is
  most likely the emulated NIC and suggest adding it to the known exceptions.

## 5. Uplinks and the internet link near capacity
Uplinks: trunks and routed links to other inventory devices (CDP/LLDP neighbor, description),
port-channels, tunnels. Internet link: the edge router's / firewall's link toward the ISP.
- Finding: 5-minute input or output rate ≥ 80% of the interface bandwidth (`BW` in
  `show interfaces`), or `txload`/`rxload` ≥ 204/255. **High** at ≥ 90%, else **Medium**.
- Where: IOS H `show-interfaces.txt` (`5 minute input rate`, `BW`, `txload`, `rxload`).
  FortiGate: Not checked (no per-interface rate in its health commands). Snapshot-only: Not checked.
- Fix: find the top talker (NetFlow / the firewall's sessions), add capacity or a port-channel
  member, QoS on the internet link.

## 6. Port-channel members down
- Finding: a port-channel that is not up (`SU`/`RU`), or a member not bundled (not `(P)`:
  `(D)` down, `(s)` suspended, `(I)` stand-alone, `(H)` hot-standby when not intended).
  **High.** Port-channel itself down: **Critical** if it is the only uplink.
- Where: IOS S `show-etherchannel-summary.txt`. NX-OS / Arista S `show-port-channel-summary.txt`;
  AOS-CX S `show-lacp-aggregates.txt`. Others: no port-channel output → Not checked.
- Fix: check the member's link (check 3), then channel-group mode and LACP on both ends
  (speed/duplex/VLANs must match or the member suspends).

## 7. OSPF neighbors full
Expected neighbors: every OSPF neighbor in the previous commit's neighbor file, plus every
non-passive OSPF interface that has a neighbor device on the other end.
- Finding: an expected neighbor missing, or in any state other than `FULL`. **Critical.**
  Exception: `2WAY/DROTHER` between two DROTHER routers on a broadcast segment is normal.
- Where: IOS S `show-ip-ospf-neighbor.txt`, `show-ip-ospf-interface-brief.txt`, previous
  commit's neighbor file. FortiGate S `get-router-info-ospf-neighbor.txt`. NX-OS / Arista S
  `show-ip-ospf-neighbors-vrf-all.txt` / `show-ip-ospf-neighbor-vrf-all.txt`; Junos
  `show-ospf-neighbor.txt`; AOS-CX `show-ip-ospf-neighbors-all-vrfs.txt`; ASA
  `show-ospf-neighbor.txt`; PAN-OS `show-routing-protocol-ospf-neighbor.txt`.
- Fix, by state: missing → link down (check 3) or interface not in OSPF; stuck `EXSTART`/
  `EXCHANGE` → MTU mismatch; `INIT` → one-way hellos (ACL or area/timer/subnet mismatch).

## 8. BGP sessions established
- Finding: a configured neighbor whose State/PfxRcd column is a state word (`Idle`, `Active`,
  `Connect`, `OpenSent`, `Idle (Admin)`) rather than a prefix count. **Critical** (the internet
  edge). A neighbor that is Established but receiving 0 prefixes where the previous snapshot
  had some: **High**. `Idle (Admin)` that is intended (shut in config): not a finding, note it.
- Where: IOS S `show-ip-bgp-summary.txt`, H `show-ip-bgp-neighbors.txt` (last reset reason).
  FortiGate S `get-router-info-bgp-summary.txt`. NX-OS / AOS-CX S `show-bgp-all-summary.txt`;
  Arista `show-ip-bgp-summary-vrf-all.txt`; Junos / ASA `show-bgp-summary.txt`; PAN-OS
  `show-routing-protocol-bgp-summary.txt`.
- Fix: reachability of the neighbor address, then AS number / update-source / password / ACL;
  `show ip bgp neighbors` last reset reason says which.

## 9. HSRP active and standby where expected, on the STP root
For each HSRP group (per VLAN interface) across the switches that run it:
- Healthy: exactly one `Active` and one `Standby`; the Active is the switch the config intends
  (higher `standby <g> priority`, with `preempt`; equal priority → higher interface IP); and that
  switch is the spanning-tree root for the same VLAN.
- Findings (all **High**): no Active, or two (split brain); no Standby (redundancy lost); Active
  on the wrong switch; Active and STP root on different switches (traffic crosses the
  inter-switch link and the access uplink that should be forwarding is blocked).
- STP root per VLAN: in `show-spanning-tree-root.txt` the root bridge's own line has no Root Port
  (and cost 0). If no in-scope switch is root, name the root's MAC and which device it is if a
  snapshot shows it.
- Where: IOS S `show-standby-brief.txt`, `show-spanning-tree-root.txt`, running config
  (`standby` lines, `spanning-tree vlan <v> priority` / `root primary`); H `show-standby.txt`.
  VRRP the same way from `show-vrrp-brief.txt` if used. Other vendors: Not checked (no
  first-hop redundancy output in their profiles; NX-OS/Arista/AOS-CX vPC/MLAG/VSX state is in
  `show-vpc-brief.txt` / `show-mlag.txt` / `show-vsx-brief.txt`: report it if it is not up).
- Fix: put STP root and HSRP Active on the same switch per VLAN (raise priority on the intended
  one, through a change); Standby missing → check the peer's SVI and the link between them.

## 10. Spanning-tree inconsistent ports
- Finding: any port in `show spanning-tree inconsistentports` (root, loop, PVID or type
  inconsistent). **High.** Number of inconsistent ports > 0 is the test.
- Blocked ports are normal on redundant uplinks. **Never** report blocked ports, their count,
  or a change in their count as a finding. A blocked port is a finding only if it is on the
  only path to a switch (that switch has no forwarding uplink left: say which).
- Where: IOS H `show-spanning-tree-inconsistentports.txt`, `show-spanning-tree-blockedports.txt`,
  `show-spanning-tree-detail.txt`; S `show-spanning-tree-summary.txt`. Others: Not checked
  (summary only).
- Fix: root inconsistent → root guard is seeing a better bridge: find who is sending it; loop
  inconsistent → a unidirectional link: check the link; type/PVID → native VLAN or trunk mismatch
  between the two ends.

## 11. NTP synced
- Finding: `Clock is unsynchronized`, or no association marked `*` (sys.peer). **Medium.**
  Stratum 16 means unsynced. Clock off by more than a few seconds from the other devices
  (`show-clock.txt`): **Low**.
- Where: IOS H `show-ntp-status.txt`, `show-ntp-associations.txt`, `show-clock.txt`.
  FortiGate: Not checked (sync state is `diagnose sys ntp status`, outside the read-only
  account; `get-system-ntp.txt` shows only the configured servers). Others: Not checked.
- Fix: reachability of the NTP server from the device's source interface, ACLs, `ntp server`
  config.

## 12. CPU and memory
- Finding: CPU 5-minute ≥ 80% or memory used ≥ 85% of total. **High** at ≥ 90%, else
  **Medium**. Name the top process.
- Where: IOS H `show-processes-cpu-sorted-5min.txt` (`five minutes: N%`),
  `show-memory-statistics.txt` (Processor: Used/Total), `show-platform-resources.txt` on IOS-XE
  hardware. FortiGate H `get-system-performance-status.txt` (`CPU states`, `Memory`),
  `get-hardware-memory.txt`. Others: Not checked.
- Fix: the top process names the cause (routing churn, a loop, logging to console, SNMP polls);
  memory → check for a leak across reports.

## 13. Errors in the logs
- Finding: messages at severity 0–3 (`%FAC-0-` … `%FAC-3-`) since the previous health report,
  or in the last 24 hours if there is none. Also repeated `%LINK-3-UPDOWN` / `%LINEPROTO-5-UPDOWN`
  for the same interface (flapping, **High**), `%OSPF-5-ADJCHG` / `%BGP-5-ADJCHANGE` down events,
  `%SPANTREE-2-` and `%DUAL-` messages. Default **Medium**; by what the message says.
- Not faults on their own: `%LINK-3-UPDOWN ... changed state to up` (an interface coming up,
  e.g. a new SVI), and severity 3 lines that follow a `%SYS-5-CONFIG_I` by seconds (a change
  being made). Say who changed what in the Healthy line instead.
- Leave out documented known exceptions (lab v2: `%CRYPTO-0-SELF_TEST_FAILURE ... Bypassed` at
  boot) and list them under Known exceptions.
- Group by message: one finding per kind with count, first and last time, and one quoted line.
- Where: IOS H `show-logging.txt`. FortiGate: Not checked (logs need `execute log display`,
  outside the read-only account). Others: Not checked.
- Fix: follows from the message; link flaps → check 3 and 4 on that interface.
