# Where each check reads, per vendor

The `device_type` in the inventory picks the row set. **H** = health folder, **S** = snapshot
folder (names as in checks.md). A command missing here, or in the run's `rejected` list, means
the check is Not checked for that device. Profiles marked `untested` in network-snapshot's
`platforms/` were written from vendor docs: if output does not look like the check expects, say so
in Not checked and suggest the profile fix, never guess a value.

## cisco_ios (IOS, IOS-XE, IOL)  · tested
| Check | Files |
|---|---|
| 2 Hardware | H `show-environment-all`, `show-power-inline`; S `show-inventory`, `show-module` |
| 3 Redundancy | S `show-switch-detail`, `show-redundancy` |
| 4 Reboots | report (`uptime_s`, `reboots`); S `show-version` (Last reload reason; IOL says Unknown reason) |
| 5 Routing | S `show-ip-ospf-neighbor`, `show-ip-ospf-interface-brief`, `show-ip-bgp-summary`, `show-ip-eigrp-neighbors`, `show-ip-route`; H `show-ip-ospf-neighbor-detail` (up for), `show-ip-bgp-neighbors` (Last reset, established/dropped), `show-ip-eigrp-neighbors-detail`, `show-ip-route-summary`, `show-ip-sla-statistics`; tunnels H `show-crypto-session` |
| 6 FHRP + root | S `show-standby-brief`, `show-vrrp-brief`, `show-spanning-tree-root`, running config; H `show-standby` |
| 7 Down / err-disabled | S `show-ip-interface-brief`, `show-interfaces-status`, `show-interfaces-description`, `show-interfaces-trunk`, `show-cdp-neighbors-detail`, `show-lldp-neighbors-detail`; H `show-interfaces-status-err-disabled` |
| 8 Port-channels | S `show-etherchannel-summary` |
| 9 Errors / 10 Load / 11 Flaps | H `show-interfaces` (CRC, input errors, collisions, output drops, rates, BW, txload/rxload, Last clearing), `show-interfaces-counters-errors`; H `show-logging` for UPDOWN |
| 12 STP | H `show-spanning-tree-inconsistentports`, `show-spanning-tree-detail` (topology changes, last change, from), `show-spanning-tree-blockedports`; S `show-spanning-tree-summary` |
| 13 Optics | H `show-interfaces-transceiver-detail` |
| 14 CPU / memory | H `show-processes-cpu-sorted-5min` (`five minutes: N%`, `five seconds: X%/Y%`), `show-memory-statistics`, `show-platform-resources`, `show-platform-software-status-control-processor-brief` |
| 15 Logs | H `show-logging` |
| 16 NTP | H `show-ntp-status`, `show-ntp-associations`, `show-clock` |
| 17 Hygiene | S `show-running-config-view-full` vs `show-startup-config`; H `show-debugging` |

A privilege-limited account (lab v2 `claude-ro`, level 5) gets "% Invalid input" for every
command not lowered to its level: the same text as a missing command.

## fortinet (FortiGate)  · tested
| Check | Files |
|---|---|
| 2 Hardware | S `get-hardware-status`, `get-system-status` (VM model → virtual) |
| 3 Redundancy | S `get-system-ha-status` (mode standalone = by design) |
| 5 Routing | S `get-router-info-ospf-neighbor`, `get-router-info-bgp-summary`, `get-router-info-bgp-neighbors`, `get-router-info-routing-table-all` |
| 7 Down | S `get-system-interface-physical` (`status: down`), `show` for `set status down` |
| 14 CPU / memory / sessions | H `get-system-performance-status` (CPU states, Memory, Uptime), `get-hardware-memory`, `get-system-session-info-statistics`, `get-system-performance-firewall-statistics` |
| VPN tunnels | H `get-vpn-ipsec-tunnel-summary` (`selectors(total,up)`: up < total is **High**; a tunnel at 0 up is **Critical** if it is the only path to a site) |
| Licence / FortiGuard | S `get-system-fortiguard-service-status` (expired service: **Medium**) |
Not checked on FortiGate with the read-only profile: interface errors and load, NTP sync, logs,
conserve-mode thresholds. They need `diagnose` / `execute`, which the read-only rule refuses.

## cisco_nxos (Nexus)  · untested
2 H `show-environment`, `show-module` · 3 H `show-vpc` (peer status, keep-alive, consistency) · 4 H
`show-system-reset-reason`, `show-cores` · 5 S `show-ip-ospf-neighbors-vrf-all`, `show-bgp-all-summary`;
H `show-ip-ospf-neighbors-detail-vrf-all`, `show-bgp-sessions-vrf-all` · 6 H `show-hsrp-brief`,
`show-vrrp` · 7 S `show-interface-brief`; H `show-interface-status-err-disabled` · 8 S
`show-port-channel-summary` · 9/10/11 H `show-interface` (Last link flapped), `show-interface-counters-errors`
· 12 H `show-spanning-tree-detail`, `show-spanning-tree-inconsistentports` · 13 H
`show-interface-transceiver-details` · 14 H `show-system-resources` · 15 H `show-logging-logfile-last-index-500`
· 16 H `show-ntp-peer-status`, `show-ntp-status`

## arista_eos  · untested
2 H `show-system-environment-all` · 3 H `show-mlag-detail`, `show-mlag-config-sanity` · 4 H
`show-reload-cause`, `show-version-detail` · 5 S `show-ip-ospf-neighbor-vrf-all`,
`show-ip-bgp-summary-vrf-all`; H `show-ip-ospf-neighbor-detail-vrf-all`, `show-ip-bgp-neighbors-vrf-all`
· 6 H `show-vrrp-brief` · 7 S `show-interfaces-status`; H `show-interfaces-status-errdisabled` · 8 S
`show-port-channel-summary` · 9/10/11 H `show-interfaces`, `show-interfaces-counters-errors`,
`show-interfaces-counters-discards`, `show-interfaces-counters-rates` · 12 H `show-spanning-tree-detail`,
`show-spanning-tree-inconsistentports` · 13 H `show-interfaces-transceiver-detail` · 14 H `show-processes-top-once`
· 15 H `show-logging` · 16 H `show-ntp-status`, `show-ntp-associations`

## juniper_junos (MX, EX, QFX, SRX)  · untested
2 H `show-chassis-alarms`, `show-system-alarms`, `show-chassis-environment`, `show-chassis-fpc` · 3 H
`show-chassis-routing-engine`, `show-virtual-chassis`; S `show-chassis-cluster-status` (SRX) · 4 H
`show-system-core-dumps`; S `show-version` · 5 S `show-ospf-neighbor`, `show-bgp-summary`, `show-route-summary`;
H `show-ospf-neighbor-extensive`, `show-bgp-neighbor` · 6 H `show-vrrp-summary` · 7/9/10/11 S
`show-interfaces-terse`; H `show-interfaces-extensive` (errors, drops, Last flapped, rates) · 12 H
`show-spanning-tree-bridge` · 13 H `show-interfaces-diagnostics-optics` · 14 H `show-chassis-routing-engine`
(CPU idle, memory), `show-system-storage` · 15 H `show-log-messages-last-300` · 16 H `show-ntp-status`,
`show-ntp-associations` · 17 H `show-system-commit`

## aruba_aoscx  · untested
2 H `show-environment-fan`, `show-environment-power-supply`, `show-environment-temperature` · 3 H
`show-vsx-status` · 4 H `show-boot-history` · 5 S `show-ip-ospf-neighbors-all-vrfs`, `show-bgp-all-summary`
· 6 H `show-vrrp-brief` · 7 S `show-interface-brief` · 8 S `show-lacp-aggregates` · 9/10/11 H
`show-interface`, `show-interface-error-statistics` · 12 H `show-spanning-tree-detail` · 13 H
`show-interface-transceiver-detail` · 14 H `show-system-resource-utilization` · 15 H
`show-events-r-c-200` · 16 H `show-ntp-status`, `show-ntp-associations`

## hp_procurve (ArubaOS-Switch)  · untested
2 H `show-system-fans`, `show-system-power-supply`, `show-system-temperature` · 3 S `show-vsf` · 7 S
`show-interfaces-brief`; H `show-loop-protect`, `show-port-access-summary` · 8 S `show-trunks`, `show-lacp`
· 9 H `show-interfaces` · 12 H `show-spanning-tree-detail` · 13 H `show-interfaces-transceiver-detail` · 14 H
`show-cpu`; S `show-system` (memory) · PoE H `show-power-over-ethernet-brief` · 15 H `show-logging-r-m-p`
(major/warning only) · 16 H `show-sntp`

## huawei_vrp  · untested
2 H `display-alarm-active`, `display-health`, `display-power`, `display-fan`, `display-temperature-all`; S
`display-device` (Abnormal) · 3 H `display-stack` · 4 H `display-reboot-info` · 5 S `display-ospf-peer-brief`,
`display-bgp-peer`; H `display-ospf-peer`, `display-bgp-peer-verbose` · 6 S `display-vrrp-brief` · 7 S
`display-interface-brief` · 8 S `display-eth-trunk` · 9/10/11 H `display-interface` · 12 H
`display-stp-topology-change` · 13 H `display-transceiver-verbose` · 14 H `display-cpu-usage`,
`display-memory-usage` · 15 H `display-logbuffer` · 16 H `display-ntp-service-status` · 17 S
`display-current-configuration` vs `display-saved-configuration`

## extreme_exos  · untested
2 H `show-fans`, `show-power`, `show-temperature` · 3 H `show-stacking`, `show-mlag-peer` · 5 S
`show-ospf-neighbor`, `show-bgp-neighbor` · 6 S `show-vrrp` · 7 S `show-ports-no-refresh` · 8 S `show-sharing`
· 9 H `show-ports-rxerrors-no-refresh`, `show-ports-txerrors-no-refresh` · 10 H
`show-ports-utilization-no-refresh` · 12 H `show-stpd-detail` · 13 H `show-ports-transceiver-information-detail`
· 14 H `show-cpu-monitoring`, `show-memory` · 15 H `show-log` · 16 H `show-ntp-sys-info`

## dell_os10  · untested
2 H `show-alarms`, `show-environment` · 3 S `show-vlt-all`; H `show-vlt-all-mismatch` · 5 S
`show-ip-ospf-neighbor`, `show-ip-bgp-summary` · 6 H `show-vrrp-brief` · 7 S `show-interface-status` · 8 S
`show-port-channel-summary` · 9/10/11 H `show-interface` · 12 H `show-spanning-tree-details` · 13 H
`show-interface-transceiver-detail` · 14 H `show-processes-node-id-1`, `show-system` · 15 H
`show-logging-log-file` · 16 H `show-ntp-status`

## nokia_sros  · untested
2 H `show-system-alarms`, `show-chassis-environment`, `show-chassis-power-supply`; S `show-card-state` · 4 S
`show-system-information` · 5 S `show-router-ospf-neighbor`, `show-router-isis-adjacency`,
`show-router-bgp-summary`; H `show-router-ospf-neighbor-detail`, `show-router-bgp-neighbor` · 7 S `show-port`
· 8 S `show-lag` · 9/11 H `show-port-detail` · 14 H `show-system-cpu`, `show-system-memory-pools` · 15 H
`show-log-log-id-99` · 16 H `show-system-ntp`. No config file: `admin display-config` is not a read verb.

## cisco_asa  · untested
2 H `show-environment` · 3 H `show-failover`, `show-failover-history` · 4 H `show-crashinfo` · 5 S
`show-ospf-neighbor`, `show-bgp-summary` · 7/9 S `show-interface-ip-brief`; H `show-interface` · 14 H
`show-cpu-usage`, `show-memory`, `show-blocks`, `show-resource-usage` (Denied), `show-conn-count` · 15 H
`show-logging` · 16 H `show-ntp-status`, `show-ntp-associations`

## paloalto_panos  · untested
2 H `show-system-environmentals` · 3 H `show-high-availability-all` · 5 S
`show-routing-protocol-ospf-neighbor`, `show-routing-protocol-bgp-summary` · 7/9 H `show-interface-all` · 14 H
`show-system-resources`, `show-session-info` (num-active vs num-max), `show-system-disk-space`,
`show-counter-global-filter-severity-drop` · 15 H `show-log-system-direction-equal-backward` · 16 H `show-ntp`
