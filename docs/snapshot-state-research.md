# network-snapshot: what one run must collect to build a source of truth

Research report, 2026-11-28. Research only: no repo file was edited. Scope: Cisco IOS / IOS-XE and
Fortinet FortiOS first. Lab evidence comes from read-only runs against lab v2 on 2026-11-28
(accounts `claude-ro` privilege 5 and `claude-ro-cli`); every probe was `show` (Cisco) or
`get`/`show` (FortiGate). Firecrawl was not used; built-in search and fetch were enough, except
that cisco.com command-reference chapters are too large for one fetch and block plain curl, so
some syntax was read from chapter tables of contents only (marked below).

Tags: [T1] vendor or official project documentation/source. [LAB] observed on lab v2 today.
[MEM] from my own knowledge, not re-verified today (treat as UNSOURCED until checked).

---

## 1. Verdict

1. Today's run is a good config-change differ, but only roughly half a source of truth: it captures config and the global-table L2/L3 control plane, and nothing about hosts.
2. Gap 1, hosts: no ARP, MAC table, IPv6 ND, DHCP lease/snooping or device-tracking data in the committed set on any platform (FortiGate ARP sits only in `--health`), so end hosts, unmanaged switches and silent links (the fw-01 case) cannot be found.
3. Gap 2, VRFs: every operational command is global-table only. [LAB] On hq-edge-rtr-01 `show ip route` misses the whole MGMT VRF (21 lines in `show ip route vrf MGMT`), and `show ip arp` misses its 4 MGMT ARP entries; `show ip arp vrf *` does not exist, so a VRF loop is required.
4. Gap 3, interface and link facts: interface MAC/MTU/speed (only in `--health`), secondary and IPv6 addresses, LACP/UDLD partners, BGP sessions in other address families or VRFs, FHRP GLBP, and FortiGate LLDP/managed-device/user-device data are missing.
5. All three close with CLI alone at privilege 5: 17 committed commands, about 20 default "state" commands and a per-VRF loop, with no new lab privilege lines; lab cost is about 0.5 s per command.

---

## 2. Pass 1, breadth: what "complete network state" means and how the best tools gather it

### 2.1 Reference collectors (what each one actually runs)

| Tool | How it collects | What it collects (IOS-XE / FortiOS) | Source |
|---|---|---|---|
| IP Fabric 7.8 (Cisco IOS-XE family) | CLI over SSH, model built from show output | Per task: ARP (`show ip arp`, `show ip arp vrf <vrf>`), MAC (`show mac address`), routing table per VRF (`show ip route vrf <vrf> [<protocol>]`, `show ip cef detail`), VRF (`show vrf detail`), STP (`show spanning-tree detail`, `show spanning-tree mst`), FHRP (`show standby`, `show vrrp`, `show glbp brief`), BGP neighbors and advertised routes per neighbor, OSPF/OSPFv3/EIGRP/IS-IS per VRF, DHCP server bindings, DHCP snooping, 802.1X (`show access-session`, `show authentication sessions`), IPsec SAs, DMVPN, VXLAN (`show nve vni`, `show nve peers`), PoE, transceivers, license (`show license all`), stacking, VSS/StackWise Virtual, multicast (PIM, mroute, IGMP, IGMP snooping), MPLS LDP/forwarding, port mirroring, policy-based routing, prefix lists, QoS, wireless controller and clients, UDLD, err-disabled. Initial discovery runs `show privileges`. | [T1] https://matrix.ipfabric.io/api/7.8.0/family/129976135/text |
| IP Fabric 7.5 (FortiGate family) | CLI | ARP `get system arp`; neighbors `diagnose user device list`; IPv6 ND `diagnose ipv6 neighbor-cache list`; routing `get router info routing-table all`; IPsec `diagnose vpn ike gateway list`, `diagnose vpn tunnel list`; FHRP `get router info vrrp`; SD-WAN `diagnose sys sdwan member`; transceivers `get system interface transceiver`; VDOMs `diagnose system vd list` after `config global`; policies/objects via `show firewall ...`. | [T1] https://matrix.ipfabric.io/api/7.5.0/family/100891664/markdown |
| SuzieQ | CLI, one YAML per table | IOS-XE: `show version`, `show interfaces`, `show ip interface`, `show ipv6 interface`, `show vrf detail`, `show ip route vrf *`, `show ipv6 route vrf *`, `show ip arp`, `show ipv6 neighbors`, `show mac address-table`, `show bgp all summary`, `show bgp all neighbors`, `show ip ospf`, `show ip ospf interface`, `show ip ospf neighbor detail`, `show cdp neighbors`, `show lldp neighbors`, `show vlan`, `show interface trunk`, `show inventory`, `show running-config`. Note: its IOS ARP is global-table only (same gap as ours). No FortiOS support. | [T1] https://github.com/netenglabs/suzieq/tree/develop/suzieq/config (arpnd.yml, routes.yml, bgp.yml, interfaces.yml, macs.yml, ospfIf.yml, ospfNbr.yml, vlan.yml, inventory.yml, lldp.yml, devconfig.yml); table matrix https://suzieq.readthedocs.io/en/latest/tables/ |
| Cisco Genie (pyATS) `learn` | CLI parsers into per-feature models | Ops features: acl, arp, bgp, device, dot1x, eigrp, fdb, hsrp, igmp, interface, isis, lag, lisp, lldp, management, mcast, mld, msdp, nd, ntp, ospf, pim, platform, prefix_list, rip, route_policy, routing, static_routing, stp, vlan, vrf, vxlan. | [T1] https://github.com/CiscoTestAutomation/genielibs (pkgs/ops-pkg/src/genie/libs/ops) |
| NAPALM (ios driver) | CLI via netmiko | 26 getters on IOS incl. get_arp_table, get_mac_address_table, get_ipv6_neighbors_table, get_interfaces, get_interfaces_ip, get_lldp_neighbors_detail, get_bgp_neighbors_detail, get_network_instances (VRFs), get_vlans, get_optics, get_environment, get_snmp_information, get_users, get_ntp_*. Not on IOS: get_route_to, get_firewall_policies. | [T1] https://napalm.readthedocs.io/en/latest/support/index.html |
| ntc-templates | TextFSM parsers | 100+ cisco_ios commands parsed (ARP, MAC, DHCP snooping binding, device tracking, access-session, VRF detail, BGP, OSPF, NHRP/DMVPN, NVE, transceiver, power inline, license, stack). Fortinet: only ~19, incl. `get system arp`, `get system interface`, `get router info routing-table all`, `diagnose lldprx port neighbor details`, `execute dhcp lease-list`. | [T1] https://github.com/networktocode/ntc-templates/blob/master/ntc_templates/templates/index |
| Nautobot Device Onboarding (sync network data) | netmiko + parsers | IOS commands in its mapper: `show version`, `show inventory`, `show switch detail`, `show interfaces`, `show ip interface`, `show interfaces switchport`, `show etherchannel summary`, `show vlan`, `show cdp neighbors detail`. Creates interfaces, IPs, optional VLANs and VRFs, cables. | [T1] https://github.com/nautobot/nautobot-app-device-onboarding (command_mappers/cisco_ios.yml); https://docs.nautobot.com/projects/device-onboarding/en/latest/user/app_use_cases/ |
| NetBox Discovery (orb-agent device_discovery) | NAPALM drivers | Interfaces, interface VLANs, VLANs, IPs and prefixes, facts, virtual chassis, modules (opt-in), VRFs (opt-in). No ARP, MAC or routes. | [T1] https://netboxlabs.com/docs/discovery/agent/backends/device_discovery/supported_platforms/ |
| LibreNMS discovery | SNMP | Default-on modules include arp-table, fdb-table, vlans, vrf, ipv4/ipv6-addresses, discovery-protocols, bgp-peers, stp, entity-physical, sensors, ntp, wireless; `route` and `cisco-cef` are off by default. | [T1] https://docs.librenms.org/Support/Discovery%20Support/ |
| Netdisco | SNMP or CLI (SSH) | IP, MAC and wireless address data (ARP and forwarding tables) plus device ports and neighbors. Detail pages not read. | [T1] https://github.com/netdisco/netdisco/wiki |
| Auvik | SNMP plus CLI show commands | ARP tables, L2 forwarding tables, IP assignments, VLAN associations, CDP/LLDP/FDP; draws "inferred" links separately; adds unmanaged devices implied by the data. | [T1] support.auvik.com article 202956414, as read and recorded in netops-skills `docs/handoff-network-diagram.md` (not re-read today) |
| Batfish | Config files (plus optional supplemental data) | Device configs are the core input; supplemental files live in a `batfish/` folder. Pages for layer-1 topology and runtime data formats were not reachable today. | [T1] https://batfish.readthedocs.io/en/latest/notebooks/interacting.html |
| SolarWinds NPM/NTM/NCM, NetBrain, Forward Networks, LogicMonitor, PRTG, Infrahub sync | | Not verified: the SolarWinds NTM page returned 404, and no public Forward Networks command list was found. Evidence for these is thin; nothing below depends on them. | |

What the best tools agree on, and this skill lacks: per-VRF ARP and routes, MAC table, IPv6 ND, DHCP
bindings, interface detail (MAC, MTU, speed), BGP across all address families, OSPF interface
detail, FHRP, STP per VLAN, and on FortiGate the user-device inventory and LLDP. Where we can beat
them: we commit full config plus stable state to git with noise removed, run with a read-only
privilege-5 account, and can join ARP + MAC + CDP/LLDP + DHCP into one host table per run.

### 2.2 Source-of-truth target model

Model families checked: NetBox apps (circuits, core, dcim, extras, ipam, tenancy, users,
virtualization, vpn, wireless) [T1] https://netboxlabs.com/docs/netbox/models/ (app index verified;
per-model names below are [MEM] from NetBox 4.x and were not opened one by one). Nautobot and
Infrahub core models were not opened today [MEM]: Nautobot adds Namespace, SoftwareVersion,
InterfaceRedundancyGroup and Controller; routing and firewall objects live in apps (Nautobot BGP
Models, Nautobot Firewall Models, netbox-bgp / netbox-routing plugins).

| Source-of-truth object | Can a device tell us? | Command(s) that fill it (Cisco / FortiOS) | Collected today? |
|---|---|---|---|
| Region, Site, Location | Partly (snmp-server location, hostname convention) | config | no (config only) |
| Rack, rack position, rack type | No | none: intent | no |
| Manufacturer, DeviceType, Platform | Yes | `show version`, `show inventory` / `get system status` | yes |
| Device (name, serial, role) | Name and serial yes; role inferred | `show version`, `show inventory` / `get system status` | yes (role no) |
| SoftwareVersion | Yes | `show version` / `get system status` | yes |
| Module, ModuleBay, InventoryItem (incl. optics) | Yes on hardware | `show inventory`, `show module` / `get hardware status` | yes |
| VirtualChassis (stack, StackWise Virtual) | Yes | `show switch detail`, `show stackwise-virtual` | partly (no SVL) |
| VirtualDeviceContext (FortiGate VDOM) | Yes | `get system status` (mode), `diagnose sys vd list` | partly |
| Interface: name, type, enabled, description, mode, VLANs, LAG parent | Yes | config, `show ip interface brief`, `show interfaces switchport`, `show etherchannel summary` / `show`, `get system interface` | mostly yes |
| Interface: MAC, MTU, speed, duplex | Yes | `show interfaces` / `get system interface physical` | Cisco no (health only); FortiGate yes |
| MACAddress object (NetBox 4.2+) | Yes | `show interfaces` | no |
| Cable / link | Partly: CDP/LLDP give strong evidence; LACP partner, UDLD, MAC/ARP give inferred links | `show cdp/lldp neighbors detail`, `show lacp neighbor`, `show udld neighbors`, MAC + ARP join / `diagnose lldprx neighbor summary` | partly (no FortiGate LLDP, no inference inputs) |
| FrontPort, RearPort, console, power ports, PowerPanel, PowerFeed | No (patch panels, power are physical) | none (PoE draw partly from `show power inline`) | no |
| IPAddress (incl. secondary, VIP/HSRP role) | Yes | config, `show ip interface`, `show ipv6 interface`, `show standby brief`, `show glbp brief` / `get system interface`, `get router info vrrp` | partly (no secondary, IPv6, GLBP) |
| Prefix | Yes (derived) | interface IPs, `show ip route vrf *` / routing table | partly (global only) |
| IPRange (DHCP pools) | Yes | config, `show ip dhcp pool` / `show` (config system dhcp server) | config only |
| Aggregate, RIR | No | none: intent | no |
| VLAN | Yes | `show vlan brief`, `show vlan private-vlan` | yes (no private VLANs) |
| VLANGroup | No | none: intent | no |
| VRF | Yes | `show vrf detail` | partly (`show vrf` without RD/RT detail) |
| RouteTarget | Yes | `show vrf detail`, config | config only |
| FHRPGroup | Yes | `show standby brief`, `show vrrp brief`, `show glbp brief` / `get router info vrrp` | partly |
| ASN | Yes | `show bgp all summary`, config | yes |
| Routing objects (BGP sessions, OSPF areas and interfaces, static routes) | Yes | `show bgp all summary/neighbors`, `show ip ospf interface`, `show ip protocols vrf X` / `get router info bgp ...`, `get router info ospf ...` | partly (global, IPv4 unicast only) |
| Route table (operational, not a SoT object) | Yes | `show ip route vrf *`, `show ipv6 route vrf *` / `get router info routing-table all` | partly (global only on Cisco) |
| Circuit, Provider, CircuitTermination | No (circuit IDs, providers are paperwork; at best a description convention) | none | no |
| Tunnel, TunnelTermination (GRE, IPsec, DMVPN) | Config yes; runtime state yes | config, `show crypto session`, `show ip nhrp`, `show dmvpn` / `show`, `get vpn ipsec tunnel summary` | config only |
| IKE/IPsec policy, proposal, profile | Yes | config / `show` | yes (config) |
| L2VPN (VXLAN EVPN, VPLS, EoMPLS) | Yes | config, `show nve vni`, `show nve peers` | config only |
| WirelessLAN, AP inventory, WirelessLink | Yes on controllers | `show wlan summary`, `show ap summary` (Cat9800) / `get wireless-controller wtp` | no |
| Cluster, VirtualMachine, VMInterface | No (hypervisor data); VMs appear only as hosts | ARP/MAC | no |
| Hosts / end devices (modeled as Device with a role, or IPAddress + MACAddress) | Yes | ARP, MAC, ND, DHCP bindings, DHCP snooping, device-tracking, access-session / `get system arp`, `diagnose user device list`, DHCP leases | no |
| ACLs, firewall policies, address objects, VIPs, NAT | Yes (config) | config / `show` | yes (config) |
| Device services (NTP, SNMP, syslog, AAA servers) | Yes | config / `show` | yes (config) |
| Tenant, Contact, owner, contracts, intent | No | none | no |
| Licenses, end-of-life inputs | Partly (PID and version; EoL dates come from vendor lists) | `show license summary`, `show version`, `show inventory` / `get system status` | partly |

---

## 3. Cisco IOS / IOS-XE command table

Lab notes. Lab v2 runs IOL (IOS-XE 17.16): an L3 image on routers and an L2 image on switches,
with no hardware. A command that is hardware or Catalyst-only (transceivers, PoE, environment,
StackWise, device-tracking, licensing) answers "% Invalid input" on IOL because it does not
exist there, not because of privilege. Probes: hq-edge-rtr-01 (.231, router) and hq-dist-sw-01
(.233, switch), 137 commands each, run twice ~2 minutes apart to see which outputs move.
`show privilege` returns "Current privilege level is 5" [LAB].

Reference keys (Cisco Catalyst 9300 IOS XE 17.18 Command Reference chapters, [T1]):
- IF: https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-18/command_reference/b_1718_9300_cr/interface_and_hardware_commands.html
- IPA: .../b_1718_9300_cr/ip_addressing_services_commands.html
- L2: .../b_1718_9300_cr/layer_2_3_commands.html
- RT: .../b_1718_9300_cr/unicast_routing_commands.html
- SEC: .../b_1718_9300_cr/security_commands.html
- HA: .../b_1718_9300_cr/stack_manager_and_high_availability_commands.html
- MC: .../b_1718_9300_cr/ip_multicast_routing.html
- MPLS: .../b_1718_9300_cr/mpls_commands.html
- VLAN: .../b_1718_9300_cr/vlan_commands.html
- SECZ: Cisco IOS Security Command Reference, Commands S to Z (crypto show commands), https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-cr-s3.html (found via search as a cisco.com mirror; not opened)
- SISF: Cisco doc 221562, https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9300-series-switches/221562-troubleshoot-sisf-on-catalyst-9000-serie.html

"Ref check": E = the command's own reference entry was read (syntax and mode); T = the command
is listed in that chapter's table of contents but its entry was not read (chapters are 160 to 250
KB and were read in slices); C = chapter inferred, not read; L = syntax proven only by the lab
parser accepting it on IOS-XE 17.16. Every "yes" in the lab column is also an L.

Tool keys: S SuzieQ, G Genie, N NAPALM, I IP Fabric, A Auvik, NO Nautobot onboarding, NB NetBox Discovery.

### 3.1 Add to the committed (diffed) set: 17 commands plus 1 preflight

| # | Command (exact) | Feeds | Volatile? | VRF-aware form | Priv 5 in lab | Privilege line? | Ref | Also collected by |
|---|---|---|---|---|---|---|---|---|
| 0 | `show privilege` (preflight, report only, no file) | records the account level so "% Invalid input" can be labeled "missing or not permitted" | no | n/a | yes | no | C (SYS) | I (`show privileges`) |
| 1 | `show ip route vrf *` (replaces `show ip route`) | routes, prefixes, next hops, all VRFs | route ages only; existing masks cover them; unchanged across the two runs | is the VRF form | yes (60 vs 21+ lines) | no | C (RT) | S, I, G |
| 2 | `show ipv6 route vrf *` | IPv6 routes | ages, masked | is the VRF form | global form yes (empty, no IPv6 in lab); `vrf *` not tested | no | C (RT) | S, I |
| 3 | `show ip route vrf * summary` | route counts per VRF and protocol; also the size gate for #1 | memory bytes move only with route churn | is the VRF form | yes | no | C (RT) | I |
| 4 | `show vrf detail` (replaces `show vrf`) | VRF, RD, RT import/export, interfaces, address families | no | n/a | yes | no | C (RT) | S, I, NB |
| 5 | `show ip interface` | secondary IPs, helper addresses, ACLs applied, uRPF, PBR, VRF per interface | no (unchanged across runs) | covers all VRFs | yes (217 to 276 lines) | no | E (IF: `show ip interface [type number] [brief]`) | S, I, NO |
| 6 | `show ipv6 interface` | IPv6 addresses, link-local, ND settings | no | covers all VRFs | brief form yes; full form not tested | no | C (IPA) | S, I |
| 7 | `show bgp all summary` (replaces `show ip bgp summary`) | BGP sessions in every AFI/SAFI incl. VPNv4 and EVPN | message counters; existing neighbor-line mask covers IPv4 peers, needs an IPv6-peer variant | covers VRF AFs | yes | no | C (RT) | S, I |
| 8 | `show ip ospf interface` | OSPF area, cost, network type, DR/BDR per interface | "Hello due in" (masked by hh:mm:ss), "Last flood scan length/time" (add a strip rule) | per process, all VRFs | yes (53 lines) | no | C (RT) | S, I, G |
| 9 | `show ip protocols vrf {vrf}` | routing processes and redistribution inside each VRF | timers ("next due in"): mask | is the VRF form | yes | no | C (RT) | I |
| 10 | `show spanning-tree` | root, port roles/states/costs per VLAN | no (unchanged across runs; counters live in `detail`) | n/a | yes (67 lines) | no (lab already has a level-5 line for `show spanning-tree`) | E (L2) | I, G |
| 11 | `show vlan private-vlan` | private VLAN pairs | no | n/a | yes (switch) | no | C (VLAN) | |
| 12 | `show lacp neighbor` | LACP partner system ID and port: link evidence for port-channels | per-port age column: mask | n/a | yes (empty, no LACP in lab) | no | E (L2: `show lacp [channel-group-number] {counters | internal | neighbor | sys-id}`) | I, G (lag) |
| 13 | `show udld neighbors` | UDLD neighbor device and port: link evidence | no | n/a | yes on switch; invalid on router (feature absent) | no | T (L2) | I |
| 14 | `show glbp brief` | GLBP FHRP groups | no | n/a | yes (empty) | no | C (IPA) | I |
| 15 | `show ip dhcp snooping` | snooping VLANs, trusted ports | no | n/a | yes on switch | no | C (SEC) | I |
| 16 | `show stackwise-virtual` | StackWise Virtual pairs (Cat9k) | no | n/a | invalid on IOL (feature absent) | no | C (HA) | I |
| 17 | `show nve vni` | VXLAN VNI to VLAN/VRF map | no | n/a | not tested (`show nve peers` exists on both images) | no | C | I, S (NX-OS) |

### 3.2 Add to the collected-but-not-diffed "state" set: 21 default, 10 `--full` only (9 rows)

Run by default, saved outside git (like health), never diffed. Commands marked {vrf} run once per
VRF found in `show vrf detail`.

| # | Command (exact) | Feeds | Why not diffed / stable form | VRF-aware form | Priv 5 in lab | Privilege line? | Ref | Also collected by |
|---|---|---|---|---|---|---|---|---|
| 1 | `show ip arp` | hosts: IP to MAC to interface | age column moves [LAB, changed between runs]; stable form exists: mask the Age column and sort by IP (then only real host arrivals and departures diff) | global only | yes | no | C (IPA) | S, I, N, A, G |
| 2 | `show ip arp vrf {vrf}` | hosts in each VRF (MGMT) | same | is the VRF form; `show ip arp vrf *` is rejected ("% VRF * does not exist") [LAB] | yes | no | C (IPA) | I |
| 3 | `show ipv6 neighbors` | IPv6 hosts | ages, states | global | yes (empty) | no | T (IPA) | S, I, N |
| 4 | `show ipv6 neighbors vrf {vrf}` | IPv6 hosts per VRF | same; an IPv4-only VRF answers "% IPv6 routing table MGMT does not exist" [LAB], treat as no data | is the VRF form | yes | no | T (IPA) | I |
| 5 | `show mac address-table` | L2 forwarding table: host to port, unmanaged-switch inference | dynamic entries appear and age out (300 s); a new entry appeared between runs [LAB]; no stable form beyond keeping STATIC rows | per VLAN | yes on switch; invalid on router | no | C (L2) | S, I, N, A, G (fdb) |
| 6 | `show mac address-table count` | size gate for #5 (not saved) | counts move | n/a | yes | no | C (L2) | |
| 7 | `show ip dhcp binding` | DHCP server leases (router as server) | lease expiry | per pool; VRF pools listed separately | yes | no | C (IPA) | I |
| 8 | `show ip dhcp snooping binding` | IP/MAC/VLAN/port bindings on access switches | lease seconds | n/a | yes on switch | no | C (SEC) | I |
| 9 | `show device-tracking database` | SISF host bindings (Cat9k 17.x) | ages and states | n/a | invalid on IOL (feature absent in image) | unknown on Cat9k: reference shows privileged EXEC; test on real hardware | T (SEC), SISF | |
| 10 | `show access-session` | 802.1X / MAB sessions: user and MAC per port | session timers | n/a | IOL L2 answers "% Incomplete command" (needs a keyword there); router invalid | unknown on Cat9k | T (SEC) | I |
| 11 | `show bgp all neighbors` | per-session detail: AF, policies, accepted/advertised prefix counts | message and timer counters (56 lines changed between runs) | covers VRF AFs | yes | no | C (RT) | S, I, N |
| 12 | `show ip ospf neighbor detail` (move from health) | neighbor interface address, area, DR/BDR | dead timer, uptime | all VRFs | yes | no | C (RT) | S, I |
| 13 | `show ip ospf database` | LSDB summary: every router and network LSA | LS age and sequence move (14 lines changed) | per process | yes | no | C (RT) | I |
| 14 | `show interfaces` (move from health) | interface MAC (BIA), MTU, speed, duplex, encapsulation | counters and rates; stable facts can be parsed out into a committed derived file | n/a | yes | no | E (IF) | S, I, NO, N |
| 15 | `show power inline` (move from health) | PoE class and draw per port: phones and APs | watts move | n/a | invalid on IOL (no hardware) | no | T (IF) | I |
| 16 | `show crypto session` | IPsec/IKE peer and tunnel status | uptime | n/a | yes on router (empty) | no | C (SECZ) | |
| 17 | `show ip nhrp` | DMVPN NHRP mappings | expiry timers | `show ip nhrp vrf {vrf}` [MEM, not tested] | yes (empty) | no | T (IPA) | I |
| 18 | `show ip nat translations` | NAT state (static rows are stable) | dynamic rows churn; huge on busy edges | `vrf` keyword exists [MEM, not tested] | yes (empty) | no | T (IPA) | ntc |
| 19 | `show ip mroute` | multicast state | uptime/expiry | `show ip mroute vrf {vrf}` | yes (22 lines) | no | C (MC) | I |
| 20 | `show ip pim neighbor` | PIM adjacencies | uptime/expiry | `show ip pim vrf {vrf} neighbor` | yes | no | C (MC) | I |
| 21 | `show nve peers` | VXLAN VTEP peers | uptime | n/a | yes (header only) | no | C | I |
| F1 | `show bgp {afi} {safi} neighbors {ip} advertised-routes` (`--full`) | what each peer is sent | table versions | `show bgp vrf {vrf} ...` | yes | no | C (RT) | I |
| F2 | `show bgp {afi} {safi} neighbors {ip} routes` (`--full`) | what each peer sends (accepted) | same | same | yes | no | C (RT) | I |
| F3 | `show ip ospf database router` (`--full`) | full intra-area topology | LS age | per process | yes (263 lines) | no | C (RT) | |
| F4 | `show mpls ldp neighbor` (`--full`, only when config has `mpls ip`) | LDP adjacencies | uptime | n/a | yes (empty) | no | C (MPLS) | I |
| F5 | `show crypto ikev2 sa` (`--full`) | IKEv2 SAs | SA lifetimes | n/a | refused | maybe: see section 7 | C (SECZ) | I |
| F6 | `show crypto isakmp sa` (`--full`) | IKEv1 SAs | same | n/a | refused | maybe | C (SECZ) | I |
| F7 | `show crypto ipsec sa` (`--full`) | IPsec SAs and SPIs | packet counters | n/a | refused | maybe | C (SECZ) | I |
| F8 | `show dmvpn` (`--full`) | DMVPN peer table | timers | n/a | refused | maybe | C | I |
| F9 | `show ap summary` and `show wireless client summary` (Cat9800 controllers only) | AP inventory, wireless hosts | clients churn | n/a | not tested (no controller in lab) | unknown | C | I |

Refused commands, cause assessment: `show crypto ikev2 sa`, `show crypto isakmp sa`,
`show crypto ipsec sa`, `show crypto map` and `show dmvpn` are refused on hq-edge-rtr-01 while
`show crypto session` and `show crypto key mypubkey rsa` are accepted, so the crypto parser exists
in the image. Either the IOL image lacks IPsec, or these commands sit at privilege 15. I could not
tell which without the admin account, and I did not use it. Everything else refused in the lab is
a feature the IOL image does not have (hardware, Catalyst-only, or L2 commands on the L3 image).

### 3.3 Already collected (32 committed, 27 health): recommended action

Committed today (`commands`): `show running-config view full`, `show startup-config`,
`show version`, `show inventory`, `show boot`, `show license summary`, `show switch detail`,
`show module`, `show redundancy`, `show ip interface brief`, `show interfaces description`,
`show interfaces status`, `show interfaces switchport`, `show interfaces trunk`, `show vlan brief`,
`show vtp status`, `show etherchannel summary`, `show spanning-tree summary`,
`show spanning-tree root`, `show standby brief`, `show vrrp brief`, `show cdp neighbors detail`,
`show lldp neighbors detail`, `show vrf`, `show ip protocols`, `show ip route`,
`show ip ospf interface brief`, `show ip ospf neighbor`, `show ip eigrp neighbors`,
`show ip bgp summary`, `show ip access-lists`, `show ip ssh`. Keep all except:

| Command | Action | Reason (evidence) |
|---|---|---|
| `show ip route` | replace with `show ip route vrf *` | global table only; misses MGMT [LAB] |
| `show vrf` | replace with `show vrf detail` | no RD/RT/AF detail |
| `show ip bgp summary` | replace with `show bgp all summary` | IPv4 unicast global only |
| `show ip eigrp neighbors` | consider `show ip eigrp vrf * neighbors` (IP Fabric's form) | global only; `vrf *` form not lab-tested |
| `show license summary` | keep | invalid on IOL [report of 2026-11-13 snapshot]; valid on IOS-XE hardware per profile comment |
| `show running-config view full` | keep | `show running-config` at privilege 5 returns an 88-byte stub ("Current configuration : 88 bytes", only `end`) [LAB]; the classic gotcha is confirmed |

Health today (`health_commands`, unchanged unless listed): keep `show processes cpu sorted 5min`,
`show processes cpu history`, `show memory statistics`, `show platform resources`,
`show platform software status control-processor brief`, `show environment all`,
`show interfaces transceiver detail`, `show interfaces counters errors`,
`show interfaces status err-disabled`, `show spanning-tree detail`,
`show spanning-tree inconsistentports`, `show spanning-tree blockedports`, `show standby`,
`show track`, `show ip eigrp neighbors detail`, `show ip bgp neighbors`, `show ip route summary`,
`show debugging`, `show crypto session`, `show ip sla statistics`, `show ntp status`,
`show ntp associations`, `show logging`, `show clock`. Move to state: `show interfaces`,
`show power inline`, `show ip ospf neighbor detail`. Drop from health once state has them:
`show ip bgp neighbors` (superseded by `show bgp all neighbors`), `show crypto session`.

### 3.4 Considered and rejected: 35 commands in 23 rows

| Command | Reason |
|---|---|
| `show running-config` | empty stub at privilege 5 [LAB] |
| `show tech-support` | very large, slow, CPU-heavy on production; duplicates everything else |
| `show ip bgp` (full table) | a full internet table is ~1M paths; per-neighbor counts in `show bgp all neighbors` suffice |
| `show ip cef` / `show ip cef vrf X` | FIB duplicates the RIB for SoT purposes; big on cores (IP Fabric uses it for forwarding analysis, out of scope) |
| `show ip arp vrf *` | does not exist [LAB] |
| `show ip arp summary`, `show ip route static` | subsets of other output |
| `show route-map`, `show ip prefix-list`, `show ip policy`, `show object-group`, `show ip as-path-access-list`, `show ip community-list` | definitions are in the committed config; `show route-map` adds match counters that churn |
| `show zone-pair security`, `show policy-map type inspect zone-pair sessions` | ZBFW config is in the config; sessions are volatile; invalid on IOL |
| `show policy-map interface`, `show ip sla summary`, `show ip dhcp server statistics` | counters only |
| `show snmp user`, `show snmp host` | refused at privilege 5; SNMP config is in the config; low SoT value |
| `show hosts`, `show clock detail`, `show users`, `show line` | volatile, not network state |
| `show crypto key mypubkey rsa` | accepted but no SoT value |
| `show crypto map` | refused; config has crypto maps |
| `show lldp entry *` | same data as `show lldp neighbors detail` |
| `show interfaces capabilities` | static hardware data, long on real switches |
| `show authentication sessions` | invalid on both images; IBNS 2.0 uses `show access-session` |
| `show storm-control` | invalid on IOL; storm-control config is in the config |
| `show monitor session all` | invalid on the router; SPAN config is in the config |
| `show vlan` (full) | `show vlan brief` + `show vlan private-vlan` + switchport cover it |
| `show ip vrf interfaces` | covered by `show vrf detail` |
| `show ip ospf border-routers` | derivable from the LSDB |
| `show archive` | refused; not network state |

---

## 4. FortiOS command table

Lab: fw-01, FortiGate-VM 8.0.1, VDOMs off, account `claude-ro-cli`. 76 `get`/`show` probes, run
twice. `get` and `show` answered in 0.4 s each; `show` (full config) is 13,071 lines, 404 KB,
1.2 s. Fortinet references [T1]: FortiOS 8.0.0 CLI reference https://docs.fortinet.com/document/fortigate/8.0.0/cli-reference/8000 (index only; get/diagnose entries not reached),
`get system arp` https://docs.fortinet.com/document/fortigate/6.0.0/cli-reference/230076 (notes it is not available in multiple-VDOM mode),
LLDP reception https://docs.fortinet.com/document/fortigate/7.6.7/administration-guide/311052 and CLI 7.6.3 https://docs.fortinet.com/document/fortigate/7.6.3/cli-reference/124921537,
DHCP monitor https://docs.fortinet.com/document/fortigate/7.0.1/administration-guide/38214 and `execute dhcp` https://docs.fortinet.com/document/fortigate/7.6.7/cli-reference/329164585,
device detection https://docs.fortinet.com/document/fortiswitch/7.2.1/fortilink-guide/801195.

Key point: almost every FortiGate object a SoT needs (interfaces, zones, policies, addresses,
VIPs, IP pools, IPsec phase1/phase2, SD-WAN members and health checks, DHCP server, SNMP, syslog,
admins, managed FortiSwitch and FortiAP definitions) is already in the committed `show`. What is
missing is runtime state, and most of it is only exposed through `diagnose`/`execute` or the REST
API.

### 4.1 Add to the committed set: 4

| # | Command | Feeds | Volatile? | VRF/VDOM form | Lab | Ref | Also collected by |
|---|---|---|---|---|---|---|---|
| 1 | `get system interface` | every interface incl. tunnel, aggregate, VLAN, FortiLink: IP, mode, status, type | no (unchanged across runs) | per VDOM | yes | ntc; IP Fabric | I |
| 2 | `get router info vrrp` | VRRP groups | state changes only | per VDOM | yes (empty) | IP Fabric FHRP task | I |
| 3 | `get switch-controller managed-switch` | managed FortiSwitch list and status | status | global | yes (empty, none managed) | not found in reference today | |
| 4 | `get wireless-controller wtp` | managed FortiAP list | status | global | yes (empty) | not found in reference today | |

Note: `get router info routing-table all` (already collected) prints "Routing table for VRF=default(0)" headers [LAB], so it already covers FortiOS VRFs. `get router info routing-table vrf 0` does not exist [LAB].

### 4.2 Add to the not-diffed state set: 12

| # | Command | Feeds | Why not diffed | Lab | Notes and reference | Also collected by |
|---|---|---|---|---|---|---|
| 1 | `get system arp` (move from health) | hosts | Age column; stable form: mask age, sort by IP | yes | per VDOM; ref above | I, ntc, A |
| 2 | `get vpn ipsec tunnel summary` (move from health) | tunnel up/down, selectors | counters | yes (empty) | | |
| 3 | `get router info ospf database brief` | LSDB | LS age (14 lines changed) | yes | | |
| 4 | `get router info routing-table database` (`--full`) | RIB incl. non-selected routes | route ages | yes | | |
| 5 | `get system interface transceiver` | optic type and levels (hardware only) | light levels | refused on VM ("command parse error"); IP Fabric runs it on hardware | not lab-verified, hardware only | I |
| 6 | `diagnose user device list` | device inventory: MAC, IP, hostname, OS, interface | hosts come and go | not lab-verified, read-only status per Fortinet docs: documented as the CLI way to "display a list of detected devices" (FortiLink guide) | needs device detection on LAN interfaces | I |
| 7 | `diagnose ipv6 neighbor-cache list` | IPv6 hosts | states | not lab-verified, read-only status per Fortinet docs: no reference entry found; IP Fabric uses it | `get router info6 neighbor-cache list` does not exist [LAB] | I |
| 8 | `diagnose lldprx neighbor summary` (up to 7.6.2) / `diagnose lldp rx neighbor summary` (7.6.3 and later) | LLDP neighbors: link evidence for fw-01 | holdtimes | not lab-verified, read-only status per Fortinet docs: documented display command; spelling changed in 7.6.3, so the profile needs both and must try the newer first on 8.0 | `get system lldp neighbors` does not exist [LAB] | ntc |
| 9 | `diagnose vpn ike gateway list` | IKE gateways, peers | SA timers | not lab-verified, read-only status per Fortinet docs: not confirmed; IP Fabric uses it | | I |
| 10 | `diagnose sys sdwan member` | SD-WAN member state | state | not lab-verified, read-only status per Fortinet docs: not confirmed; IP Fabric uses it | | I |
| 11 | `diagnose sys sdwan health-check` | SLA probe state | latency/jitter | not lab-verified, not confirmed in docs | | |
| 12 | `execute dhcp lease-list` | DHCP leases | lease times | not lab-verified; the CLI reference lists it as "List all DHCP leases" (read-only), but the verb is `execute`, which snapshot.py refuses (READ_VERBS = show, get, display) | prefer REST (4.5) | ntc |

### 4.3 Already collected (15 committed, 10 health)

Committed: `show`, `get system status`, `get hardware status`, `get system interface physical`,
`get system ha status`, `get system dns`, `get system ntp`, `get router info routing-table all`,
`get router info6 routing-table`, `get router info ospf interface`, `get router info ospf neighbor`,
`get router info bgp summary`, `get router info bgp neighbors`, `get firewall proute`,
`get system fortiguard-service status`. Keep all. Note `get router info ospf neighbor` moved between
runs (4 lines: dead time) [LAB]; the existing hh:mm:ss mask should cover it, check the diff.

Health: `get system performance status`, `get hardware cpu`, `get hardware memory`,
`get system session-info statistics`, `get system session-info full-stat`,
`get system performance firewall statistics`, `get vpn ipsec tunnel summary`,
`get vpn ipsec tunnel details`, `get system admin status`, `get system arp`. Move the two noted
above to state.

### 4.4 Considered and rejected: 33 commands

| Command | Reason |
|---|---|
| `show firewall policy`, `show firewall address`, `show firewall addrgrp`, `show firewall vip`, `show firewall ippool`, `show firewall service custom`, `show vpn ipsec phase1-interface`, `show vpn ipsec phase2-interface`, `show system sdwan`, `show system zone`, `show system dhcp server`, `show system snmp community`, `show log syslogd setting`, `show system admin` (14) | all are sections of the committed `show`; separate files would duplicate diffs |
| `get firewall policy` | prints only policy IDs [LAB] |
| `get system sdwan`, `get system global`, `get system settings`, `get log syslogd setting`, `get system snmp sysinfo` | config again, with defaults; large |
| `get system session list` | every session; volatile; thousands of lines on production |
| `get router info kernel` | kernel FIB, duplicates the routing table |
| `get router info ospf status`, `get system admin list`, `get system auto-update versions` | counters or sessions change every run [LAB] |
| `get vpn certificate local` | certificate audit, not SoT |
| `get system arp-table` | is the static ARP config table (empty) [LAB] |
| `get router info6 neighbor-cache list`, `get user device`, `get system lldp neighbors`, `get system virtual-wan-link`, `get system vdom-property`, `get router info routing-table vrf 0` | do not exist on 8.0.1 ("command parse error") [LAB]; `get system vdom-property` is likely hidden because VDOMs are off |

### 4.5 Where the FortiOS REST API is the better source

The monitor API exposes exactly the runtime state the CLI hides behind `diagnose`/`execute`.
Fortinet's own Ansible collection (fortinet.fortios, `fortios_monitor_fact`) lists these selectors
[T1] https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/fortios_monitor_fact_module.html:
`network_arp`, `network_lldp_neighbors`, `user_device_query`, `system_dhcp`,
`switch-controller_managed-switch_status`, `wifi_managed_ap`, `wifi_client`, `vpn_ipsec`,
`virtual-wan_health-check`, `virtual-wan_members`, `router_ipv4`, `router_ipv6`,
`system_interface_transceivers`, `system_interface_poe`, `system_ha-peer`. Paths follow
`/api/v2/monitor/<selector with / for _>` (for example `/api/v2/monitor/network/arp`, available
from FortiOS 6.4 per a third-party wrapper [T3]; `/api/v2/monitor/user/device/query` confirmed by
Fortinet staff in the community forum [T3]). The official REST reference sits behind the Fortinet
Developer Network login, so exact paths and fields are UNVERIFIED here.

Better than CLI for: DHCP leases (no `execute`), user devices, LLDP, managed switch and AP status,
SD-WAN health, all as JSON (no screen scraping, no paging). Cost: a REST API admin with a
read-only profile and an API token (an account change the owner must approve and the user must
create), HTTPS reachability, and a second transport in the script.

---

## 5. Collection method recommendation

Recommendation: CLI first and default, with an optional FortiOS REST source later.

- CLI over SSH with the existing read-only account reaches everything in sections 3.1, 3.2 and
  4.1 to 4.2 (except `diagnose`/`execute`) with one credential and one transport. It is what IP
  Fabric, SuzieQ, Nautobot onboarding and NAPALM use for IOS. The raw text stays the git record,
  which is the skill's main value.
- FortiOS REST: worth adding as an opt-in second source for FortiGate state (hosts, DHCP leases,
  LLDP, managed devices, SD-WAN health). It needs a read-only API token, which is simple for one
  engineer to create. This is the one place the structured source clearly beats the CLI.
- IOS-XE RESTCONF/NETCONF (YANG oper models for ARP, MAC, CDP/LLDP, routing): not now. It needs
  `restconf`/`netconf-yang` enabled on each device (a config change), I believe a privilege-15 user
  [MEM, UNVERIFIED], and classic IOS lacks it entirely, so it cannot replace CLI. `| json` does not
  exist on IOS/IOS-XE (it is an NX-OS feature, as SuzieQ's `| json native` forms show).
- SNMP (what Auvik, LibreNMS and Netdisco use for ARP and FDB): skip. Same data as CLI, another
  credential set, weaker on VRFs (per-VRF SNMP contexts).
- Normalization: keep raw text; parse later in `devicefacts` (own parsers, or depend on the
  ntc-templates package rather than copying templates). Join ARP + MAC + CDP/LLDP + DHCP into one
  host table per run; that join is what beats the commercial tools, which show these as separate
  screens.

Trade-off in plain words: CLI-only means one account, one transport and diffable text, but host
data from FortiGate stays thin until `diagnose` is allowed or REST is added. REST gives clean
FortiGate data but costs an API token and a second code path.

---

## 6. Design implications for the implementer

1. New command class. Add `state_commands` to the profile schema, run by default, saved like
   health under `<repo>/.snapshot/state/<site>/<device>/` with a `state-prev` copy, never
   committed. Keep `health_commands` opt-in. Add `--no-state`. Add a `tier: full` flag per command
   for `--full`.
2. Per-VRF iteration (Cisco). Run `show vrf detail` (committed anyway) first, parse VRF names
   (`^VRF (\S+) \(VRF Id`) [LAB format: "VRF MGMT (VRF Id = 1); default RD <not set>"]. Legacy
   `ip vrf` boxes: `show ip vrf` also works [LAB]. Validate each name against
   `^[A-Za-z0-9_.:-]{1,32}$` before putting it in a command (it comes from device output, so treat
   it as untrusted), then expand `{vrf}` templates. Filenames: slug of the expanded command.
   Commands that already accept `vrf *` (`show ip route vrf *`, `show ipv6 route vrf *`,
   `show ip route vrf * summary`) run once.
3. New "no data" markers, not errors: "% VRF * does not exist", "% IPv6 routing table <x> does
   not exist", "% BGP not active", "no MPLS apps enabled". "% Incomplete command" is already an
   invalid marker.
4. Privilege-5 ambiguity. Record `show privilege` once per device and put the level in the
   report; label rejected commands "not supported on this device, or not permitted at privilege N".
5. Conditional commands. Add an optional `when:` regex matched against the saved running config
   (for example `mpls ip`, `interface nve`, `crypto`, `ip pim`, `ip dhcp snooping`,
   `device-tracking`, `access-session`), so routers do not run 20 switch commands and vice versa.
   This cuts run time and the unsupported list.
6. Size gates for production. Before `show ip route vrf *`, read `show ip route vrf * summary`;
   above a threshold (suggest 20,000 routes) keep only the summary and say so. Before
   `show mac address-table`, read `show mac address-table count`; above a threshold, raise the
   read timeout. Never run per-neighbor BGP route commands when a neighbor's PfxRcd exceeds
   10,000 or without `--full`. Never run `show tech-support`.
7. Timeouts and paging. Today `read_timeout` defaults to 90 s per command; set 300 s for route,
   MAC and BGP-neighbor commands. Cisco paging is handled by netmiko (`terminal length 0`). Risk:
   netmiko's Fortinet driver changes config when the console is in "more" mode: it sends
   `config system console` / `set output standard` / `end` (and `config global` with VDOMs)
   [read in the installed netmiko 4.8.0 `fortinet_ssh.py`]. The lab already has
   `set output standard` [LAB, in `show`], so it did not fire. A read-only tool should not depend
   on that: override `disable_paging` to a no-op and fail with a clear message when output mode is
   "more", and document the one-line setting in the README.
8. Volatility masks to add (from the two-run diff [LAB]): ARP Age column (Cisco and FortiOS);
   `show ip ospf interface` "Last flood scan" lines; `show lacp neighbor` age column;
   `show standby` "Next hello sent in" and "expires in" (only if it ever moves to committed);
   OSPF database LS age and sequence (stays in state). Sorting: ARP by IP, MAC table by VLAN and
   MAC, CDP/LLDP already sorted.
9. FortiOS verbs. `diagnose` and `execute` are refused by `READ_VERBS`. If the owner allows them,
   use an exact-string allowlist of named read-only commands (section 4.2), never a verb-wide
   allow. FortiOS 8.0 spelling of LLDP diagnose differs from 7.4; try both.
10. FortiOS VDOMs. Per-VDOM commands (`get system arp` is "not available in multiple VDOM mode")
    need `config vdom` / `edit <name>` context switches, which `READ_VERBS` blocks and which look
    like config mode. Detect VDOM mode from `get system status` and report "VDOM state not
    collected" until the owner decides.
11. Output size and run time, measured [LAB]: 137 Cisco commands took 74 to 75 s per device
    (0.51 to 0.52 s each) and produced 107 to 126 KB; 76 FortiGate commands took 36.5 s and 476 KB
    (404 KB of it the config). The current committed set is about 100 KB per Cisco device on disk.
    Estimate for the proposed default (about 50 committed + 21 state Cisco commands, plus 4 per
    extra VRF): about 40 s per IOL device. Real Catalyst and ISR hardware is slower per command
    and has larger tables; expect 1 to 4 minutes per device [MEM, unmeasured]. The script already
    runs 8 devices in parallel (`--workers`).
12. Recommended tiers:
    - default: committed set (config + stable structure) + state set (hosts, protocol detail).
    - `--full`: per-neighbor BGP routes, OSPF router LSAs, crypto SAs, FortiGate RIB database,
      wireless clients.
    - `--health`: unchanged purpose (CPU, memory, environment, errors, logs).
13. Other 12 platform profiles: same two gaps. Cheap equivalents [MEM, not verified today]:
    NX-OS `show ip arp vrf all`, `show mac address-table`; Arista EOS `show ip arp vrf all`,
    `show mac address-table`; Junos `show arp no-resolve`, `show ethernet-switching table`;
    PAN-OS `show arp all`; AOS-CX `show arp all-vrfs`, `show mac-address-table`.

---

## 7. Open questions for the owner (with recommended answers)

1. Should ARP be committed in a masked, sorted form? Recommend yes for ARP (low churn once the age
   is masked; a new or vanished host is a real change), no for MAC, ND, DHCP and device-tracking
   (state only), plus a derived `hosts` table (IP, MAC, VLAN, switch port, source) written each run
   to the state folder.
2. Run the state set by default? Recommend yes, with `--no-state` to skip; health stays opt-in.
3. How much state history to keep? Recommend current plus previous (mirrors health/health-prev),
   with `--keep N` later if needed.
4. Allow FortiOS `diagnose` / `execute` read-only commands via an exact allowlist? Recommend yes,
   for the six in section 4.2, after the owner runs each once with `claude-ro-cli` to confirm the
   read-only admin profile permits them.
5. Add an opt-in FortiOS REST source (read-only API token)? Recommend yes, as phase 2, FortiGate
   only.
6. Lab privilege lines for crypto (only if the admin account shows these commands work, meaning
   they are privilege-gated rather than missing from IOL): `privilege exec level 5 show crypto
   ikev2 sa`, `privilege exec level 5 show crypto isakmp sa`, `privilege exec level 5 show crypto
   ipsec sa`, `privilege exec level 5 show dmvpn`. Recommend not adding them now: the lab has no
   IPsec, and they are `--full` only. No privilege line is needed for the default set.
7. Thresholds for size gates: recommend 20,000 routes and 20,000 MAC entries, overridable per
   device in the inventory.
8. FortiGate VDOM support: recommend deferring; report clearly when VDOMs are on.
9. Netmiko Fortinet paging write: recommend overriding it (fail closed) and documenting
   `set output standard`.

---

## 8. What I could not verify

- Exact reference entries (syntax and command mode) for most Cisco commands: the 9300 17.18
  chapters are too large for one fetch and plain curl is blocked, so many rows rest on the chapter
  table of contents (T), an inferred chapter (C), or the lab parser (L). Entries read in full: the
  `show etherchannel`, `show lacp`, `show pagp`, `show spanning-tree`, `show ip interface`,
  `show interfaces` (counters, switchport, transceiver), `show environment`, `show errdisable
  recovery`, `show inventory` and device-tracking usage text.
- Whether the refused crypto/DMVPN commands are absent from IOL or privilege-gated (needs an admin
  check by the owner).
- Cisco "Privileged EXEC" in a reference does not predict the default privilege level:
  `show ip interface` is documented as privileged EXEC yet runs at level 5 [LAB]. Only a run on the
  target device settles it.
- Catalyst-only commands (device-tracking, access-session full form, power inline, transceivers,
  StackWise Virtual, licensing, wireless) could not be run on IOL.
- All FortiOS `diagnose`/`execute` commands (not run, per the rules) and whether the read-only
  admin profile permits them.
- FortiOS 8.0 `get`/`diagnose` reference pages (only the 8.0 config index was reached).
- FortiOS REST paths and fields (official reference is login-gated; selectors come from Fortinet's
  Ansible collection, paths from community and wrapper sources [T3]).
- IOS-XE RESTCONF privilege requirement [MEM].
- SolarWinds NPM/NTM/NCM, NetBrain, Forward Networks, LogicMonitor, PRTG and Infrahub collection
  lists (pages 404 or not found); Batfish runtime-data and layer-1 formats; Nautobot and Infrahub
  core model lists; NetBox per-model pages.
- Run time on real hardware and with large tables (lab is IOL with tiny tables).
- `show ipv6 interface`, `show ipv6 route vrf *`, `show nve vni`, `show ip eigrp vrf * neighbors`,
  VRF forms of NHRP and NAT: not run in the lab.
