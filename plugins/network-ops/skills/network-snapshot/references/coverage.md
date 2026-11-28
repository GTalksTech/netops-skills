# What a snapshot collects, and what it cannot see

## Contents
- Cisco IOS / IOS-XE
- Fortinet FortiGate
- Other platforms
- What no snapshot can see

## Cisco IOS / IOS-XE (lab-tested)

**Committed (diffed):** running and startup config (`show running-config view full`, which
works at privilege 5), version, inventory, stacks and StackWise Virtual, interfaces (brief, full
`show ip interface` with secondary addresses, helpers and ACLs, IPv6 when configured,
switchport, trunks, status), VLANs and private VLANs, VTP, EtherChannel, LACP and UDLD partners,
spanning tree per VLAN, HSRP / VRRP / GLBP, CDP and LLDP neighbors, VRFs with RD and route
targets, routing protocols globally and per VRF, routes in every VRF (IPv4, and IPv6 when
configured) with counts per VRF, OSPF interfaces and neighbors, EIGRP neighbors, BGP sessions in
every address family, DHCP snooping, VXLAN VNIs, ACLs, SSH.

**Device state (not diffed):** ARP globally and per VRF, IPv6 neighbors, MAC address table, DHCP
server and snooping bindings, device-tracking (Catalyst 9000), 802.1X / MAB sessions, full
`show interfaces` (MAC, MTU, speed), PoE, BGP neighbor detail, OSPF neighbor detail and LSDB,
crypto sessions, NHRP, NAT translations, multicast routes and PIM neighbors, VXLAN peers.

**Only with `--full`:** OSPF router LSAs, MPLS LDP neighbors, IKEv1 / IKEv2 / IPsec SAs and DMVPN.
At privilege 5 the crypto SA commands were refused in the lab; they may need privilege 15.

Commands for a feature the config does not use are skipped (`when:` in the profile), so a router
does not run DHCP snooping and a switch without BGP does not run BGP detail.

## Fortinet FortiGate (lab-tested)

**Committed:** the full configuration (`show`), system status, hardware, interfaces (physical
and every logical interface), HA, DNS, NTP, routing table (all VRFs), IPv6 routes, OSPF and BGP,
policy routes, FortiGuard status, VRRP, managed FortiSwitches and FortiAPs.

**Device state:** ARP, IPsec tunnel summary, OSPF database, transceivers (hardware only).
**Only with `--full`:** the routing table database (every route, selected or not).

**Not collected, on purpose:**
- Anything behind `diagnose` or `execute`: LLDP neighbors, the user-device list, IPv6
  neighbors, DHCP leases, SD-WAN member and health-check state, IKE gateways. The read-verb guard
  refuses those verbs, and the read-only admin profile does not grant them.
- FortiGates with VDOMs on: the run refuses them rather than enter `config global`.
- A FortiGate whose console pages (`set output more`): refused, with the one-line fix.

So FortiGate host data is its ARP table only, and FortiGate links show up through its neighbors'
CDP/LLDP and ARP tables, not its own.

## Other platforms (untested)

The NX-OS, Arista, Junos, AOS-CX, PAN-OS, Huawei, Extreme, Dell, ArubaOS-Switch, Nokia and ASA
profiles collect config and stable structure only: no device state, and the host table reads
nothing from them yet.

## What no snapshot can see

- Anything on a device not in the inventory, or a device it could not log in to.
- Hosts that sent nothing recently: ARP and MAC entries age out (MAC tables in about 5 minutes by
  default), so a quiet host can be missing from one run and back in the next.
- Which unmanaged switch, hypervisor or wireless AP a host sits behind: the table shows the edge
  port on the last managed switch, or "seen only on uplinks".
- Physical facts: cabling, patch panels, rack positions, power, circuit IDs and providers.
- Intent: what something should be, who owns it, which site a device belongs to beyond the
  inventory.
- Very large tables on production gear: there is no size gate yet. A core with a full internet
  routing table will commit every route in `show ip route vrf *`; run `--no-state` or a longer
  timeout if a run gets slow, and tell the maintainer.
