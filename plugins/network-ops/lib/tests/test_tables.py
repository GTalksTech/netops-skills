"""devicefacts.tables: host and link tables read from saved show output.
Inputs are real output from lab v2 (IOL IOS-XE 17.16, FortiGate-VM 8.0.1), 2026-11-28, unless
the test says otherwise. Run: python -m pytest plugins (repo root)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from devicefacts import tables  # noqa: E402

IOS_ARP = """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.0.0.5              116   aabb.cc00.7420  ARPA   Ethernet0/1
Internet  10.0.0.6                -   aabb.cc00.7710  ARPA   Ethernet0/1
Internet  10.10.0.1               -   0000.0c9f.f00a  ARPA   Vlan10
Internet  10.10.0.9               0   Incomplete      ARPA
"""

IOS_MAC = """          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0100.0ccc.cccc    STATIC      CPU
  10    0000.0c9f.f00a    DYNAMIC     Et0/1
  20    aabb.cc00.7801    DYNAMIC     Et0/2
Total Mac Addresses for this criterion: 3
"""

IOS_TRUNK = """
Port           Mode             Encapsulation  Status        Native vlan
Et0/1          on               802.1q         trunking      1
Po1            on               802.1q         trunking      1

Port           Vlans allowed on trunk
Et0/1          10,20,30
Po1            10,20,30
"""

IOS_CDP = """-------------------------
Device ID: hq-dist-sw-02.gtt.lab
Entry address(es):
  IP address: 10.10.0.3
Platform: Linux Unix,  Capabilities: Router Switch IGMP
Interface: Ethernet0/2,  Port ID (outgoing port): Ethernet1/0
Holdtime : 160 sec
Peer Source MAC: aabb.cc00.7801
"""

IOS_LLDP = """------------------------------------------------
Local Intf: Et0/1
Local Intf service instance: -
Chassis id: aabb.cc00.7700
Port id: Et1/0
Port Description: TO hq-acc-sw-01 Eth0/1
System Name: hq-dist-sw-01.gtt.lab
Peer Source MAC: aabb.cc00.7701
"""

# Format from Cisco documentation (no snooping bindings exist in the lab).
IOS_SNOOP = """MacAddress          IpAddress        Lease(sec)  Type           VLAN  Interface
------------------  ---------------  ----------  -------------  ----  --------------------
00:50:56:B3:A2:C7   10.10.0.50       86017       dhcp-snooping   10    GigabitEthernet1/0/7
Total number of bindings: 1
"""

# Format from Cisco documentation (no DHCP server leases exist in the lab).
IOS_DHCP = """Bindings from all pools not associated with VRF:
IP address      Client-ID/              Lease expiration        Type       State      Interface
                Hardware address/
                User name
10.20.0.11      0100.5056.b3a2.c8       Dec 01 2026 10:00 AM    Automatic  Active     Vlan20
10.20.0.12      0063.6973.636f.2d61.    Dec 01 2026 10:05 AM    Automatic  Active     Vlan20
"""

FGT_ARP = """Address           Age(min)   Hardware Addr      Interface
192.168.1.1       0          9e:05:d6:bb:a6:0b port1
10.0.0.1          3          aa:bb:cc:00:73:10 port2
"""


def test_mac_forms_normalize_to_cisco_dotted_lower_case():
    assert tables.norm_mac("00:50:56:B3:A2:C7") == "0050.56b3.a2c7"
    assert tables.norm_mac("0050.56b3.a2c7") == "0050.56b3.a2c7"
    assert tables.norm_mac("00-50-56-b3-a2-c7") == "0050.56b3.a2c7"
    assert tables.norm_mac("Incomplete") is None


def test_interface_names_shorten_the_same_way_in_every_table():
    assert tables.short_if("Ethernet0/1") == "Et0/1"
    assert tables.short_if("Et0/1") == "Et0/1"
    assert tables.short_if("GigabitEthernet1/0/7") == "Gi1/0/7"
    assert tables.short_if("TenGigabitEthernet1/1/1") == "Te1/1/1"
    assert tables.short_if("Port-channel1") == "Po1"
    assert tables.short_if("Vlan10") == "Vl10"
    assert tables.short_if("port1") == "port1"


def test_ios_arp_rows_mark_own_addresses_and_skip_incomplete():
    rows = tables.ios_arp(IOS_ARP)
    assert [(r["ip"], r["mac"], r["interface"], r["own"]) for r in rows] == [
        ("10.0.0.5", "aabb.cc00.7420", "Et0/1", False),
        ("10.0.0.6", "aabb.cc00.7710", "Et0/1", True),
        ("10.10.0.1", "0000.0c9f.f00a", "Vl10", True),
    ]


def test_ios_mac_table_skips_cpu_entries():
    assert tables.ios_mac_table(IOS_MAC) == [
        {"vlan": "10", "mac": "0000.0c9f.f00a", "type": "DYNAMIC", "port": "Et0/1"},
        {"vlan": "20", "mac": "aabb.cc00.7801", "type": "DYNAMIC", "port": "Et0/2"},
    ]


def test_ios_trunk_ports_come_from_the_first_section_only():
    assert tables.ios_trunks(IOS_TRUNK) == {"Et0/1", "Po1"}


def test_cdp_and_lldp_neighbors_give_local_port_name_and_mac():
    assert tables.ios_cdp(IOS_CDP) == [
        {"local_port": "Et0/2", "name": "hq-dist-sw-02.gtt.lab", "remote_port": "Et1/0",
         "macs": ["aabb.cc00.7801"], "network": True}]
    assert tables.ios_lldp(IOS_LLDP) == [
        {"local_port": "Et0/1", "name": "hq-dist-sw-01.gtt.lab", "remote_port": "Et1/0",
         "macs": ["aabb.cc00.7700", "aabb.cc00.7701"], "network": True}]


def test_dhcp_snooping_binding():
    assert tables.ios_snooping(IOS_SNOOP) == [
        {"mac": "0050.56b3.a2c7", "ip": "10.10.0.50", "vlan": "10", "port": "Gi1/0/7"}]


def test_dhcp_server_binding_reads_mac_only_from_a_hardware_client_id():
    assert tables.ios_dhcp_binding(IOS_DHCP) == [
        {"ip": "10.20.0.11", "mac": "0050.56b3.a2c8", "interface": "Vl20"},
        {"ip": "10.20.0.12", "mac": None, "interface": "Vl20"},
    ]


def test_fortios_arp():
    assert tables.fortios_arp(FGT_ARP) == [
        {"ip": "192.168.1.1", "mac": "9e05.d6bb.a60b", "age": "0", "interface": "port1", "own": False},
        {"ip": "10.0.0.1", "mac": "aabb.cc00.7310", "age": "3", "interface": "port2", "own": False},
    ]


def test_empty_or_rejected_output_gives_no_rows():
    for fn in (tables.ios_arp, tables.ios_mac_table, tables.ios_snooping, tables.ios_dhcp_binding,
               tables.ios_cdp, tables.ios_lldp, tables.fortios_arp):
        assert fn("% Invalid input detected at '^' marker.\n") == []
        assert fn("") == []
    assert tables.ios_trunks("") == set()


FGT_IFACES = """== [ port1 ]
name: port1   mode: static    ip: 192.168.1.242 255.255.255.0   status: up    netbios-forward: disable    type: physical
== [ port3 ]
name: port3   mode: static    ip: 10.0.0.13 255.255.255.252   status: up    type: physical
== [ naf.root ]
name: naf.root   ip: 0.0.0.0 0.0.0.0   status: up    netbios-forward: disable    type: tunnel
"""


def test_fortios_interface_addresses_skip_unnumbered():
    assert tables.fortios_interfaces(FGT_IFACES) == [
        {"name": "port1", "ip": "192.168.1.242"}, {"name": "port3", "ip": "10.0.0.13"}]
    assert tables.fortios_interfaces("") == []


def test_neighbor_capabilities_say_whether_it_is_a_network_device():
    assert tables.ios_cdp(IOS_CDP)[0]["network"] is True
    assert tables.ios_lldp(IOS_LLDP + "Enabled Capabilities: B,R\n")[0]["network"] is True
    phone = "Device ID: SEP0011\nPlatform: Cisco IP Phone,  Capabilities: Host Phone \nInterface: Gi1/0/7,  Port ID (outgoing port): Port 1\n"
    assert tables.ios_cdp(phone)[0]["network"] is False
    assert tables.ios_lldp("Local Intf: Gi1/0/8\nSystem Name: ap1\nEnabled Capabilities: W\n")[0]["network"] is False
    assert tables.ios_lldp("Local Intf: Gi1/0/9\n")[0]["network"] is True   # unknown: treated as an uplink
