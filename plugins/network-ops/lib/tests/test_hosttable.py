"""hosttable: one row per host a snapshot saw, joined from ARP, MAC table, neighbors and DHCP,
each row naming the tables that showed it. Run: python -m pytest plugins (repo root)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import hosttable  # noqa: E402

ARP_HEAD = "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
MAC_HEAD = "Vlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n"
TRUNK = "\nPort           Mode             Encapsulation  Status        Native vlan\nEt0/1          on               802.1q         trunking      1\n"
SNOOP = ("MacAddress          IpAddress        Lease(sec)  Type           VLAN  Interface\n"
         "00:50:56:B3:A2:C7   10.10.0.50       86017       dhcp-snooping   10    GigabitEthernet1/0/7\n")
CDP_TO_DIST = ("-------------------------\nDevice ID: dist.lab\n"
               "Interface: Ethernet0/1,  Port ID (outgoing port): Ethernet1/0\n")


def out(cmd, text, vrf=None):
    return {"cmd": cmd, "vrf": vrf, "text": text}


DIST = {"name": "dist", "platform": "cisco_ios", "outputs": [
    out("show ip arp", ARP_HEAD
        + "Internet  10.10.0.1               -   0000.0c9f.f00a  ARPA   Vlan10\n"
        + "Internet  10.10.0.2               -   aabb.cc80.7700  ARPA   Vlan10\n"
        + "Internet  10.10.0.50              3   0050.56b3.a2c7  ARPA   Vlan10\n"),
    out("show ip arp vrf MGMT", ARP_HEAD + "Internet  192.168.1.86           20   2ccf.67e4.7b2a  ARPA   Ethernet0/0\n", "MGMT"),
    out("show interfaces trunk", TRUNK),
    out("show mac address-table", MAC_HEAD + "  10    0050.56b3.a2c7    DYNAMIC     Et0/1\n"),
]}
ACC = {"name": "acc", "platform": "cisco_ios", "outputs": [
    out("show mac address-table", MAC_HEAD
        + "  10    0050.56b3.a2c7    DYNAMIC     Gi1/0/7\n"
        + "  20    aabb.cc80.7700    DYNAMIC     Et0/1\n"  # an SVI MAC, seen in another VLAN
        + "  20    dead.beef.0001    DYNAMIC     Gi1/0/9\n"
        + "  30    cafe.0000.0001    DYNAMIC     Et0/1\n"),
    out("show interfaces trunk", TRUNK),
    out("show cdp neighbors detail", CDP_TO_DIST),
    out("show ip dhcp snooping binding", SNOOP),
]}
EDGE = {"name": "edge", "platform": "cisco_ios", "outputs": [
    out("show ip arp vrf MGMT", ARP_HEAD + "Internet  192.168.1.86           15   2ccf.67e4.7b2a  ARPA   Ethernet0/0\n", "MGMT"),
]}


def rows_by_key():
    return {(r["ip"], r["mac"]): r for r in hosttable.build([DIST, ACC, EDGE])}


def test_host_on_an_edge_port_joins_arp_snooping_and_mac_table():
    r = rows_by_key()[("10.10.0.50", "0050.56b3.a2c7")]
    assert (r["vrf"], r["vlan"], r["device"], r["port"], r["kind"]) == ("default", "10", "acc", "Gi1/0/7", "host")
    assert r["sources"] == "arp:dist; dhcp-snoop:acc:Gi1/0/7; mac:acc:Gi1/0/7; mac:dist:Et0/1"
    assert r["note"] == ""


def test_host_with_no_mac_table_entry_has_no_port_and_says_where_arp_learned_it():
    r = rows_by_key()[("192.168.1.86", "2ccf.67e4.7b2a")]
    assert (r["vrf"], r["device"], r["port"], r["kind"]) == ("MGMT", "", "", "host")
    assert r["sources"] == "arp:dist; arp:edge"
    assert r["note"] == "no MAC table entry; ARP on dist Et0/0, edge Et0/0"


def test_mac_seen_only_on_uplinks_gets_no_port():
    r = rows_by_key()[("", "cafe.0000.0001")]
    assert (r["vlan"], r["device"], r["port"]) == ("30", "", "")
    assert r["note"] == "seen only on uplinks: acc Et0/1"


def test_mac_on_an_edge_port_with_no_ip_is_still_a_row():
    r = rows_by_key()[("", "dead.beef.0001")]
    assert (r["vlan"], r["device"], r["port"], r["sources"]) == ("20", "acc", "Gi1/0/9", "mac:acc:Gi1/0/9")


def test_device_own_addresses_and_fhrp_macs_are_marked_not_hosts():
    rows = rows_by_key()
    own = rows[("10.10.0.2", "aabb.cc80.7700")]
    assert (own["kind"], own["device"], own["port"]) == ("network-device", "dist", "Vl10")
    assert own["sources"] == "arp-self:dist; mac:acc:Et0/1"
    assert rows[("10.10.0.1", "0000.0c9f.f00a")]["kind"] == "virtual"


def test_nothing_is_invented():
    rows = hosttable.build([DIST, ACC, EDGE])
    assert len(rows) == 6
    seen = {r["mac"] for r in rows}
    assert seen == {"0000.0c9f.f00a", "aabb.cc80.7700", "0050.56b3.a2c7", "2ccf.67e4.7b2a",
                    "cafe.0000.0001", "dead.beef.0001"}
    assert hosttable.build([]) == []


def test_rows_are_ordered_vrf_then_ip_then_mac_only_rows():
    order = [(r["vrf"], r["ip"], r["mac"]) for r in hosttable.build([EDGE, ACC, DIST])]
    assert order == [
        ("default", "10.10.0.1", "0000.0c9f.f00a"), ("default", "10.10.0.2", "aabb.cc80.7700"),
        ("default", "10.10.0.50", "0050.56b3.a2c7"), ("MGMT", "192.168.1.86", "2ccf.67e4.7b2a"),
        ("", "", "cafe.0000.0001"), ("", "", "dead.beef.0001")]


def test_fortigate_arp_feeds_the_table():
    fw = {"name": "fw", "platform": "fortinet", "outputs": [out("get system arp",
          "Address           Age(min)   Hardware Addr      Interface\n192.168.1.1       0          9e:05:d6:bb:a6:0b port1\n")]}
    [r] = hosttable.build([fw])
    assert (r["ip"], r["mac"], r["vrf"], r["sources"]) == ("192.168.1.1", "9e05.d6bb.a60b", "default", "arp:fw")


def test_csv_round_trip_and_change_list(tmp_path):
    rows = hosttable.build([DIST, ACC, EDGE])
    path = tmp_path / "hosts.csv"
    hosttable.write_csv(rows, path)
    assert path.read_text().splitlines()[0] == "ip,mac,vrf,vlan,device,port,kind,sources,note"
    assert hosttable.read_csv(path) == rows
    fewer = [r for r in rows if r["mac"] != "dead.beef.0001"]
    changes = hosttable.compare(rows, fewer)
    assert changes == {"new": [], "gone": ["- dead.beef.0001"]}
    assert hosttable.compare(fewer, rows)["new"] == ["- dead.beef.0001"]
    assert hosttable.compare([], rows[:1])["new"] == ["10.10.0.1 0000.0c9f.f00a vrf default"]
    assert hosttable.compare(None, rows) is None


def test_a_fortigate_interface_address_seen_in_a_cisco_arp_table_is_that_firewall():
    core = {"name": "core", "platform": "cisco_ios", "outputs": [out("show ip arp", ARP_HEAD
            + "Internet  10.0.0.13             12   000c.29de.812b  ARPA   Ethernet0/1\n")]}
    fw = {"name": "fw", "platform": "fortinet", "outputs": [out("get system interface",
          "== [ port3 ]\nname: port3   mode: static    ip: 10.0.0.13 255.255.255.252   status: up\n"
          "== [ port1 ]\nname: port1   mode: static    ip: 192.168.1.242 255.255.255.0   status: up\n")]}
    rows = {r["ip"]: r for r in hosttable.build([core, fw])}
    r = rows["10.0.0.13"]
    assert (r["mac"], r["kind"], r["device"], r["port"]) == ("000c.29de.812b", "network-device", "fw", "port3")
    assert r["sources"] == "arp:core; if-self:fw"
    assert (rows["192.168.1.242"]["mac"], rows["192.168.1.242"]["sources"]) == ("", "if-self:fw")


def test_an_svi_address_takes_its_vlan_from_the_interface_not_from_mac_sightings():
    r = rows_by_key()[("10.10.0.2", "aabb.cc80.7700")]
    assert r["vlan"] == "10"


def test_a_cdp_neighbor_in_the_run_is_named_as_the_inventory_names_it():
    sw = {"name": "acc", "platform": "cisco_ios", "outputs": [
        out("show cdp neighbors detail", "Device ID: dist.lab\nInterface: Ethernet0/1,  Port ID (outgoing port): Ethernet1/0\n"
            "Peer Source MAC: aabb.cc00.7701\n"),
        out("show mac address-table", MAC_HEAD + "  10    aabb.cc00.7701    DYNAMIC     Et0/1\n")]}
    [r] = hosttable.build([sw, {"name": "dist", "platform": "cisco_ios", "outputs": []}])
    assert (r["mac"], r["kind"], r["device"], r["port"], r["note"]) == (
        "aabb.cc00.7701", "network-device", "dist", "Et1/0", "neighbor from CDP/LLDP")


def test_a_phone_or_ap_neighbor_does_not_turn_its_port_into_an_uplink():
    sw = {"name": "acc", "platform": "cisco_ios", "outputs": [
        out("show cdp neighbors detail", "Device ID: SEP001122334455\nPlatform: Cisco IP Phone 8845,  Capabilities: Host Phone Two-port Mac Relay \n"
            "Interface: GigabitEthernet1/0/7,  Port ID (outgoing port): Port 1\n"),
        out("show mac address-table", MAC_HEAD + "  10    0050.56b3.a2c7    DYNAMIC     Gi1/0/7\n")]}
    [r] = hosttable.build([sw])
    assert (r["device"], r["port"], r["kind"]) == ("acc", "Gi1/0/7", "host")


def test_device_text_cannot_become_a_spreadsheet_formula(tmp_path):
    rows = [{"ip": "", "mac": "", "vrf": "", "vlan": "", "device": "=HYPERLINK(\"x\")", "port": "+1",
             "kind": "network-device", "sources": "@x", "note": "-2"}]
    p = tmp_path / "h.csv"
    hosttable.write_csv(rows, p)
    line = p.read_text().splitlines()[1]
    assert "'=HYPERLINK" in line and ",'+1," in line and "'@x" in line and line.endswith("'-2")
