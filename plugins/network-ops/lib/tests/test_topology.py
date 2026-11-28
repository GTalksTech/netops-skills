"""Topology from saved show output: parsers, neighbor / subnet / tunnel links, port-channels,
unknown neighbors, unlinked devices and spreadsheet links (lib/topology)."""
import sys
import textwrap
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import topology  # noqa: E402
import topo_fixture  # noqa: E402
from topology import parsers as p  # noqa: E402


def topo_of(tmp_path, **kw):
    repo = topo_fixture.build(tmp_path)
    inv = yaml.safe_load((repo / "inventory.yaml").read_text(encoding="utf-8"))
    t = topology.read_snapshot(repo, inv, **kw)
    return topology.build_links(t)


def link(t, a, b):
    found = [l for l in t["links"] if {l["a"], l["b"]} == {a, b}]
    assert len(found) == 1, f"{a} - {b}: {found}"
    return found[0]


# ---------- parsers ----------
def test_names():
    assert p.norm_intf("Gi1/0/1") == "GigabitEthernet1/0/1"
    assert p.norm_intf("Et0/1") == "Ethernet0/1"
    assert p.short_intf("Port-channel1") == "Po1"
    assert p.short_host("core-sw-01.lab.example") == "core-sw-01"
    assert p.short_host("192.0.2.1") == "192.0.2.1"


def test_lldp_off_reads_nothing():
    assert p.lldp("% LLDP is not enabled") == []
    assert p.lldp_enabled("% LLDP is not enabled") is False


def test_lldp_arista_style():
    text = textwrap.dedent("""
        Interface Ethernet1 detected 1 LLDP neighbors:
          Neighbor 001c.7300.0001/"Ethernet2", age 12 seconds
          - Port ID     : "Ethernet2"
          - System Name: "leaf-02.lab"
        """)
    assert p.lldp(text) == [{"remote": "leaf-02", "local_intf": "Ethernet1", "remote_intf": "Ethernet2", "platform": ""}]


def test_vlan_brief_wrapped_ports_and_reserved_vlans():
    v = p.vlans(textwrap.dedent(topo_fixture.FILES[("hq", "dist-sw-01")]["show-vlan-brief.txt"]))
    assert sorted(v) == [1, 10, 20]                       # 1002 left out
    assert v[10]["ports"][-1] == "Ethernet3/0"            # from the continuation line
    assert len(v[10]["ports"]) == 5


def test_trunk_allowed_and_native():
    t = p.trunks(textwrap.dedent(topo_fixture.FILES[("hq", "dist-sw-01")]["show-interfaces-trunk.txt"]))
    assert t == {"Ethernet1/0": {"native": "99", "allowed": "10,20"}}


def test_etherchannel_members():
    e = p.etherchannels(textwrap.dedent(topo_fixture.FILES[("hq", "core-sw-01")]["show-etherchannel-summary.txt"]))
    assert e == {"Port-channel1": {"protocol": "LACP", "flags": "SU", "members": ["Ethernet0/1", "Ethernet0/2"]}}


def test_fortios_ips_ignore_nested_config():
    ips = p.fortios_ips(textwrap.dedent(topo_fixture.FILES[("hq", "fw-01")]["show.txt"]))
    assert sorted(ips) == ["port1", "port2", "port3"]
    assert p.fortios_descriptions(textwrap.dedent(topo_fixture.FILES[("hq", "fw-01")]["show.txt"])) == {"port2": "outside"}


# ---------- links ----------
def test_subnet_links_find_what_discovery_cannot(tmp_path):
    t = topo_of(tmp_path)
    fw_edge = link(t, "fw-01", "edge-rtr-01")
    assert fw_edge["kind"] == topology.SUBNET and fw_edge["note"] == "198.51.100.8/30"
    assert link(t, "fw-01", "core-sw-01")["kind"] == topology.SUBNET
    assert link(t, "br1-rtr-01", "edge-rtr-01")["kind"] == topology.TUNNEL


def test_management_vrf_and_lans_make_no_links(tmp_path):
    t = topo_of(tmp_path)
    assert not [l for l in t["links"] if "192.168.1" in l["note"]]


def test_port_channel_is_one_link_listing_members(tmp_path):
    l = link(topo_of(tmp_path), "core-sw-01", "dist-sw-01")
    assert (l["a_intf"], l["b_intf"]) == ("Port-channel1", "Port-channel1")
    assert sorted(l["members"]) == [("Ethernet0/1", "Ethernet0/1"), ("Ethernet0/2", "Ethernet0/2")]
    assert l["kind"] == topology.NEIGHBOR


def test_lldp_link_and_unknown_neighbor(tmp_path):
    t = topo_of(tmp_path)
    assert link(t, "dist-sw-01", "acc-sw-01")["sources"] == {topology.NEIGHBOR}
    assert t["unknown_neighbors"] == ["mystery-ap"]
    assert t["devices"]["mystery-ap"]["in_inventory"] is False


def test_unlinked_device_is_kept(tmp_path):
    t = topo_of(tmp_path)
    assert topology.unlinked(t) == ["lonely-sw-01"]
    assert "lonely-sw-01" in t["devices"]


def test_roles_from_inventory_name_and_platform(tmp_path):
    d = topo_of(tmp_path)["devices"]
    assert (d["core-sw-01"]["role"], d["core-sw-01"]["role_source"]) == ("core", "inventory")
    assert d["dist-sw-01"]["role"] == "distribution" and "guessed" in d["dist-sw-01"]["role_source"]
    assert d["fw-01"]["role"] == "firewall"
    assert d["lonely-sw-01"]["role"] is None


def test_no_subnet_leaves_firewall_unlinked(tmp_path):
    repo = topo_fixture.build(tmp_path)
    t = topology.build_links(topology.read_snapshot(repo), subnets=False)
    assert "fw-01" in topology.unlinked(t)


def test_site_filter(tmp_path):
    t = topo_of(tmp_path, site="br1")
    assert sorted(t["devices"]) == ["br1-rtr-01", "lonely-sw-01"]


def test_device_without_cdp_or_lldp_is_a_gap(tmp_path):
    gaps = {g["device"]: g["gap"] for g in topo_of(tmp_path)["gaps"]}
    assert "no CDP or LLDP" in gaps["fw-01"]


# ---------- spreadsheet ----------
def test_csv_without_header(tmp_path):
    f = tmp_path / "links.csv"
    f.write_text("sw-a,Gi1/0/1,Gi1/0/2,sw-b\n", encoding="utf-8")
    t = topology.new()
    assert topology.read_csv(t, f) == 1
    l = t["links"][0]
    assert (l["a"], l["a_intf"], l["b_intf"], l["b"]) == ("sw-a", "GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "sw-b")


def test_csv_header_and_optional_columns(tmp_path):
    f = tmp_path / "links.csv"
    f.write_text("Site,Device A,Port A,Port B,Device B,VLAN,Description\n"
                 "hq,sw-a,Gi1/0/1,Gi1/0/2,sw-b,10,uplink\n", encoding="utf-8")
    t = topology.new()
    topology.read_csv(t, f)
    assert t["links"][0]["note"] == "uplink | VLAN 10"
    assert t["devices"]["sw-a"]["site"] == "hq"


def test_csv_row_without_ports_joins_existing_link(tmp_path):
    t = topo_of(tmp_path)
    f = tmp_path / "links.csv"
    f.write_text("fw-01,,,edge-rtr-01\n", encoding="utf-8")
    topology.read_csv(t, f)
    assert link(t, "fw-01", "edge-rtr-01")["sources"] == {topology.SUBNET, topology.SPREADSHEET}
