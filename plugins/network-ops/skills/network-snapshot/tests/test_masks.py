"""The masks and strip rules that keep the committed set quiet: two runs on an unchanged network
must save the same text, and a real change must still show. Text from lab v2 (IOL IOS-XE 17.16)
unless a test says otherwise. Run: python -m pytest plugins (repo root)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import snapshot  # noqa: E402

IOS = snapshot.load_profile("cisco_ios")
FGT = snapshot.load_profile("fortinet")


def same(before, after, prof=IOS, cmd=None):
    return snapshot.normalize(before, prof, cmd) == snapshot.normalize(after, prof, cmd)


def test_lldp_hold_timer_is_stripped():
    a = "Local Intf: Et0/1\nPort id: Et1/0\nTime remaining: 108 seconds\nSystem Name: hq-dist-sw-01.gtt.lab\n"
    assert same(a, a.replace("108", "95"), cmd="show lldp neighbors detail")
    assert not same(a, a.replace("Et1/0", "Et1/1"), cmd="show lldp neighbors detail")


def test_ospf_interface_flood_scan_and_hello_timer_are_masked():
    a = ("Vlan30 is up, line protocol is up \n  Internet Address 10.30.0.2/24, Interface ID 16, Area 0\n"
         "    Hello due in 00:00:03\n  Index 1/4/4, flood queue length 0\n  Next 0x0(0)/0x0(0)/0x0(0)\n"
         "  Last flood scan length is 0, maximum is 0\n  Last flood scan time is 0 msec, maximum is 0 msec\n"
         "  Neighbor Count is 1, Adjacent neighbor count is 1 \n")
    b = (a.replace("00:00:03", "00:00:07").replace("queue length 0", "queue length 2")
         .replace("length is 0, maximum is 0", "length is 1, maximum is 3")
         .replace("Next 0x0(0)/0x0(0)/0x0(0)", "Next 0x7F1(2)/0x0(0)/0x0(0)"))
    assert same(a, b)
    assert not same(a, a.replace("Neighbor Count is 1, Adjacent neighbor count is 1",
                                 "Neighbor Count is 0, Adjacent neighbor count is 0"))


def test_bgp_all_summary_counters_are_masked_but_state_is_kept():
    a = ("For address family: IPv4 Unicast\nBGP table version is 5, main routing table version 5\n"
         "Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n"
         "198.51.100.1    4        64500   21896   21913        5    0    0 1w6d            3\n")
    b = a.replace("21896   21913        5", "21950   21961        7").replace("version 5", "version 7")
    assert same(a, b)
    assert same(a, a.replace("1w6d            3", "23:59:59        3"))      # age changes width
    assert not same(a, a.replace("1w6d            3", "1w6d            4"))      # prefix count
    assert not same(a, a.replace("1w6d            3", "00:00:12 Idle"))         # session down


def test_bgp_all_summary_ipv6_neighbor_on_a_wrapped_line():
    # IOS wraps a long neighbor address (format from Cisco documentation)
    a = ("For address family: IPv6 Unicast\n2001:DB8::1\n"
         "                4        64500     120     118       10    0    0 01:02:03        2\n")
    assert same(a, a.replace("120     118       10", "130     129       12").replace("01:02:03", "01:12:03"))
    assert not same(a, a.replace("        2\n", "        5\n"))


def test_lacp_partner_age_is_masked():
    # format from Cisco documentation (no LACP bundles in the lab)
    a = ("Port      Flags   Priority  Dev ID          Age    key    Key    Number  State\n"
         "Gi1/0/1   SA      32768     0011.2233.4455  25s    0x0    0x1    0x101   0x3D\n")
    assert same(a, a.replace("25s ", "3s  "))
    assert not same(a, a.replace("0011.2233.4455", "0011.2233.9999"))


def test_route_ages_in_every_vrf_are_masked():
    a = ("Routing Table: MGMT\nS*    0.0.0.0/0 [1/0] via 192.168.1.1\n"
         "O        10.20.0.0/24 [110/2] via 10.0.0.1, 00:41:07, Ethernet0/1\n"
         "O        10.30.0.0/24 [110/2] via 10.0.0.1, 2w0d, Ethernet0/1\n")
    assert same(a, a.replace("00:41:07", "00:43:09").replace("2w0d", "2w1d"))
    assert not same(a, a.replace("via 10.0.0.1, 00:41:07", "via 10.0.0.5, 00:41:07"))


def test_fortigate_ospf_dead_time_is_masked():
    a = "OSPF process 0, VRF 0:\nNeighbor ID     Pri   State           Dead Time   Address         Interface\n10.255.0.1        1   Full/DR         00:00:35    10.0.1.1        port2\n"
    assert same(a, a.replace("00:00:35", "00:00:31"), prof=FGT)


def test_fortigate_route_age_with_weeks_is_masked():
    # FortiOS 8.0.1 lab: the age rolled from 01w6d19h to 01w6d20h between two runs
    a = "O       10.0.0.4/30 [110/11] via 10.0.0.14, port3, 01w6d19h, [1/0]\nC       10.0.0.12/30 is directly connected, port3, 01w6d19h\n"
    assert same(a, a.replace("01w6d19h", "01w6d20h"), prof=FGT)
    assert same(a, a.replace("01w6d19h", "02w0d00h"), prof=FGT)
    assert not same(a, a.replace("via 10.0.0.14", "via 10.0.0.18"), prof=FGT)


def test_no_data_markers_match_missing_tables_not_show_boot():
    # lab: show boot prints "BOOT variable does not exist" next to real data (config register)
    assert not snapshot.is_no_data("BOOT variable does not exist\nConfiguration register is 0x0\n", IOS)
    assert snapshot.is_no_data("% IPv6 routing table MGMT does not exist\n", IOS)
    assert snapshot.is_no_data("% IPv6 routing table * does not exist\n", IOS)
    assert snapshot.is_no_data("% VRF RED does not exist\n", IOS)
    assert snapshot.is_no_data("% BGP not active\n", IOS)
