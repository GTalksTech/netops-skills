# Tests for ios_l2.py (R6): BPDU guard, DHCP snooping, DAI, port security / 802.1X, unused ports,
# DTP, trunk native and allowed VLANs, VTP password and HSRP / VRRP / GLBP authentication, with
# the config defaults, the show-output parsers, and the results on the sanitized lab v2 access
# and distribution switches.
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import ios_l2  # noqa: E402
import vendor_ios  # noqa: E402

LAB = HERE / "fixtures" / "lab-v2"

# A hardened access switch: every R6 check passes on it.
GOOD = """version 17.16
hostname acc1
vtp mode transparent
ip dhcp snooping vlan 10
ip dhcp snooping
ip arp inspection vlan 10
spanning-tree mode rapid-pvst
spanning-tree portfast bpduguard default
vlan 10
 name USERS
vlan 99
 name NATIVE
vlan 999
 name PARKED
interface GigabitEthernet1/0/1
 description uplink
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,99
 switchport mode trunk
 switchport nonegotiate
 ip dhcp snooping trust
interface GigabitEthernet1/0/2
 switchport access vlan 10
 switchport mode access
 switchport port-security
 spanning-tree portfast
interface GigabitEthernet1/0/3
 switchport access vlan 10
 switchport mode access
 authentication port-control auto
 dot1x pae authenticator
 mab
 spanning-tree portfast
interface GigabitEthernet1/0/4
 switchport access vlan 999
 switchport mode access
 shutdown
interface Vlan10
 ip address 10.10.0.2 255.255.255.0
 standby 10 ip 10.10.0.1
 standby 10 authentication md5 key-chain HSRP-KC
"""


def _res(cfg, folder=None, switch=False):
    dev = {"_folder": str(folder)} if folder else {}
    if switch:
        dev["_is_switch"] = True
    facts, _ = vendor_ios.analyze(cfg, dev)
    return {r["check"]: r for r in facts["results"] if r["check"] in ios_l2.CHECKS}


def _st(cfg, check, folder=None):
    return _res(cfg, folder)[check]["status"]


def _sw(body, head="version 17.16\nhostname s1\nvtp mode transparent\nspanning-tree mode rapid-pvst\n"):
    return head + body


def test_parsers():
    assert ios_l2.short("GigabitEthernet1/0/1") == "Gi1/0/1"
    assert ios_l2.short("Ethernet0/3") == "Et0/3"
    assert ios_l2.short("TenGigabitEthernet1/1/1") == "Te1/1/1"
    assert ios_l2.vlan_set("10,20-22") == {10, 20, 21, 22}
    assert ios_l2.vlan_set("ALL") == set(ios_l2.ALL_VLANS)
    assert ios_l2.vlan_text({10, 20, 21, 22}) == "10,20-22"
    st = ios_l2.parse_status("Port         Name               Status       Vlan       Duplex  Speed Type\n"
                             "Et0/0        MGMT | lab LAN via connected    routed       full   auto x\n"
                             "Et0/3        UNUSED             disabled     999          full   auto x\n"
                             "Et1/0                           notconnect   1            auto   auto x\n")
    assert st == {"Et0/0": "connected", "Et0/3": "disabled", "Et1/0": "notconnect"}
    sw = ios_l2.parse_switchport("Name: Et0/1\nSwitchport: Enabled\nAdministrative Mode: trunk\n"
                                 "Negotiation of Trunking: On\nTrunking Native Mode VLAN: 1 (default)\n")
    assert sw["Et0/1"]["Negotiation of Trunking"] == "On"
    assert ios_l2.parse_vtp_mode("VTP Operating Mode                : Transparent") == "transparent"
    assert ios_l2.parse_vlan_names("10   USERS      active    Et0/3\n30   SERVERS   active\n") == {
        10: "USERS", 30: "SERVERS"}


def test_good_switch_passes_everything():
    res = _res(GOOD)
    assert {c: r["status"] for c, r in res.items()} == {c: "pass" for c in ios_l2.CHECKS}
    assert not any(r["exposed"] for r in res.values())


def test_router_without_switchports_is_na():
    cfg = "version 17.16\nhostname r1\ninterface GigabitEthernet1\n ip address 10.0.0.1 255.255.255.0\n" \
          "interface GigabitEthernet2\n shutdown\nrouter ospf 1\nline vty 0 4\n transport input ssh\n"
    res = _res(cfg)
    assert {c for c, r in res.items() if r["status"] == "n/a"} == set(ios_l2.CHECKS)


def test_bpduguard():
    base = " switchport access vlan 10\n switchport mode access\n"
    no_pf = _sw(f"spanning-tree portfast bpduguard default\ninterface Gi1/0/1\n{base}")
    assert _st(no_pf, "IOS-L2-BPDUGUARD") == "fail"            # default only covers portfast ports
    pf_default = _sw(f"spanning-tree portfast default\nspanning-tree portfast bpduguard default\n"
                     f"interface Gi1/0/1\n{base}")
    assert _st(pf_default, "IOS-L2-BPDUGUARD") == "pass"
    per_port = _sw(f"interface Gi1/0/1\n{base} spanning-tree bpduguard enable\n")
    assert _st(per_port, "IOS-L2-BPDUGUARD") == "pass"
    disabled = _sw(f"spanning-tree portfast bpduguard default\ninterface Gi1/0/1\n{base} spanning-tree portfast\n"
                   " spanning-tree bpduguard disable\n")
    r = _res(disabled)["IOS-L2-BPDUGUARD"]
    assert r["status"] == "fail" and "bpduguard disable" in r["detail"]
    nothing = _sw(f"interface Gi1/0/1\n{base} spanning-tree portfast\n")
    assert _st(nothing, "IOS-L2-BPDUGUARD") == "fail"
    shut = _sw(f"interface Gi1/0/1\n{base} shutdown\n")
    assert _st(shut, "IOS-L2-BPDUGUARD") == "n/a"


def test_dhcp_snooping_and_dai():
    ports = ("vlan 30\n name SERVERS\ninterface Gi1/0/1\n switchport access vlan 10\n switchport mode access\n"
             "interface Gi1/0/2\n switchport access vlan 20\n switchport mode access\n"
             "interface Gi1/0/3\n switchport access vlan 30\n switchport mode access\n")
    none = _res(_sw(ports))
    assert none["IOS-L2-DHCP-SNOOPING"]["status"] == "fail"
    assert "no global 'ip dhcp snooping'" in none["IOS-L2-DHCP-SNOOPING"]["detail"]
    assert "server VLANs not graded: 30" in none["IOS-L2-DHCP-SNOOPING"]["detail"]
    assert none["IOS-L2-DAI"]["status"] == "fail"
    # vlan list without the global command is still a fail
    assert _st(_sw("ip dhcp snooping vlan 10,20\n" + ports), "IOS-L2-DHCP-SNOOPING") == "fail"
    part = _res(_sw("ip dhcp snooping\nip dhcp snooping vlan 10\nip arp inspection vlan 10\n" + ports))
    assert part["IOS-L2-DHCP-SNOOPING"]["status"] == "fail" and "VLAN(s) 20" in part["IOS-L2-DHCP-SNOOPING"]["detail"]
    full = _res(_sw("ip dhcp snooping\nip dhcp snooping vlan 10,20\nip arp inspection vlan 10-20\n" + ports))
    assert full["IOS-L2-DHCP-SNOOPING"]["status"] == "pass" and full["IOS-L2-DAI"]["status"] == "pass"
    servers_only = _sw("vlan 30\n name SERVERS\ninterface Gi1/0/3\n switchport access vlan 30\n"
                       " switchport mode access\n")
    assert _st(servers_only, "IOS-L2-DHCP-SNOOPING") == "n/a"
    # no access vlan line: VLAN 1, a user VLAN
    default = _res(_sw("interface Gi1/0/1\n switchport mode access\n"))
    assert "VLAN(s) 1:" in default["IOS-L2-DHCP-SNOOPING"]["detail"]


def test_port_auth():
    base = "interface Gi1/0/1\n switchport mode access\n"
    r = _res(_sw(base))["IOS-L2-PORT-AUTH"]
    assert r["status"] == "fail" and "NAC" in r["detail"]
    assert _st(_sw(base + " switchport port-security\n switchport port-security maximum 2\n"),
               "IOS-L2-PORT-AUTH") == "pass"
    assert _st(_sw(base + " access-session port-control auto\n"), "IOS-L2-PORT-AUTH") == "pass"
    assert _st(_sw(base + " mab\n"), "IOS-L2-PORT-AUTH") == "pass"


def test_unused_ports(tmp_path):
    trunk = "interface Gi1/0/48\n switchport mode trunk\n switchport nonegotiate\n"
    vlan1 = _res(_sw("interface Gi1/0/1\n switchport mode access\n shutdown\n"))["IOS-L2-UNUSED-PORTS"]
    assert vlan1["status"] == "fail" and "in VLAN 1" in vlan1["detail"]
    on_trunk = _res(_sw(trunk + "interface Gi1/0/1\n switchport access vlan 999\n switchport mode access\n"
                        " shutdown\n"))["IOS-L2-UNUSED-PORTS"]
    assert on_trunk["status"] == "fail" and "carried on a trunk" in on_trunk["detail"]
    parked = _sw(trunk + " switchport trunk allowed vlan 10\ninterface Gi1/0/1\n switchport access vlan 999\n"
                 " switchport mode access\n shutdown\n")
    assert _st(parked, "IOS-L2-UNUSED-PORTS") == "pass"
    # an idle port that is not shut down is only seen through show interfaces status
    idle = _sw("interface Gi1/0/1\n switchport access vlan 999\n switchport mode access\n")
    assert _st(idle, "IOS-L2-UNUSED-PORTS") == "n/a"
    (tmp_path / "show-interfaces-status.txt").write_text(
        "Port         Name               Status       Vlan       Duplex  Speed Type\n"
        "Gi1/0/1                         notconnect   999          auto   auto x\n", encoding="utf-8")
    r = _res(idle, tmp_path)["IOS-L2-UNUSED-PORTS"]
    assert r["status"] == "fail" and "not shut down (status notconnect)" in r["detail"]


def test_dtp_defaults_and_show_output(tmp_path):
    no_mode = _res(_sw("interface Gi1/0/1\n description printer\n"), switch=True)["IOS-L2-DTP"]
    assert no_mode["status"] == "fail" and "DTP is on by default" in no_mode["detail"]
    assert _st(_sw("interface Gi1/0/1\n switchport mode dynamic desirable\n"), "IOS-L2-DTP") == "fail"
    assert _st(_sw("interface Gi1/0/1\n switchport mode trunk\n"), "IOS-L2-DTP") == "fail"
    assert _st(_sw("interface Gi1/0/1\n switchport mode trunk\n switchport nonegotiate\n"), "IOS-L2-DTP") == "pass"
    # the saved show output is the truth: this platform reports negotiation off for the port
    (tmp_path / "show-interfaces-switchport.txt").write_text(
        "Name: Gi1/0/1\nSwitchport: Enabled\nAdministrative Mode: static access\nOperational Mode: static access\n"
        "Negotiation of Trunking: Off\nAccess Mode VLAN: 1 (default)\n", encoding="utf-8")
    assert _st(_sw("interface Gi1/0/1\n description printer\n"), "IOS-L2-DTP", tmp_path) == "pass"


def test_trunk_vlans():
    t = "interface Gi1/0/48\n switchport mode trunk\n switchport nonegotiate\n"
    r = _res(_sw(t))["IOS-L2-TRUNK-VLANS"]
    assert r["status"] == "fail" and "native VLAN 1 untagged" in r["detail"] and "all VLANs allowed" in r["detail"]
    assert _st(_sw(t + " switchport trunk native vlan 99\n switchport trunk allowed vlan 10,99\n"),
               "IOS-L2-TRUNK-VLANS") == "pass"
    assert _st(_sw("vlan dot1q tag native\n" + t + " switchport trunk allowed vlan 1,10\n"),
               "IOS-L2-TRUNK-VLANS") == "pass"
    user_native = _sw(t + " switchport trunk native vlan 10\n switchport trunk allowed vlan 10,20\n"
                      "interface Gi1/0/1\n switchport access vlan 10\n switchport mode access\n")
    r = _res(user_native)["IOS-L2-TRUNK-VLANS"]
    assert r["status"] == "fail" and "native VLAN 10 is also an access VLAN" in r["detail"]
    added = _sw(t + " switchport trunk native vlan 99\n switchport trunk allowed vlan 10\n"
                " switchport trunk allowed vlan add 20\n")
    assert _st(added, "IOS-L2-TRUNK-VLANS") == "pass"


def test_vtp(tmp_path):
    trunk = "interface Gi1/0/48\n switchport mode trunk\n switchport nonegotiate\n"
    head = "version 17.16\nhostname s1\nspanning-tree mode rapid-pvst\nspanning-tree extend system-id\nip cef\n"
    assert _st(head + "vtp mode off\n" + trunk, "IOS-L2-VTP-AUTH") == "pass"
    r = _res(head + trunk)["IOS-L2-VTP-AUTH"]           # no vtp line: server by default
    assert r["status"] == "not-visible" and "server" in r["detail"]
    r = _res(head + "vtp password Sup3rS3cret\n" + trunk)["IOS-L2-VTP-AUTH"]
    assert r["status"] == "pass" and "Sup3rS3cret" not in json.dumps(r)
    (tmp_path / "show-vtp-status.txt").write_text("VTP Operating Mode                : Client\n", encoding="utf-8")
    (tmp_path / "show-vtp-password.txt").write_text("The VTP password is not configured.\n", encoding="utf-8")
    r = _res(head + "vtp mode transparent\n" + trunk, tmp_path)["IOS-L2-VTP-AUTH"]   # show output wins
    assert r["status"] == "fail" and "client" in r["detail"]
    # server mode with no trunk or DTP port: VTP cannot reach it
    routed = head + "interface Gi1/0/1\n switchport mode access\n"
    assert _st(routed, "IOS-L2-VTP-AUTH") == "n/a"


def test_fhrp():
    def cfg(lines, shut=False):
        return ("version 17.16\nhostname d1\nrouter ospf 1\nline vty 0 4\n transport input ssh\n"
                "interface Vlan10\n ip address 10.10.0.2 255.255.255.0\n" + lines + (" shutdown\n" if shut else ""))
    none = _res(cfg(" standby 10 ip 10.10.0.1\n standby 10 priority 110\n"))["IOS-FHRP-NO-AUTH"]
    assert none["status"] == "fail" and "HSRP 10 (no authentication)" in none["detail"] and not none["exposed"]
    text = _res(cfg(" standby 10 ip 10.10.0.1\n standby 10 authentication text Cl34rT3xt\n"))["IOS-FHRP-NO-AUTH"]
    assert text["status"] == "fail" and "clear text" in text["detail"]
    assert "Cl34rT3xt" not in json.dumps(text)
    bare = _res(cfg(" standby ip 10.10.0.1\n standby authentication B4reW0rd\n"))["IOS-FHRP-NO-AUTH"]
    assert "HSRP 0 (clear text)" in bare["detail"] and "B4reW0rd" not in json.dumps(bare)
    md5 = _res(cfg(" standby 10 ip 10.10.0.1\n standby 10 authentication md5 key-string 7 0822455D0A16\n"))
    assert md5["IOS-FHRP-NO-AUTH"]["status"] == "pass" and "0822455D0A16" not in json.dumps(md5)
    vrrp = _res(cfg(" vrrp 5 ip 10.10.0.1\n vrrp 5 authentication md5 key-chain KC\n glbp 7 ip 10.10.0.9\n"))
    assert vrrp["IOS-FHRP-NO-AUTH"]["status"] == "fail" and "GLBP 7" in vrrp["IOS-FHRP-NO-AUTH"]["detail"]
    assert "VRRP 5" not in vrrp["IOS-FHRP-NO-AUTH"]["detail"]
    v3 = _res(cfg(" vrrp 5 address-family ipv4\n  address 10.10.0.1 primary\n"))["IOS-FHRP-NO-AUTH"]
    assert v3["status"] == "n/a" and "VRRPv3" in v3["detail"]
    assert _st(cfg(" standby 10 ip 10.10.0.1\n", shut=True), "IOS-FHRP-NO-AUTH") == "n/a"


def test_lab_access_switch():
    d = LAB / "hq-acc-sw-01"
    res = _res((d / "show-running-config-view-full.txt").read_text(encoding="utf-8"), d)
    assert {c: r["status"] for c, r in res.items()} == {
        "IOS-L2-BPDUGUARD": "pass",          # portfast + spanning-tree portfast bpduguard default
        "IOS-L2-DHCP-SNOOPING": "fail",      # VLAN 10 (USERS) has no snooping
        "IOS-L2-DAI": "fail",
        "IOS-L2-PORT-AUTH": "fail",          # Et0/3 client port, no NAC in the lab
        "IOS-L2-UNUSED-PORTS": "n/a",        # all four ports in use
        "IOS-L2-DTP": "fail",                # Et0/1-2 trunks: Negotiation of Trunking On
        "IOS-L2-TRUNK-VLANS": "fail",        # native VLAN 1 untagged (VLAN 1 not allowed)
        "IOS-L2-VTP-AUTH": "pass",           # transparent
        "IOS-FHRP-NO-AUTH": "n/a",
    }
    assert "Ethernet0/1" in res["IOS-L2-DTP"]["where"] and "Ethernet0/3" not in res["IOS-L2-DTP"]["where"]
    assert not any(r["exposed"] for r in res.values())


def test_lab_distribution_switch():
    d = LAB / "hq-dist-sw-01"
    res = _res((d / "show-running-config-view-full.txt").read_text(encoding="utf-8"), d)
    st = {c: r["status"] for c, r in res.items()}
    assert st["IOS-L2-UNUSED-PORTS"] == "pass"      # Et0/3 shutdown in VLAN 999 (PARKED), not on any trunk
    assert st["IOS-L2-BPDUGUARD"] == st["IOS-L2-DHCP-SNOOPING"] == "n/a"   # trunks only
    assert st["IOS-L2-DTP"] == st["IOS-L2-TRUNK-VLANS"] == "fail"
    assert "Ethernet0/1" not in res["IOS-L2-DTP"]["detail"]                # routed uplink to the core
    assert st["IOS-L2-VTP-AUTH"] == "pass"
    f = res["IOS-FHRP-NO-AUTH"]
    assert f["status"] == "fail" and all(f"HSRP {g}" in f["detail"] for g in (10, 20, 30))
