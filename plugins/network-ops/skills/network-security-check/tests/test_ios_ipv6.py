# B4: IPv6 edge parity. IPv6 internet-facing detection, anti-spoofing (uRPF or a ULA-denying
# traffic-filter), ICMPv6 redirects/unreachables and RA suppression on external interfaces,
# ipv6 source-route, eBGP over IPv6 (activation, policy, max-prefix, GTSM, IPv6 bogons and /48),
# and RA Guard / DHCPv6 Guard on access ports. The lab is IPv4-only, so these rest on the two
# fixtures in tests/fixtures/ipv6 (a dual-stack edge router and a dual-stack access switch).
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import common  # noqa: E402
import ios_edge  # noqa: E402
import ios_l2  # noqa: E402
import rollup  # noqa: E402
import vendor_ios  # noqa: E402

FX = HERE / "fixtures" / "ipv6"
EDGE = (FX / "dual-stack-edge.cfg").read_text(encoding="utf-8")
ACC = (FX / "dual-stack-access.cfg").read_text(encoding="utf-8")
LAB = HERE / "fixtures" / "lab-v2"
CHECKS = yaml.safe_load((HERE.parent / "settings" / "checks.yaml").read_text(encoding="utf-8"))
EDGE_CHECKS = ("IOS-EDGE-NO-ANTISPOOF", "IOS-EDGE-IP-SERVICES", "IOS-EDGE-CDP-LLDP", "IOS-LEGACY-SERVICES",
               "IOS-NO-COPP", "IOS-BGP-NO-POLICY", "IOS-BGP-MAX-PREFIX", "IOS-BGP-NO-GTSM",
               "IOS-BGP-INBOUND-PERMISSIVE")


def _run(cfg, switch=False, folder=None):
    dev = {"_is_switch": True} if switch else {}
    if folder:
        dev["_folder"] = str(folder)
    facts, _ = vendor_ios.analyze(cfg, dev)
    return {r["check"]: r for r in facts["results"]}, facts


def _without(cfg, *lines):
    for l in lines:
        assert l + "\n" in cfg, l
        cfg = cfg.replace(l + "\n", "", 1)
    return cfg


def _itf(facts, name):
    return next(i for i in facts["interfaces"] if i["name"] == name)


# ---------- addresses and internet-facing detection ----------

def test_is_public_ipv6():
    for a in ("2001:4860::8888", "2a00:1450::1/64", "2001:db8::1"):        # doc range counts, like IPv4
        assert common.is_public(a), a
    for a in ("fe80::1", "fd00::1/64", "ff02::1", "::", "::1", "::ffff:198.51.100.1", "64:ff9b::1"):
        assert not common.is_public(a), a


def test_edge_fixture_interfaces():
    _, facts = _run(EDGE)
    wan, lan = _itf(facts, "GigabitEthernet0/0"), _itf(facts, "GigabitEthernet0/1")
    assert wan["internet4"] and wan["internet6"] and wan["acl6_in"] == "EDGE6-IN"
    # a global IPv6 address on the LAN is normal: not internet-facing without an outside sign
    assert lan["ips6"] == ["2001:DB8:500:1::1/64", "FD00:10::1/64"]
    assert not lan["internet"]
    assert "GigabitEthernet0/1" not in facts["internet_interfaces"]


V6ONLY = ("version 17.16\nservice timestamps log datetime msec\nhostname r6\nno ip http server\n"
          "ip domain name lab.test\nipv6 unicast-routing\n"
          "interface GigabitEthernet0/0\n{wan}"
          "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n ipv6 address 2001:DB8:500:1::1/64\n"
          "{tail}")


def _v6only(wan, tail=""):
    return V6ONLY.format(wan=wan, tail=tail)


def test_internet6_signals():
    gua = " ipv6 address 2001:DB8:FFFF::2/126\n"
    cases = {
        "nothing": (_v6only(gua), False),
        "default route by interface": (_v6only(gua, "ipv6 route ::/0 GigabitEthernet0/0 FE80::1\n"), True),
        "default route by next hop": (_v6only(gua, "ipv6 route ::/0 2001:DB8:FFFF::1\n"), True),
        "eBGP neighbor in subnet": (_v6only(gua, "router bgp 65010\n neighbor 2001:DB8:FFFF::1 remote-as 64500\n"),
                                    True),
        "iBGP neighbor in subnet": (_v6only(gua, "router bgp 65010\n neighbor 2001:DB8:FFFF::1 remote-as 65010\n"),
                                    False),
        "description": (_v6only(" description Uplink to ISP\n" + gua), True),
        "SLAAC + prefix delegation": (_v6only(" ipv6 address autoconfig\n ipv6 dhcp client pd FROM-ISP\n"), True),
        "SLAAC alone": (_v6only(" ipv6 address autoconfig\n"), False),
        "link-local and ULA only": (_v6only(" ipv6 address FE80::2 link-local\n ipv6 address FD00::2/64\n"
                                            " description ISP\n"), False),
        "shut down": (_v6only(gua + " shutdown\n", "ipv6 route ::/0 GigabitEthernet0/0\n"), False),
    }
    for label, (cfg, want) in cases.items():
        _, facts = _run(cfg)
        assert _itf(facts, "GigabitEthernet0/0")["internet6"] is want, label
        assert not _itf(facts, "GigabitEthernet0/1")["internet"], label        # the LAN never is
        assert facts["internet_facing"] is want, label


def test_general_prefix_lan_is_not_internet():
    # LAN numbered from a delegated prefix: global unicast, but the default route and the PD client are
    # on the WAN interface, so only the WAN counts
    cfg = _v6only(" ipv6 address autoconfig default\n ipv6 dhcp client pd FROM-ISP\n",
                  "interface GigabitEthernet0/2\n ipv6 address FROM-ISP ::1:0:0:0:1/64\n")
    _, facts = _run(cfg)
    assert _itf(facts, "GigabitEthernet0/0")["internet6"]
    lan = _itf(facts, "GigabitEthernet0/2")
    assert lan["public"] and not lan["internet"]
    cfg = _v6only(" ipv6 address 2001:DB8:FFFF::2/126\n ipv6 address ULA-PFX ::1/64\n",
                  "ipv6 general-prefix ULA-PFX FD00:1::/48\n")
    _, facts = _run(cfg)
    assert _itf(facts, "GigabitEthernet0/0")["ips6"] == ["2001:DB8:FFFF::2/126", "FD00:1::/48"]


# ---------- the hardened dual-stack edge ----------

def test_edge_fixture_passes_edge_checks():
    res, _ = _run(EDGE)
    assert {c: res[c]["status"] for c in EDGE_CHECKS} == {c: "pass" for c in EDGE_CHECKS}
    assert "GigabitEthernet0/0 (IPv6): IPv6 ACL EDGE6-IN denies fc00::/7" in res["IOS-EDGE-NO-ANTISPOOF"]["detail"]
    assert "IPv6 redirects and unreachables off, router advertisements suppressed" in \
        res["IOS-EDGE-IP-SERVICES"]["detail"]
    assert "(IPv6: /48)" in res["IOS-BGP-INBOUND-PERMISSIVE"]["detail"]
    assert "ISP6-IN from 2001:DB8:FFFF::1" in res["IOS-BGP-INBOUND-PERMISSIVE"]["detail"]


# ---------- anti-spoofing ----------

def test_antispoof_v6_no_filter_fails_in_the_same_finding():
    res, _ = _run(_without(EDGE, " ipv6 traffic-filter EDGE6-IN in"))
    r = res["IOS-EDGE-NO-ANTISPOOF"]
    assert r["status"] == "fail" and r["exposed"]
    assert "GigabitEthernet0/0 (IPv6): no inbound IPv6 traffic-filter and no uRPF" in r["detail"]
    assert "GigabitEthernet0/0: ACL" not in r["detail"]        # the IPv4 side passes, so it is not listed
    assert r["where"] == "GigabitEthernet0/0"


def test_antispoof_v6_both_families_fail_one_interface_listed_once():
    cfg = _without(EDGE, " ipv6 traffic-filter EDGE6-IN in", " ip access-group EDGE-IN in")
    r = _run(cfg)[0]["IOS-EDGE-NO-ANTISPOOF"]
    assert "GigabitEthernet0/0: no inbound ACL and no uRPF" in r["detail"]
    assert "GigabitEthernet0/0 (IPv6): no inbound IPv6 traffic-filter" in r["detail"]
    assert r["evidence"].count("interface GigabitEthernet0/0") == 1


def test_antispoof_v6_urpf():
    base = _without(EDGE, " ipv6 traffic-filter EDGE6-IN in")
    strict = base.replace(" ipv6 nd ra suppress all\n",
                          " ipv6 nd ra suppress all\n ipv6 verify unicast source reachable-via rx\n")
    assert _run(strict)[0]["IOS-EDGE-NO-ANTISPOOF"]["status"] == "pass"
    loose = base.replace(" ipv6 nd ra suppress all\n",
                         " ipv6 nd ra suppress all\n ipv6 verify unicast source reachable-via any\n")
    r = _run(loose)[0]["IOS-EDGE-NO-ANTISPOOF"]
    assert r["status"] == "fail" and "loose uRPF only" in r["detail"] and "spoofed ULA sources" in r["detail"]


def test_acl6_grading():
    def verdict(body):
        blocks = [("ipv6 access-list T", body.strip().splitlines())]
        return ios_edge.acl6_antispoof(blocks, "T")[0]
    # neighbor discovery permits before the ULA deny are fine (link-scoped)
    assert verdict("permit icmp any any nd-na\npermit icmp any any router-advertisement\n"
                   "deny ipv6 FC00::/7 any\npermit ipv6 any any") == "ok"
    assert verdict("permit ipv6 any any\ndeny ipv6 FC00::/7 any") == "open"
    assert verdict("permit tcp any any eq 443\ndeny ipv6 FC00::/7 any") == "open"
    assert verdict("deny tcp FC00::/7 any\npermit ipv6 any any") == "open"         # only tcp denied
    assert verdict("deny ipv6 FD00::/8 any\npermit ipv6 any any") == "open"         # half of fc00::/7
    assert verdict("permit tcp 2001:DB8::/32 any eq bgp") == "ok"                   # implicit deny
    assert verdict("sequence 10 deny ipv6 any any") == "ok"
    assert verdict("permit ipv6 object-group X any") == "unknown"
    assert ios_edge.acl6_antispoof([], "MISSING")[0] == "open"


# ---------- ICMPv6 and RA on external interfaces, ipv6 source-route ----------

def test_ip_services_v6():
    for line, word, exposed in ((" no ipv6 redirects", "ipv6 redirects", False),
                                (" no ipv6 unreachables", "ipv6 unreachables", True),
                                (" ipv6 nd ra suppress all", "ipv6 router advertisements", False)):
        r = _run(_without(EDGE, line))[0]["IOS-EDGE-IP-SERVICES"]
        assert r["status"] == "fail", line
        assert f"GigabitEthernet0/0 ({word})" in r["detail"], r["detail"]
        assert r["exposed"] is exposed, line
    # a host-mode device (no ipv6 unicast-routing) sends no router advertisements
    cfg = _without(EDGE, " ipv6 nd ra suppress all", "ipv6 unicast-routing")
    assert _run(cfg)[0]["IOS-EDGE-IP-SERVICES"]["status"] == "pass"
    # the older form of the command is accepted
    assert _run(EDGE.replace(" ipv6 nd ra suppress all", " ipv6 nd suppress-ra"))[0][
        "IOS-EDGE-IP-SERVICES"]["status"] == "pass"


def test_ipv6_only_external_interface_skips_ipv4_items():
    cfg = _v6only(" ipv6 address 2001:DB8:FFFF::2/126\n no ipv6 redirects\n no ipv6 unreachables\n"
                  " ipv6 nd ra suppress\n ipv6 verify unicast source reachable-via rx\n",
                  "ipv6 route ::/0 GigabitEthernet0/0\n")
    res, _ = _run(cfg)
    assert res["IOS-EDGE-IP-SERVICES"]["status"] == "pass", res["IOS-EDGE-IP-SERVICES"]["detail"]
    assert res["IOS-EDGE-NO-ANTISPOOF"]["status"] == "pass", res["IOS-EDGE-NO-ANTISPOOF"]["detail"]
    assert "(IPv6)" in res["IOS-EDGE-NO-ANTISPOOF"]["detail"]


def test_ipv6_source_route_is_legacy():
    r = _run(EDGE.replace("ipv6 unicast-routing\n", "ipv6 unicast-routing\nipv6 source-route\n"))[0]
    assert r["IOS-LEGACY-SERVICES"]["status"] == "fail"
    assert "ipv6 source-route" in r["IOS-LEGACY-SERVICES"]["detail"]


def test_ospfv3_link_is_not_external():
    cfg = _v6only(" ipv6 address 2001:DB8:FFFF::2/126\n ospfv3 1 ipv6 area 0\n",
                  "ipv6 route ::/0 GigabitEthernet0/0\n")
    res, facts = _run(cfg)
    assert _itf(facts, "GigabitEthernet0/0")["internet6"]          # still internet-facing for CVE exposure
    assert res["IOS-EDGE-NO-ANTISPOOF"]["status"] == "n/a"        # but an IGP link, not the ISP edge


# ---------- eBGP over IPv6 ----------

def test_v6_neighbor_not_auto_activated_in_ipv4():
    # without 'no bgp default ipv4-unicast' IOS activates IPv4 neighbors only: the IPv6 neighbor must
    # not be graded (and failed) in the IPv4 address family it never runs in
    cfg = _without(EDGE, " no bgp default ipv4-unicast")
    sessions = [s for s in ios_edge.bgp_sessions(vendor_ios.ios_blocks(cfg)) if ":" in s["neighbor"]]
    assert [s["af"] for s in sessions] == ["ipv6"]
    assert _run(cfg)[0]["IOS-BGP-NO-POLICY"]["status"] == "pass"


def test_v6_session_hygiene():
    r = _run(_without(EDGE, "  neighbor 2001:DB8:FFFF::1 maximum-prefix 1000 80"))[0]["IOS-BGP-MAX-PREFIX"]
    assert r["status"] == "fail" and "2001:DB8:FFFF::1 (AS 64500, ipv6)" in r["detail"] and r["exposed"]
    r = _run(_without(EDGE, " neighbor 2001:DB8:FFFF::1 ttl-security hops 1"))[0]["IOS-BGP-NO-GTSM"]
    assert r["status"] == "fail" and "2001:DB8:FFFF::1" in r["detail"]
    r = _run(_without(EDGE, "  neighbor 2001:DB8:FFFF::1 prefix-list OUR6-NETS out"))[0]["IOS-BGP-NO-POLICY"]
    assert r["status"] == "fail" and "2001:DB8:FFFF::1 (AS 64500, ipv6): no outbound filter" in r["detail"]


def _pl(*entries):
    return ios_edge.prefix_lists([f"ipv6 prefix-list P seq {5 * (n + 1)} {e}" for n, e in enumerate(entries)])[
        ("ipv6", "P")]


def test_v6_prefix_list_leaks():
    leaks = {w for _, w, _ in ios_edge.pl_leaks(_pl("permit ::/0 le 128"))}
    assert {"bogon fc00::/7", "bogon fe80::/10", "bogon ff00::/8", "bogon 2001::/32", "bogon ::1/128",
            "longer than /48"} <= leaks
    assert "bogon 2001:db8::/32" not in leaks                       # documentation counts as public
    assert {w for _, w, _ in ios_edge.pl_leaks(_pl("permit 2000::/3 le 64"))} == {
        "bogon 2001::/32", "bogon 2001:2::/48", "bogon 2001:10::/28", "longer than /48"}
    assert ios_edge.pl_leaks(_pl("deny 2001::/23 le 128", "permit 2000::/3 le 48")) == []
    assert ios_edge.pl_leaks(_pl("permit 2001:DB8:1:2::/64")) == []      # one exact long prefix: deliberate
    # the full fixture list rejects everything it should
    assert ios_edge.pl_leaks(ios_edge.prefix_lists([h for h, _ in vendor_ios.ios_blocks(EDGE)])[
        ("ipv6", "ISP6-IN")]) == []


def test_v6_inbound_permissive_fails_on_the_router():
    cfg = EDGE.replace("ipv6 prefix-list ISP6-IN seq 50 permit 2000::/3 le 48",
                       "ipv6 prefix-list ISP6-IN seq 50 permit 2000::/3 le 64")
    r = _run(cfg)[0]["IOS-BGP-INBOUND-PERMISSIVE"]
    assert r["status"] == "fail" and r["exposed"]
    assert "ISP6-IN from 2001:DB8:FFFF::1 accepts 2000::/49 (longer than /48)" in r["detail"]


# ---------- RA Guard and DHCPv6 Guard ----------

def test_access_fixture():
    res, facts = _run(ACC, switch=True)
    assert not facts["internet_interfaces"]                          # the IPv6 SVI is not internet-facing
    assert res["IOS-L2-V6-FHS"]["status"] == "pass"
    adv = res["IOS-L2-V6-FHS-ADVISORY"]
    assert adv["status"] == "fail" and not adv["exposed"]
    assert "GigabitEthernet1/0/4 VLAN 20 (no RA Guard, no DHCPv6 Guard)" in adv["detail"]
    assert "GigabitEthernet1/0/24" not in adv["detail"]              # trunks are not graded


def test_vlan_policy_and_port_policy():
    # Gi1/0/3 relies on the VLAN 10 policy: without it, the standard check fails on that port only
    cfg = _without(ACC, "vlan configuration 10", " ipv6 nd raguard attach-policy HOSTS",
                   " ipv6 dhcp guard attach-policy CLIENTS")
    r = _run(cfg, switch=True)[0]["IOS-L2-V6-FHS"]
    assert r["status"] == "fail" and r["where"] == "GigabitEthernet1/0/3"
    # a router-role policy on an access port lets router advertisements in
    cfg = ACC.replace("interface GigabitEthernet1/0/1\n switchport access vlan 10\n switchport mode access\n"
                      " spanning-tree portfast\n authentication port-control auto\n dot1x pae authenticator\n"
                      " ipv6 nd raguard attach-policy HOSTS\n",
                      "interface GigabitEthernet1/0/1\n switchport access vlan 10\n switchport mode access\n"
                      " spanning-tree portfast\n authentication port-control auto\n dot1x pae authenticator\n"
                      " ipv6 nd raguard attach-policy UPLINK-RTR\n")
    r = _run(cfg, switch=True)[0]["IOS-L2-V6-FHS"]
    assert r["status"] == "fail"
    assert "GigabitEthernet1/0/1 VLAN 10 (no RA Guard (policy UPLINK-RTR: device-role router))" in r["detail"]
    cfg = ACC.replace(" ipv6 dhcp guard attach-policy CLIENTS\ninterface GigabitEthernet1/0/2",
                      " ipv6 dhcp guard attach-policy NOPE\ninterface GigabitEthernet1/0/2")
    r = _run(cfg, switch=True)[0]["IOS-L2-V6-FHS"]
    assert r["status"] == "fail" and "names an undefined policy" in r["detail"]


def test_port_vlan_list_attach():
    # a port attach limited to another VLAN does not cover the port's access VLAN 20
    cfg = ACC.replace("interface GigabitEthernet1/0/4\n switchport access vlan 20\n",
                      "interface GigabitEthernet1/0/4\n switchport access vlan 20\n"
                      " ipv6 nd raguard attach-policy HOSTS vlan 10\n ipv6 dhcp guard attach-policy CLIENTS vlan 20\n")
    r = _run(cfg, switch=True)[0]["IOS-L2-V6-FHS-ADVISORY"]
    assert r["status"] == "fail" and "(no RA Guard)" in r["detail"] and "DHCPv6" not in r["detail"].split(":", 1)[1]


def test_no_ipv6_on_switch_is_na():
    cfg = _without(ACC, "ipv6 unicast-routing", " ipv6 address 2001:DB8:500:10::2/64")
    res, _ = _run(cfg, switch=True)
    assert res["IOS-L2-V6-FHS"]["status"] == res["IOS-L2-V6-FHS-ADVISORY"]["status"] == "n/a"
    # an IPv6 SVI alone (no unicast-routing) still makes the VLAN an IPv6 VLAN
    res, _ = _run(_without(ACC, "ipv6 unicast-routing"), switch=True)
    assert res["IOS-L2-V6-FHS"]["status"] == "pass"
    assert res["IOS-L2-V6-FHS-ADVISORY"]["status"] == "fail"


def test_catalog_and_rollup():
    std, adv = CHECKS["IOS-L2-V6-FHS"], CHECKS["IOS-L2-V6-FHS-ADVISORY"]
    assert std.get("tier", "standard") == "standard" and adv["tier"] == "advisory"
    assert adv["suppressed_by"] == ["IOS-L2-V6-FHS"]
    assert std["validated"] == adv["validated"] == "fixture"
    assert set(ios_l2.V6_CHECKS) <= set(vendor_ios.CHECKS)
    for cid in ("IOS-L2-V6-FHS", "IOS-L2-V6-FHS-ADVISORY", "IOS-EDGE-NO-ANTISPOOF", "IOS-EDGE-IP-SERVICES",
                "IOS-BGP-INBOUND-PERMISSIVE"):
        assert "ipv6" in (CHECKS[cid]["why"] + CHECKS[cid]["fix"]).lower(), cid
    f = [{"type": "config", "id": "IOS-L2-V6-FHS", "device": "s1", "title": "t", "detail": "a", "deadline": "next maintenance window",
          "score": 10}, {"type": "config", "id": "IOS-L2-V6-FHS-ADVISORY", "device": "s1", "title": "t", "detail": "b",
                         "deadline": "next maintenance window", "score": 5}]
    kept = rollup.fold_dependents(f, CHECKS)
    assert [x["id"] for x in kept] == ["IOS-L2-V6-FHS"]


# ---------- the IPv4-only lab is unchanged ----------

def test_lab_v2_has_no_ipv6_results():
    for d in sorted(p for p in LAB.iterdir() if (p / "show-running-config-view-full.txt").exists()):
        cfg = (d / "show-running-config-view-full.txt").read_text(encoding="utf-8")
        if "hostname" not in cfg or "version 17" not in cfg:
            continue
        res, facts = _run(cfg, switch="sw" in d.name, folder=d)
        assert not any(i.get("internet6") for i in facts["interfaces"]), d.name
        assert res["IOS-L2-V6-FHS"]["status"] == res["IOS-L2-V6-FHS-ADVISORY"]["status"] == "n/a", d.name
        assert "IPv6" not in res["IOS-EDGE-NO-ANTISPOOF"]["detail"], d.name
