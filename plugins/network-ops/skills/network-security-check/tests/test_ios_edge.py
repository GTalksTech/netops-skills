# Tests for ios_cp.py and ios_edge.py (round 7, R4 + R5): CoPP, ICMP/ARP behaviour and
# CDP/LLDP on external interfaces, legacy services, anti-spoofing, and eBGP policy,
# maximum-prefix, GTSM and inbound prefix-list content, with peer-group and peer template
# resolution and platform defaults. Plus the results on the sanitized lab v2 edge router.
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import ios_cp  # noqa: E402
import ios_edge  # noqa: E402
import vendor_ios  # noqa: E402

LAB = HERE / "fixtures" / "lab-v2" / "hq-edge-rtr-01"
NEW = ios_cp.CHECKS + ios_edge.CHECKS

# A hardened internet edge: every R4/R5 check passes on it.
GOOD = """version 17.16
hostname edge1
no cdp run
class-map match-any CM-ROUTING
 match access-group name CPP-BGP
policy-map CPP
 class CM-ROUTING
  police 64000 conform-action transmit exceed-action drop
control-plane
 service-policy input CPP
interface Loopback0
 ip address 203.0.113.250 255.255.255.255
interface GigabitEthernet0/0
 description ISP
 ip address 198.51.100.2 255.255.255.252
 ip access-group EDGE-IN in
 no ip redirects
 no ip unreachables
 no ip proxy-arp
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
router bgp 65010
 neighbor 198.51.100.1 remote-as 64500
 neighbor 198.51.100.1 ttl-security hops 1
 address-family ipv4
  neighbor 198.51.100.1 activate
  neighbor 198.51.100.1 prefix-list ISP-IN in
  neighbor 198.51.100.1 prefix-list OUR-NETS out
  neighbor 198.51.100.1 maximum-prefix 1000 80
 exit-address-family
ip access-list extended EDGE-IN
 10 deny ip 10.0.0.0 0.255.255.255 any
 20 deny ip 172.16.0.0 0.15.255.255 any
 30 deny ip 192.168.0.0 0.0.255.255 any
 40 permit tcp host 198.51.100.1 host 198.51.100.2 eq bgp
 50 permit ip any any
ip prefix-list ISP-IN seq 5 deny 10.0.0.0/8 le 32
ip prefix-list ISP-IN seq 10 deny 172.16.0.0/12 le 32
ip prefix-list ISP-IN seq 15 deny 192.168.0.0/16 le 32
ip prefix-list ISP-IN seq 20 permit 0.0.0.0/0
ip prefix-list OUR-NETS seq 5 permit 203.0.113.0/24
"""


PAD = "service timestamps log datetime msec\nno ip http server\nip domain name lab.test\n"   # past the near-empty guard


def _res(cfg, folder=None):
    facts, _ = vendor_ios.analyze(cfg, {"_folder": folder} if folder else {})
    return {r["check"]: r for r in facts["results"] if r["check"] in NEW}


def _st(cfg, check, folder=None):
    return _res(cfg, folder)[check]["status"]


def test_good_edge_passes_everything():
    res = _res(GOOD)
    assert set(res) == set(NEW)
    bad = {c: (r["status"], r["detail"]) for c, r in res.items() if r["status"] != "pass"}
    assert not bad


# ---------- external interfaces ----------

def test_external_skips_loopbacks_and_igp_links():
    cfg = GOOD + ("interface GigabitEthernet0/2\n ip address 198.51.100.9 255.255.255.252\n"
                  "router ospf 1\n network 198.51.100.8 0.0.0.3 area 0\n")
    facts, _ = vendor_ios.analyze(cfg, {})
    from parsers import ios_blocks
    ext = [i["name"] for i in ios_cp.external_interfaces(ios_blocks(cfg), facts["interfaces"])]
    assert ext == ["GigabitEthernet0/0"]          # Loopback0 public, Gi0/2 runs OSPF: both left out


# ---------- IOS-NO-COPP ----------

def test_copp_missing_on_edge_is_exposed():
    r = _res(GOOD.replace(" service-policy input CPP\n", ""))["IOS-NO-COPP"]
    assert r["status"] == "fail" and r["exposed"]


def test_copp_undefined_policy_fails():
    r = _res(GOOD.replace("policy-map CPP\n", "policy-map OTHER\n"))["IOS-NO-COPP"]
    assert r["status"] == "fail" and "not defined" in r["detail"]


def test_copp_internal_router_not_exposed_and_l2_switch_na():
    internal = ("hostname core\ninterface Vlan10\n ip address 10.1.0.1 255.255.255.0\nrouter ospf 1\n"
                " network 10.1.0.0 0.0.0.255 area 0\ncontrol-plane\nline vty 0 4\n transport input ssh\n")
    r = _res(internal)["IOS-NO-COPP"]
    assert r["status"] == "fail" and not r["exposed"]
    l2 = PAD + "hostname acc\ninterface Vlan99\n ip address 10.9.0.5 255.255.255.0\ncontrol-plane\n"
    assert _st(l2, "IOS-NO-COPP") == "n/a"


# ---------- IOS-EDGE-IP-SERVICES (defaults: proxy-arp, redirects, unreachables ON) ----------

def test_ip_services_default_on_fails():
    cfg = GOOD.replace(" no ip redirects\n no ip unreachables\n no ip proxy-arp\n", "")
    r = _res(cfg)["IOS-EDGE-IP-SERVICES"]
    assert r["status"] == "fail" and r["exposed"]
    assert "proxy-arp, redirects, unreachables" in r["detail"]


def test_ip_services_link_local_only_not_exposed():
    r = _res(GOOD.replace(" no ip proxy-arp\n", ""))["IOS-EDGE-IP-SERVICES"]
    assert r["status"] == "fail" and not r["exposed"]          # proxy ARP only reaches the link


def test_icmp_rate_limit_counts_for_unreachables_and_directed_broadcast_fails():
    cfg = GOOD.replace(" no ip unreachables\n", "") + "ip icmp rate-limit unreachable 1000\n"
    assert _st(cfg, "IOS-EDGE-IP-SERVICES") == "pass"
    r = _res(GOOD.replace(" no ip proxy-arp\n", " no ip proxy-arp\n ip directed-broadcast\n"))
    assert r["IOS-EDGE-IP-SERVICES"]["status"] == "fail" and "directed-broadcast" in r["IOS-EDGE-IP-SERVICES"]["detail"]


def test_ip_services_na_without_external():
    cfg = PAD + "hostname r\ninterface Gi0/1\n ip address 10.0.0.1 255.255.255.0\ncontrol-plane\n"
    assert _st(cfg, "IOS-EDGE-IP-SERVICES") == "n/a" and _st(cfg, "IOS-EDGE-NO-ANTISPOOF") == "n/a"


# ---------- IOS-EDGE-CDP-LLDP ----------

def test_cdp_assumed_on_without_show_output(tmp_path):
    cfg = GOOD.replace("no cdp run\n", "")
    r = _res(cfg)["IOS-EDGE-CDP-LLDP"]
    assert r["status"] == "fail" and not r["exposed"] and "assumed on" in r["detail"]
    (tmp_path / "show-cdp-neighbors-detail.txt").write_text("% CDP is not enabled\n")
    assert _st(cfg, "IOS-EDGE-CDP-LLDP", str(tmp_path)) == "pass"
    cfg2 = cfg.replace(" no ip proxy-arp\n", " no ip proxy-arp\n no cdp enable\n")
    assert _st(cfg2, "IOS-EDGE-CDP-LLDP") == "pass"


def test_lldp_only_with_lldp_run():
    cfg = GOOD + "lldp run\n"
    r = _res(cfg)["IOS-EDGE-CDP-LLDP"]
    assert r["status"] == "fail" and "(LLDP)" in r["detail"]
    assert _st(cfg.replace(" no ip proxy-arp\n", " no ip proxy-arp\n no lldp transmit\n"), "IOS-EDGE-CDP-LLDP") == "pass"


# ---------- IOS-LEGACY-SERVICES ----------

def test_legacy_services_present_line_and_exposure():
    r = _res(GOOD + "service tcp-small-servers\nservice pad\n")["IOS-LEGACY-SERVICES"]
    assert r["status"] == "fail" and not r["exposed"]         # EDGE-IN denies private sources first
    open_edge = GOOD.replace(" ip access-group EDGE-IN in\n", "") + "ip finger\n"
    r = _res(open_edge)["IOS-LEGACY-SERVICES"]
    assert r["status"] == "fail" and r["exposed"] and "GigabitEthernet0/0" in r["detail"]
    pad_only = GOOD.replace(" ip access-group EDGE-IN in\n", "") + "service pad\n"
    r = _res(pad_only)["IOS-LEGACY-SERVICES"]
    assert r["status"] == "fail" and not r["exposed"]                # PAD listens on no IP port


def test_source_route_default_depends_on_release():
    assert _st(GOOD, "IOS-LEGACY-SERVICES") == "pass"                                  # 17.16: off
    old = GOOD.replace("version 17.16", "version 16.9")
    r = _res(old)["IOS-LEGACY-SERVICES"]
    assert r["status"] == "fail" and "17.1.1" in r["detail"]
    assert _st(old + "no ip source-route\n", "IOS-LEGACY-SERVICES") == "pass"
    assert _st(GOOD + "ip source-route\n", "IOS-LEGACY-SERVICES") == "fail"


# ---------- IOS-EDGE-NO-ANTISPOOF ----------

def test_antispoof_open_acl_and_no_acl_fail():
    r = _res(GOOD.replace(" ip access-group EDGE-IN in\n", ""))["IOS-EDGE-NO-ANTISPOOF"]
    assert r["status"] == "fail" and r["exposed"] and "no inbound ACL" in r["detail"]
    opened = GOOD.replace(" 10 deny ip 10.0.0.0", " 5 permit ip any any\n 10 deny ip 10.0.0.0")
    r = _res(opened)["IOS-EDGE-NO-ANTISPOOF"]
    assert r["status"] == "fail" and "permit ip any any" in r["detail"]
    partial = GOOD.replace(" 20 deny ip 172.16.0.0 0.15.255.255 any\n", "")
    assert "172.16.0.0/12" in _res(partial)["IOS-EDGE-NO-ANTISPOOF"]["detail"]
    undefined = GOOD.replace("ip access-group EDGE-IN in", "ip access-group NOPE in")
    assert _st(undefined, "IOS-EDGE-NO-ANTISPOOF") == "fail"


def test_antispoof_urpf_credited():
    no_acl = GOOD.replace(" ip access-group EDGE-IN in\n", "")
    strict = no_acl.replace(" no ip redirects\n", " no ip redirects\n ip verify unicast source reachable-via rx\n")
    assert _st(strict, "IOS-EDGE-NO-ANTISPOOF") == "pass"
    loose = no_acl.replace(" no ip redirects\n", " no ip redirects\n ip verify unicast source reachable-via any\n")
    r = _res(loose)["IOS-EDGE-NO-ANTISPOOF"]
    assert r["status"] == "pass" and "loose" in r["detail"]
    allow = loose.replace("reachable-via any", "reachable-via any allow-default")
    assert _st(allow, "IOS-EDGE-NO-ANTISPOOF") == "fail"


def test_antispoof_whitelist_acl_and_object_group():
    wl = GOOD.replace(" 10 deny ip 10.0.0.0 0.255.255.255 any\n 20 deny ip 172.16.0.0 0.15.255.255 any\n"
                      " 30 deny ip 192.168.0.0 0.0.255.255 any\n", "").replace(" 50 permit ip any any\n", "")
    r = _res(wl)["IOS-EDGE-NO-ANTISPOOF"]
    assert r["status"] == "pass" and "only listed sources" in r["detail"]
    og = GOOD.replace(" 10 deny ip 10.0.0.0", " 5 permit ip object-group PARTNERS any\n 10 deny ip 10.0.0.0")
    assert _st(og, "IOS-EDGE-NO-ANTISPOOF") == "not-visible"


# ---------- eBGP: policy, maximum-prefix, GTSM ----------

def test_bgp_no_filters_fail_and_exposure():
    cfg = GOOD.replace("  neighbor 198.51.100.1 prefix-list ISP-IN in\n", "").replace(
        "  neighbor 198.51.100.1 maximum-prefix 1000 80\n", "").replace(" neighbor 198.51.100.1 ttl-security hops 1\n", "")
    res = _res(cfg)
    assert res["IOS-BGP-NO-POLICY"]["status"] == "fail" and res["IOS-BGP-NO-POLICY"]["exposed"]
    assert "no inbound filter" in res["IOS-BGP-NO-POLICY"]["detail"]
    assert "no outbound filter" not in res["IOS-BGP-NO-POLICY"]["detail"]
    assert res["IOS-BGP-MAX-PREFIX"]["status"] == "fail" and res["IOS-BGP-NO-GTSM"]["status"] == "fail"


def test_private_ebgp_not_exposed():
    cfg = GOOD.replace("198.51.100.1", "10.20.0.1").replace("  neighbor 10.20.0.1 maximum-prefix 1000 80\n", "")
    r = _res(cfg)
    assert r["IOS-BGP-MAX-PREFIX"]["status"] == "fail" and not r["IOS-BGP-MAX-PREFIX"]["exposed"]
    assert r["IOS-BGP-INBOUND-PERMISSIVE"]["status"] == "n/a"        # private eBGP is not graded


def test_ibgp_excluded_and_multihop_skips_gtsm():
    ibgp = (PAD + "hostname r\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\nrouter bgp 65010\n"
            " neighbor 10.255.0.2 remote-as 65010\ncontrol-plane\n")
    assert {_st(ibgp, c) for c in ios_edge.CHECKS[1:]} == {"n/a"}
    mh = GOOD.replace(" neighbor 198.51.100.1 ttl-security hops 1\n", " neighbor 198.51.100.1 ebgp-multihop 2\n")
    assert _st(mh, "IOS-BGP-NO-GTSM") == "n/a"


def test_peer_group_resolution():
    cfg = GOOD.replace("""router bgp 65010
 neighbor 198.51.100.1 remote-as 64500
 neighbor 198.51.100.1 ttl-security hops 1
 address-family ipv4
  neighbor 198.51.100.1 activate
  neighbor 198.51.100.1 prefix-list ISP-IN in
  neighbor 198.51.100.1 prefix-list OUR-NETS out
  neighbor 198.51.100.1 maximum-prefix 1000 80
""", """router bgp 65010
 neighbor ISP peer-group
 neighbor ISP remote-as 64500
 neighbor ISP ttl-security hops 1
 neighbor 198.51.100.1 peer-group ISP
 address-family ipv4
  neighbor ISP activate
  neighbor ISP prefix-list ISP-IN in
  neighbor ISP prefix-list OUR-NETS out
  neighbor ISP maximum-prefix 1000 80
  neighbor 198.51.100.1 activate
""")
    sess = ios_edge.bgp_sessions(__import__("parsers").ios_blocks(cfg))
    assert [s["neighbor"] for s in sess] == ["198.51.100.1"] and sess[0]["peer_group"] == "ISP"
    res = _res(cfg)
    assert {c: res[c]["status"] for c in ios_edge.CHECKS[1:]} == {c: "pass" for c in ios_edge.CHECKS[1:]}
    no_pg_filter = cfg.replace("  neighbor ISP prefix-list OUR-NETS out\n", "")
    assert "no outbound filter" in _res(no_pg_filter)["IOS-BGP-NO-POLICY"]["detail"]


def test_peer_template_resolution_with_inheritance():
    cfg = GOOD.replace("""router bgp 65010
 neighbor 198.51.100.1 remote-as 64500
 neighbor 198.51.100.1 ttl-security hops 1
 address-family ipv4
  neighbor 198.51.100.1 activate
  neighbor 198.51.100.1 prefix-list ISP-IN in
  neighbor 198.51.100.1 prefix-list OUR-NETS out
  neighbor 198.51.100.1 maximum-prefix 1000 80
""", """router bgp 65010
 template peer-policy BASE
  maximum-prefix 1000 80
 exit-peer-policy
 template peer-policy TRANSIT
  prefix-list ISP-IN in
  prefix-list OUR-NETS out
  inherit peer-policy BASE 10
 exit-peer-policy
 template peer-session EBGP
  remote-as 64500
  ttl-security hops 1
 exit-peer-session
 neighbor 198.51.100.1 inherit peer-session EBGP
 address-family ipv4
  neighbor 198.51.100.1 activate
  neighbor 198.51.100.1 inherit peer-policy TRANSIT
""")
    res = _res(cfg)
    assert {c: res[c]["status"] for c in ios_edge.CHECKS[1:]} == {c: "pass" for c in ios_edge.CHECKS[1:]}
    no_base = cfg.replace("  inherit peer-policy BASE 10\n", "")
    assert _st(no_base, "IOS-BGP-MAX-PREFIX") == "fail"


def test_no_default_ipv4_unicast_needs_activate():
    cfg = GOOD.replace("router bgp 65010\n", "router bgp 65010\n no bgp default ipv4-unicast\n").replace(
        "  neighbor 198.51.100.1 activate\n", "")
    assert _st(cfg, "IOS-BGP-NO-POLICY") == "n/a"          # neighbor carries no unicast AF


# ---------- IOS-BGP-INBOUND-PERMISSIVE ----------

def _pl(*lines):
    return ios_edge.prefix_lists([f"ip prefix-list T {l}" for l in lines])[("ip", "T")]


def test_prefix_list_evaluation():
    assert ios_edge.pl_leaks(_pl("seq 5 permit 0.0.0.0/0")) == []                     # default route only
    leaks = ios_edge.pl_leaks(_pl("seq 5 permit 0.0.0.0/0 le 32"))
    assert any("bogon 10.0.0.0/8" in w for _, w, _ in leaks) and any("longer than /24" in w for _, w, _ in leaks)
    clean = _pl("seq 5 deny 10.0.0.0/8 le 32", "seq 6 deny 172.16.0.0/12 le 32", "seq 7 deny 192.168.0.0/16 le 32",
                "seq 8 deny 100.64.0.0/10 le 32", "seq 9 deny 127.0.0.0/8 le 32", "seq 10 deny 169.254.0.0/16 le 32",
                "seq 11 deny 0.0.0.0/8 le 32", "seq 12 deny 224.0.0.0/3 le 32", "seq 20 permit 0.0.0.0/0 le 24")
    assert ios_edge.pl_leaks(clean) == []
    assert ios_edge.pl_leaks(_pl("seq 5 permit 198.51.100.4/30")) == []                # exact entry: deliberate
    assert [w for _, w, _ in ios_edge.pl_leaks(_pl("seq 5 permit 10.1.0.0/16"))] == ["bogon 10.0.0.0/8"]
    ge = ios_edge.pl_leaks(_pl("seq 5 permit 203.0.113.0/24 ge 25"))
    assert [str(p) for p, _, _ in ge] == ["203.0.113.0/25"]
    shadowed = _pl("seq 5 deny 203.0.113.0/24 ge 25", "seq 10 permit 203.0.113.0/24 le 32")
    assert ios_edge.pl_leaks(shadowed) == []                                           # earlier deny wins


def test_inbound_permissive_check():
    r = _res(GOOD.replace("ip prefix-list ISP-IN seq 20 permit 0.0.0.0/0",
                          "ip prefix-list ISP-IN seq 20 permit 0.0.0.0/0 le 32"))["IOS-BGP-INBOUND-PERMISSIVE"]
    assert r["status"] == "fail" and r["exposed"] and "longer than /24" in r["detail"]
    rm = GOOD.replace("prefix-list ISP-IN in", "route-map FROM-ISP in")
    assert _st(rm, "IOS-BGP-INBOUND-PERMISSIVE") == "n/a"


# ---------- lab v2 edge router ----------

def test_lab_edge_results():
    text = (LAB / "show-running-config-view-full.txt").read_text(encoding="utf-8")
    res = _res(text, str(LAB))
    expect = {"IOS-NO-COPP": "fail", "IOS-EDGE-IP-SERVICES": "fail", "IOS-EDGE-CDP-LLDP": "fail",
              "IOS-LEGACY-SERVICES": "pass", "IOS-EDGE-NO-ANTISPOOF": "pass", "IOS-BGP-NO-POLICY": "pass",
              "IOS-BGP-MAX-PREFIX": "pass", "IOS-BGP-NO-GTSM": "fail", "IOS-BGP-INBOUND-PERMISSIVE": "fail"}
    assert {c: r["status"] for c, r in res.items()} == expect
    # Ethernet0/1 (public transit to fw-01) runs OSPF, so only the ISP link Ethernet0/2 is external
    assert "Ethernet0/2" in res["IOS-EDGE-IP-SERVICES"]["detail"]
    assert "Ethernet0/1" not in res["IOS-EDGE-IP-SERVICES"]["detail"]
    assert "show cdp neighbors answers" in res["IOS-EDGE-CDP-LLDP"]["detail"]
    assert "EDGE-IN" in res["IOS-EDGE-NO-ANTISPOOF"]["detail"]
    assert "203.0.113.0/25" in res["IOS-BGP-INBOUND-PERMISSIVE"]["detail"]
    assert "198.51.100.4" not in res["IOS-BGP-INBOUND-PERMISSIVE"]["detail"]     # exact /30 entry not graded
    exposed = {c for c, r in res.items() if r["exposed"]}
    assert exposed == {"IOS-NO-COPP", "IOS-EDGE-IP-SERVICES", "IOS-BGP-NO-GTSM", "IOS-BGP-INBOUND-PERMISSIVE"}
    assert "gtt-lab-ro" not in str(res) and "$9$" not in str(res)    # no secrets in evidence
