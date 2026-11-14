# Round 12 (B2): correctness fixes and test hardening. One focused test per fix, plus the R10
# integrity tests (BOD 26-04 Table 1, sources exist, no secret in a full fixture run).
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
sys.path.insert(0, str(HERE))
import fgt_hardening  # noqa: E402
import ios_edge  # noqa: E402
import ios_l2  # noqa: E402
import scoring  # noqa: E402
import seccheck  # noqa: E402
import test_fortios_hardening as tf  # noqa: E402
import vendor_ios  # noqa: E402

FX = HERE / "fixtures"
PAD = "version 17.16\nservice timestamps log datetime msec\nno ip http server\nip domain name lab.test\n"


def _res(cfg, dev=None):
    facts, _ = vendor_ios.analyze(cfg, dev or {})
    return {r["check"]: r for r in facts["results"]}, facts


# ---------- 2: BGP authentication through peer-groups and templates ----------
BGP_BASE = PAD + "hostname r1\ninterface Ethernet0/0\n ip address 198.51.100.2 255.255.255.252\n"


def test_bgp_auth_from_peer_group_and_template():
    cfg = BGP_BASE + ("router bgp 65010\n template peer-session ISP\n  remote-as 64500\n  password 7 X\n"
                      " exit-peer-session\n neighbor UPSTREAM peer-group\n neighbor UPSTREAM remote-as 64501\n"
                      " neighbor 198.51.100.1 inherit peer-session ISP\n neighbor 203.0.113.5 peer-group UPSTREAM\n")
    res, _ = _res(cfg)
    na = res["IOS-ROUTING-NO-AUTH"]
    # the template's password counts; the peer-group neighbor (remote-as from the group) is graded
    assert na["status"] == "fail" and "203.0.113.5 (AS 64501)" in na["detail"] and "198.51.100.1" not in na["detail"]
    ok = cfg + " neighbor UPSTREAM password 7 Y\n"
    assert _res(ok)[0]["IOS-ROUTING-NO-AUTH"]["status"] == "pass"


# ---------- 13: BGP TCP MD5 passes with a note, OSPF MD5 stays weak ----------
def test_bgp_md5_pass_ospf_md5_weak():
    cfg = BGP_BASE + "router bgp 65010\n neighbor 198.51.100.1 remote-as 64500\n neighbor 198.51.100.1 password 7 X\n"
    r = _res(cfg)[0]["IOS-ROUTING-WEAK-AUTH"]
    assert r["status"] == "pass" and "BGP TCP MD5 accepted" in r["detail"]
    ospf = cfg.replace(" ip address 198.51.100.2 255.255.255.252\n", " ip address 10.0.0.1 255.255.255.0\n"
                       " ip ospf authentication message-digest\n ip ospf message-digest-key 1 md5 7 X\n") \
        + "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n"
    assert _res(ospf)[0]["IOS-ROUTING-WEAK-AUTH"]["status"] == "fail"


# ---------- 14: private eBGP graded for maximum-prefix only; listen ranges noted ----------
def test_private_ebgp_only_max_prefix():
    cfg = PAD + "hostname ce1\ninterface Ethernet0/0\n ip address 10.1.1.2 255.255.255.252\n" \
        "router bgp 65010\n bgp listen range 10.9.0.0/16 peer-group DYN\n neighbor 10.1.1.1 remote-as 65020\n"
    res, _ = _res(cfg)
    for c in ("IOS-BGP-NO-POLICY", "IOS-BGP-NO-GTSM", "IOS-BGP-INBOUND-PERMISSIVE"):
        assert res[c]["status"] == "n/a" and "not graded" in res[c]["detail"]
    assert res["IOS-BGP-MAX-PREFIX"]["status"] == "fail"
    assert ios_edge.private_asn("65020") and ios_edge.private_asn("4200000001") and not ios_edge.private_asn("64500")
    # a private address with a public ASN is still graded in full
    pub_as = cfg.replace("remote-as 65020", "remote-as 64500")
    assert _res(pub_as)[0]["IOS-BGP-NO-POLICY"]["status"] == "fail"


# ---------- 16: wildcard 255.255.255.255 is any ----------
def test_wildcard_any():
    assert str(ios_edge.wildcard_net("0.0.0.0", "255.255.255.255")) == "0.0.0.0/0"
    assert str(ios_edge.wildcard_net("172.16.0.0", "0.15.255.255")) == "172.16.0.0/12"
    assert ios_edge.wildcard_net("10.0.0.0", "0.0.255.0") is None


# ---------- 8 and 16: CDP explicit enable, control-plane host ----------
EDGE = PAD + ("hostname e1\ninterface Ethernet0/0\n ip address 198.51.100.2 255.255.255.252\n no ip redirects\n"
              " no ip unreachables\n no ip proxy-arp\ninterface Ethernet0/1\n ip address 10.0.0.1 255.255.255.0\n"
              " cdp enable\n")


def test_cdp_explicit_enable_means_default_off():
    r = _res(EDGE)[0]["IOS-EDGE-CDP-LLDP"]
    assert r["status"] == "pass" and "per-interface default off" in r["detail"]
    on = EDGE.replace(" no ip proxy-arp\n", " no ip proxy-arp\n cdp enable\n")
    assert _res(on)[0]["IOS-EDGE-CDP-LLDP"]["status"] == "fail"
    assert _res(EDGE.replace(" cdp enable\n", ""))[0]["IOS-EDGE-CDP-LLDP"]["status"] == "fail"   # assumed on


def test_control_plane_host_policy_counts():
    cfg = EDGE + "policy-map CPP\n class class-default\n  police 8000\ncontrol-plane host\n service-policy input CPP\n"
    assert _res(cfg)[0]["IOS-NO-COPP"]["status"] == "pass"


# ---------- 16: IPv6-only public interface is internet-facing ----------
def test_ipv6_global_unicast_is_internet():
    base = PAD + "hostname r6\ninterface Ethernet0/0\n ipv6 address {}\n"
    # B4: a global address needs an outside sign (here the IPv6 default route); IPv6 LANs use them too
    assert _res(base.format("2001:db8:1::2/64") + "ipv6 route ::/0 Ethernet0/0\n")[1]["internet_facing"]
    assert not _res(base.format("2001:db8:1::2/64"))[1]["internet_facing"]
    assert not _res(base.format("fd00:1::2/64"))[1]["internet_facing"]
    assert not _res(base.format("fe80::1 link-local"))[1]["internet_facing"]


# ---------- 9: HTTPS only with an access-class passes ----------
def test_http_server_https_only_with_acl():
    base = PAD.replace("no ip http server\n", "") + "hostname r1\ninterface Ethernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
    ok = base + "ip http secure-server\nip http access-class ipv4 MGMT\n"
    r = _res(ok)[0]["IOS-HTTP-SERVER"]
    assert r["status"] == "pass" and "HTTPS only" in r["detail"]
    assert _res(base + "ip http secure-server\n")[0]["IOS-HTTP-SERVER"]["status"] == "fail"
    r = _res(base + "ip http server\nip http secure-server\nip http access-class 10\n")[0]["IOS-HTTP-SERVER"]
    assert r["status"] == "fail" and "plain HTTP" in r["detail"] and not r["exposed"]


# ---------- 10: vty access-class direction, definition, any, IPv6 ----------
VTY = PAD + ("hostname r1\ninterface Ethernet0/0\n ip address 10.0.0.1 255.255.255.0\nip ssh version 2\n"
             "logging host 10.0.0.5\nip access-list standard MGMT\n permit 10.0.20.0 0.0.0.255\n"
             "line vty 0 4\n access-class MGMT in\n transport input ssh\n")


@pytest.mark.parametrize("change,status,text", [
    (None, "pass", None),
    (("access-class MGMT in", "access-class MGMT out"), "fail", "filters outgoing"),
    (("access-class MGMT in", "access-class NOPE in"), "fail", "not defined"),
    ((" permit 10.0.20.0 0.0.0.255", " permit any"), "fail", "permits any source"),
    ((" permit 10.0.20.0 0.0.0.255", " permit 0.0.0.0 255.255.255.255"), "fail", "permits any source"),
    ((" ip address 10.0.0.1 255.255.255.0", " ip address 10.0.0.1 255.255.255.0\n ipv6 address 2001:db8::1/64"),
     "fail", "ipv6 access-class"),
])
def test_vty_acl(change, status, text):
    cfg = VTY.replace(*change) if change else VTY
    r = _res(cfg)[0]["IOS-VTY-ACL"]
    assert r["status"] == status and (text is None or text in r["detail"])


def test_vty_acl_ipv6_defined_passes():
    cfg = VTY.replace(" ip address 10.0.0.1 255.255.255.0", " ip address 10.0.0.1 255.255.255.0\n"
                      " ipv6 address 2001:db8::1/64") + " ipv6 access-class MGMT6 in\nipv6 access-list MGMT6\n" \
                                                       " permit ipv6 2001:db8:20::/64 any\n"
    assert _res(cfg)[0]["IOS-VTY-ACL"]["status"] == "pass"


# ---------- 11: type 4 and line passwords ----------
def test_type4_and_line_passwords():
    base = PAD + "hostname r1\ninterface Ethernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
    r = _res(base + "enable secret 4 Sx4\n")[0]["IOS-PASSWORD-STORAGE"]
    assert r["status"] == "fail" and "type 4" in r["detail"]
    r = _res(base + "enable secret 9 $9$x\nline vty 0 4\n password 7 0822455D0A16\n login\n")[0]["IOS-PASSWORD-STORAGE"]
    assert r["status"] == "fail" and "line vty 0 4: password type 7" in r["detail"]
    assert "0822455D0A16" not in json.dumps(r)
    assert _res(base + "enable secret 9 $9$x\n")[0]["IOS-PASSWORD-STORAGE"]["status"] == "pass"


# ---------- 6 and 7: routed ports skipped, interface templates folded ----------
L2 = PAD + ("hostname s1\nvtp mode transparent\nspanning-tree portfast bpduguard default\nvlan 10\n name USERS\n"
            "template ACCESS\n switchport mode access\n switchport access vlan 10\n spanning-tree portfast\n"
            " access-session port-control auto\n mab\n"
            "interface GigabitEthernet1/0/1\n source template ACCESS\n"
            "interface GigabitEthernet1/0/2\n no switchport\n ip address 10.9.9.1 255.255.255.0\n"
            "interface GigabitEthernet1/0/3.10\n encapsulation dot1Q 10\n"
            "interface GigabitEthernet1/0/4\n vrf forwarding Mgmt-vrf\n"
            "interface AppGigabitEthernet1/0/1\n switchport mode trunk\n")


def test_l2_routed_ports_skipped_and_templates_count():
    names = [p["name"] for p in ios_l2.ports(vendor_ios.ios_blocks(L2), {"_is_switch": True})]
    assert names == ["GigabitEthernet1/0/1"]
    res, _ = _res(L2, {"_is_switch": True})
    assert res["IOS-L2-PORT-AUTH"]["status"] == "pass"       # access-session / mab from the template
    assert res["IOS-L2-BPDUGUARD"]["status"] == "pass"       # portfast from the template + global bpduguard


def test_l2_show_switchport_decides(tmp_path):
    (tmp_path / "show-interfaces-switchport.txt").write_text(
        "Name: Gi1/0/1\nSwitchport: Enabled\nAdministrative Mode: static access\nOperational Mode: static access\n"
        "Access Mode VLAN: 10 (USERS)\nNegotiation of Trunking: Off\n"
        "Name: Gi1/0/5\nSwitchport: Disabled\n", encoding="utf-8")
    cfg = L2 + "interface GigabitEthernet1/0/5\n description routed but no ip line\ninterface GigabitEthernet1/0/6\n"
    names = [p["name"] for p in ios_l2.ports(vendor_ios.ios_blocks(cfg), {"_folder": str(tmp_path)})]
    assert names == ["GigabitEthernet1/0/1"]          # 1/0/6 is not listed by the show output


# ---------- 15: FortiGate snapshot date and local-in that restricts ----------
def test_snapshot_date_prefers_system_time(tmp_path):
    f = tmp_path / "get-system-status.txt"
    f.write_text("Version: FortiGate-VM64 v8.0.1\nSystem time: Wed Nov 12 09:15:02 2026\n", encoding="utf-8")
    assert str(fgt_hardening.snapshot_date(tmp_path, f)) == "2026-11-12"
    f.write_text("Version: FortiGate-VM64 v8.0.1\n", encoding="utf-8")
    tf._taken(tmp_path, "get-system-status.txt", "2026-05-01")
    assert str(fgt_hardening.snapshot_date(tmp_path, f)) == "2026-05-01"


def test_local_in_accept_from_all_does_not_cover():
    fabric = tf.IFACES.replace("set allowaccess ping\n        set role wan", "set allowaccess ping fabric fgfm\n"
                                                                              "        set role wan")
    li = ("config firewall local-in-policy\n    edit 1\n        set intf \"wan1\"\n        set srcaddr \"all\"\n"
          "        set dstaddr \"all\"\n        set action accept\n        set service \"ALL\"\n"
          "        set schedule \"always\"\n    next\nend\n")
    res, _ = tf.run(tf.cfg("", ifaces=fabric, extra=li))
    assert tf.status(res, "FGT-WAN-NO-LOCAL-IN") == ["fail"]
    res, _ = tf.run(tf.cfg("", ifaces=fabric, extra=li.replace("        set action accept\n", "")))
    assert tf.status(res, "FGT-WAN-NO-LOCAL-IN") == ["pass"]         # FortiOS default action is deny


# ---------- 17: end of support scores below the CVEs in the 3-day band ----------
def test_lifecycle_eos_scores_low_in_its_band():
    _, checks = seccheck.load_settings()
    c = checks["LIFECYCLE-EOS"]
    s = scoring.score(True, False, c["automatable"], c["total_control"], c["weight"], cap="3d", cve=False)
    assert s["deadline"] == "3d" and s["score"] <= 81


# ---------- 18: inventory names cannot leave the snapshot repo ----------
@pytest.mark.parametrize("site,name", [("..", "x"), ("hq", "../../etc"), ("hq", "a\\b"), ("h/q", "r1")])
def test_inventory_path_traversal_is_skipped(tmp_path, site, name):
    platforms, _ = seccheck.load_settings()
    out = seccheck.device_facts({"name": name, "site": site, "device_type": "cisco_ios"}, tmp_path, platforms)
    assert any("device skipped" in n for n in out["notes"]) and not out["findings"]


# ---------- 19 (R10): Table 1, sources, no secret in a full run ----------
# BOD 26-04 Appendix A Table 1, transcribed row by row (Exposed, KEV, Automatable, Total control).
TABLE_1 = [
    ((True, True, True, True), "3d+triage"), ((True, True, True, False), "3d"),
    ((True, True, False, True), "3d+triage"), ((True, True, False, False), "14d"),
    ((True, False, True, True), "3d"), ((True, False, True, False), "14d"),
    ((True, False, False, True), "14d"), ((True, False, False, False), "60d"),
    ((False, True, True, True), "3d+triage"), ((False, True, True, False), "14d"),
    ((False, True, False, True), "14d"), ((False, True, False, False), "14d"),
    ((False, False, True, True), "60d"), ((False, False, True, False), "60d"),
    ((False, False, False, True), "upgrade"), ((False, False, False, False), "upgrade"),
]


def test_bod_26_04_table_1_all_16_rows():
    assert dict(TABLE_1) == scoring.BOD_26_04 and len(TABLE_1) == 16


def test_every_check_source_is_in_sources_md():
    keys = set(re.findall(r"^\| ([a-z0-9-]+) \|", (HERE.parent / "research" / "sources.md").read_text(
        encoding="utf-8"), re.M))
    _, checks = seccheck.load_settings()
    missing = {(cid, s) for cid, c in checks.items() for s in c["sources"] if s not in keys}
    assert not missing and all(c["sources"] for c in checks.values())


SEEDS = {
    "hq/hq-edge-rtr-01/show-running-config-view-full.txt": (
        "snmp-server community SxLeakComm01 RW\n"
        "snmp-server host 10.0.0.9 version 2c SxLeakComm02\n"
        "username bob password 0 SxLeakUser03\n"
        "ntp authentication-key 1 md5 SxLeakNtp04 7\n"
        "ntp server 10.0.0.8 key 1\n"
        "tacacs-server key 7 SxLeakTac05\n"
        "snmp-server user ops OPS v3 auth sha SxLeakAuth06 priv aes 128 SxLeakPriv07\n"
        "interface Vlan77\n ip address 10.77.0.1 255.255.255.0\n standby 1 ip 10.77.0.254\n"
        " standby 1 authentication SxLeakHsrp08\n"
        "line vty 5 15\n password 7 SxLeakLine09\n"),
}


def test_no_secret_in_a_full_fixture_run(tmp_path):
    repo = tmp_path / "snapshots"
    shutil.copytree(FX / "snapshots", repo)
    for rel, extra in SEEDS.items():
        f = repo / rel
        f.write_text(f.read_text(encoding="utf-8").replace("\nend", "\n" + extra + "end"), encoding="utf-8")
    out = tmp_path / "out"
    shutil.copytree(FX / "advisories", out / "advisories")
    args = type("A", (), {"repo": str(repo), "out": str(out), "site": None, "device": None, "events": None,
                          "bucket_minutes": 60, "no_cves": True})()
    rep = seccheck.build(args)
    text = json.dumps({"findings": rep["findings"], "devices": rep["devices"],
                       "accepted": rep.get("accepted_risk")}, default=str)
    assert "SxLeakComm01" in (repo / next(iter(SEEDS))).read_text(encoding="utf-8")    # seeded
    leaks = sorted(set(re.findall(r"SxLeak\w+", text)))
    assert not leaks, leaks
    # the seeded lines did produce findings, so the scan covered them
    ids = {f["id"] for f in rep["findings"] if f.get("device") == "hq-edge-rtr-01"}
    assert {"IOS-SNMP-COMMUNITY", "IOS-PASSWORD-STORAGE", "IOS-FHRP-NO-AUTH"} <= ids
