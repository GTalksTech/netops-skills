# Tests for network-security-check. Everything runs offline from tests/fixtures:
#   snapshots/   seven devices laid out the way network-snapshot saves them
#   advisories/  a real advisory cache (CVE.org, CISA KEV, FIRST EPSS), fetched 2026-11-07
#                with: seccheck.py fetch --cves <the IDs in it>
#   events/      firewall event exports, built by make_events.py
import json
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import advisories  # noqa: E402
import events  # noqa: E402
import scoring  # noqa: E402
import seccheck  # noqa: E402
import versions  # noqa: E402

FX = HERE / "fixtures"


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    out = tmp_path_factory.mktemp("out")
    shutil.copytree(FX / "advisories", out / "advisories")
    args = type("A", (), {"repo": str(FX / "snapshots"), "out": str(out), "site": None, "device": None,
                          "events": [str(p) for p in sorted((FX / "events").iterdir())],
                          "bucket_minutes": 60, "no_cves": False})()
    return seccheck.build(args)


def find(rep, fid, device=None):
    return [f for f in rep["findings"] if f["id"] == fid and (device is None or f.get("device") == device
                                                              or device in [d["device"] for d in f.get("devices", [])])]


# ---------- scoring ----------
def test_bod_table_has_all_16_rows():
    assert len(scoring.BOD_26_04) == 16


@pytest.mark.parametrize("row,expected", [
    ((True, True, True, True), "3d+triage"), ((True, True, False, False), "14d"),
    ((True, False, True, True), "3d"), ((True, False, False, False), "60d"),
    ((False, True, True, True), "3d+triage"), ((False, True, False, False), "14d"),
    ((False, False, True, True), "60d"), ((False, False, False, False), "upgrade")])
def test_bod_rows_match_cisa_table(row, expected):
    assert scoring.deadline(*row) == expected


def test_bands_do_not_overlap_and_order_by_deadline():
    tops = [scoring.BANDS[b][1] for b in scoring.ORDER]
    lows = [scoring.BANDS[b][0] for b in scoring.ORDER]
    assert all(lows[i] > tops[i + 1] for i in range(len(tops) - 1))


def test_cap_never_raises_a_score():
    low = scoring.score(False, False, False, False, 0.5, cap="14d")
    assert low["deadline"] == "upgrade"
    high = scoring.score(True, True, True, True, 0.5, cap="14d")
    assert high["deadline"] == "14d"


def test_cvss_fallback():
    assert scoring.from_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == (True, True)
    assert scoring.from_cvss("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N") == (False, False)
    assert scoring.from_cvss(None) == (None, None)


# ---------- versions ----------
@pytest.mark.parametrize("a,b,expect", [
    ("17.09.04a", "17.9.4a", 0), ("17.9.4", "17.9.4a", -1), ("10.2.7", "10.2.7-h1", -1),
    ("10.2.7-h3", "10.2.8", -1), ("9.18(3)56", "9.18.3.56", 0), ("21.4R3-S5.4", "21.4R3-S6", -1),
    ("4.30.2F", "4.30.10F", -1), ("FL.10.10.1000", "10.10.1000", 0)])
def test_version_compare(a, b, expect):
    assert versions.cmp(a, b) == expect


@pytest.mark.parametrize("ver,expect", [
    ("10.2.7-h3", "affected"), ("10.2.7-h8", "unaffected"),   # fixed on its own release
    ("10.2.8", "affected"),        # missing from Palo Alto's x_affectedList, caught by its ranges
    ("10.2.8-h3", "unaffected"), ("10.2.9", "affected"), ("10.2.9-h1", "unaffected"),
    ("10.2.10", "unaffected"), ("10.1.11", "unaffected")])
def test_panos_cve_2024_3400(ver, expect):
    # Expected values from Palo Alto's advisory for CVE-2024-3400 (fixed in 10.2.7-h8, 10.2.8-h3,
    # 10.2.9-h1). CVE.org's copy of the record flags 10.2.7-h8 as affected, so it is not used.
    rec = json.loads((FX / "advisories/cve/CVE-2024-3400.json").read_text())
    assert versions.affected_by(ver, rec["affected"], "^PAN-OS$")[0] == expect


def test_fortios_semver_ranges():
    rec = json.loads((FX / "advisories/cve/CVE-2024-21762.json").read_text())
    assert versions.affected_by("7.4.2", rec["affected"], "^FortiOS$")[0] == "affected"
    assert versions.affected_by("7.4.3", rec["affected"], "^FortiOS$")[0] == "unaffected"


def test_cisco_enumerated_versions():
    rec = json.loads((FX / "advisories/cve/CVE-2023-20198.json").read_text())
    rx = seccheck.load_settings()[0]["cisco_ios"]["cna_product"]
    assert versions.affected_by("17.09.04", rec["affected"], rx)[0] == "affected"
    assert versions.affected_by("17.09.04a", rec["affected"], rx)[0] == "unaffected"


def test_junos_ranges():
    rec = json.loads((FX / "advisories/cve/CVE-2023-36845.json").read_text())
    assert versions.affected_by("21.4R3-S4.9", rec["affected"], "^Junos OS$")[0] == "affected"
    assert versions.affected_by("21.4R3-S5", rec["affected"], "^Junos OS$")[0] == "unaffected"


# ---------- settings ----------
def test_every_check_is_sourced():
    platforms, checks = seccheck.load_settings()
    assert seccheck.check_settings(platforms, checks) == 0


def test_every_emitted_check_is_in_catalog(report):
    _, checks = seccheck.load_settings()
    assert {f["id"] for f in report["findings"] if f["type"] != "cve"} <= set(checks)


# ---------- report: CVEs ----------
def test_cves_hit_the_right_devices(report):
    hits = {f["id"]: sorted(d["device"] for d in f["devices"]) for f in report["findings"] if f["type"] == "cve"}
    assert hits["CVE-2023-20198"] == ["hq-edge-rtr-01"]          # 17.09.04; core switch runs the fix 17.09.04a
    assert hits["CVE-2024-3400"] == ["pa-fw-01"]
    assert hits["CVE-2024-21762"] == ["fw-01"]
    assert hits["CVE-2023-36845"] == ["srx-01"]
    for cid in ("CVE-2023-20198", "CVE-2018-0171", "CVE-2017-6742"):
        assert "hq-acc-sw-01" not in hits.get(cid, [])            # 17.15.01 has those fixes


def test_kev_on_exposed_feature_is_3_days_and_triage(report):
    f = find(report, "CVE-2024-3400")[0]
    assert f["deadline"] == "3d+triage"
    assert "GlobalProtect" in f["why"]["publicly_exposed"]
    assert f["why"]["automatable"] == "CISA Vulnrichment"


def test_cve_titles_are_readable(report):
    for f in report["findings"]:
        if f["type"] == "cve":
            assert not f["title"].lower().startswith("cisco is providing an update")


# ---------- report: config ----------
def test_outbound_lan_to_internet_is_not_any_any(report):
    assert not [f for f in find(report, "FGT-ANY-ANY") if "LAN-to-Internet" in f["detail"]]


def test_disabled_rules_are_ignored(report):
    assert not [f for f in report["findings"] if "temp-troubleshoot" in str(f.get("detail"))
                or "Allow All Temp" in str(f.get("detail"))]


def test_segment_finding_replaces_any_any(report):
    assert find(report, "FGT-SEGMENT", "fw-01") and find(report, "PAN-SEGMENT", "pa-fw-01")
    assert not [f for f in find(report, "FGT-ANY-ANY") if "IoT" in f["detail"]]
    assert not find(report, "PAN-ANY-ANY")


def test_iot_svi_without_acl_is_flagged_but_guest_with_acl_is_not(report):
    seg = find(report, "IOS-SEGMENT-ROUTED", "hq-core-sw-01")
    assert len(seg) == 1 and "Vlan30" in seg[0]["detail"]


def test_asa_inside_permit_any_is_not_flagged(report):
    assert not find(report, "ASA-ANY-ANY")


def test_clean_switch_has_no_findings(report):
    assert not [f for f in report["findings"] if f.get("device") == "hq-acc-sw-01"]


def test_vip_not_used_by_any_policy_is_not_flagged(report):
    assert not [f for f in find(report, "FGT-VIP-RISKY") if "web-server" in f["detail"]]


def test_config_findings_never_ask_for_forensic_triage(report):
    assert all(f["deadline"] != "3d+triage" for f in report["findings"] if f["type"] == "config")


def test_internal_known_exploited_config_is_not_3_days(report):
    f = find(report, "JUNOS-HTTP", "srx-01")[0]     # http on, but untrust only allows https
    assert f["inputs"]["publicly_exposed"] is False and f["deadline"] in ("60d", "upgrade")


def test_smart_install_note_only_on_switches(report):
    notes = {d["name"]: d["notes"] for d in report["devices"]}
    assert not any("vstack" in n for n in notes["hq-edge-rtr-01"])


def test_stale_ips_signatures(report):
    assert find(report, "FGT-IPS-STALE", "fw-01")


def test_snmp_community_is_not_printed(report):
    assert "public" not in json.dumps(find(report, "IOS-SNMP-COMMUNITY")[0]["evidence"])


# ---------- report: events ----------
def test_one_finding_per_campaign(report):
    gp = [f for f in report["findings"] if f["type"] == "event" and "95187" in json.dumps(f)]
    assert [f["id"] for f in gp] == ["EV-TARGETS-VULNERABLE"]
    assert "NOT blocked" in gp[0]["detail"] and "pa-fw-01 directly" in gp[0]["detail"]


def test_attacks_seen_raise_the_cve(report):
    assert find(report, "CVE-2023-20198")[0]["attacks_seen"] is True


def test_scanner_spike_is_capped_when_all_blocked(report):
    sp = find(report, "EV-SPIKE-SOURCE")
    assert len(sp) == 1 and "198.51.100.99" in sp[0]["detail"] and sp[0]["deadline"] == "60d"


def test_unblocked_critical_is_reported(report):
    assert [f for f in find(report, "EV-NOT-BLOCKED") if "RDP" in f["detail"]]


def test_event_formats_parse():
    assert len(events.read_events(FX / "events/pan-threat.csv")) == 417
    fg = events.read_events(FX / "events/fortigate-ips.log")
    assert fg and all(e["sig_id"] for e in fg)
    eve = events.read_events(FX / "events/eve.json")
    assert len(eve) == 9 and eve[0]["cves"] == ["CVE-2023-20198"] and not eve[0]["blocked"]


def test_modified_z_matches_nist_definition():
    med, z = events.modified_z([1, 2, 3, 4, 100])
    assert med == 3 and round(z[-1], 2) == round(0.6745 * 97 / 1, 2)


# ---------- round 2: real advisory data ----------
def _dev(f, name):
    return next(d for d in f["devices"] if d["device"] == name)


def test_feature_off_goes_to_next_upgrade(report):
    sdwan = find(report, "CVE-2025-20221")[0]                    # SD-WAN only
    assert all(d["deadline"] == "upgrade" and d["feature_off"] for d in sdwan["devices"])
    dhcp = find(report, "CVE-2025-20162")[0]                     # DHCP snooping only
    assert _dev(dhcp, "hq-edge-rtr-01")["deadline"] == "upgrade"


def test_same_cve_scores_per_device_exposure(report):
    snmp = find(report, "CVE-2025-20352")[0]                     # KEV, SNMP RCE
    assert _dev(snmp, "hq-edge-rtr-01")["deadline"] == "3d+triage"   # community with no ACL, public IP
    assert _dev(snmp, "hq-core-sw-01")["deadline"] == "14d"          # SNMP on, ACL, internal
    assert "not on an internet-facing" in _dev(snmp, "hq-core-sw-01")["why"]["publicly_exposed"]


def test_adjacent_attack_vector_is_not_public():
    rec = {"id": "CVE-X", "title": "", "description": "", "cvss": {"vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
           "ssvc": {"automatable": "yes", "technical_impact": "total"}}
    dev = {"internet_facing": True, "exposure_reason": "public IP", "features": {}}
    exposed, *_ , why, off, named = seccheck.cve_inputs({"record": rec}, dev, {"features": {}},
                                                        {"kev": {}}, set())
    assert exposed is False and "Adjacent" in why["publicly_exposed"]


def test_upgrade_plan_rolls_up_per_device(report):
    plan = {r["device"]: r for r in report["upgrade_plan"]}
    assert plan["hq-edge-rtr-01"]["worst"] == "3d+triage"
    assert plan["hq-edge-rtr-01"]["cves"] == sum(plan["hq-edge-rtr-01"]["by_deadline"].values())


def test_inventory_exposure_override(tmp_path):
    repo = tmp_path / "snap"
    shutil.copytree(FX / "snapshots", repo)
    inv = (repo / "inventory.yaml").read_text().replace(
        "{name: hq-core-sw-01,  host: 192.0.2.232, site: hq}",
        "{name: hq-core-sw-01,  host: 192.0.2.232, site: hq, exposure: public}")
    (repo / "inventory.yaml").write_text(inv)
    platforms, _ = seccheck.load_settings()
    dev = next(d for d in seccheck.load_devices(repo) if d["name"] == "hq-core-sw-01")
    facts = seccheck.device_facts(dev, repo, platforms)
    assert facts["internet_facing"] is True and "inventory" in facts["exposure_reason"]


# ---------- round 3: independent review ----------
import vendor_asa  # noqa: E402
import vendor_fortios  # noqa: E402
import vendor_ios  # noqa: E402
import vendor_junos  # noqa: E402
import vendor_panos  # noqa: E402
import parsers  # noqa: E402


def ids(found):
    return sorted(f["check"] for f in found)


def test_fortios_multi_vdom_keeps_interfaces():
    text = (FX / "snapshots/hq/fw-01/show.txt").read_text()
    head, rest = text.split("config vpn ssl settings", 1)
    wrapped = ("config global\n" + head.split("\n", 1)[1] + "end\nconfig vdom\nedit root\n"
               "config vpn ssl settings" + rest + "next\nend\n")
    facts, found = vendor_fortios.analyze(wrapped, {})
    assert "wan1" in facts["internet_interfaces"]
    assert {"FGT-MGMT-ON-WAN", "FGT-VIP-RISKY", "FGT-ADMIN-NO-TRUSTHOST"} <= set(ids(found))


def test_unparsed_config_never_marks_features_off(tmp_path):
    repo = tmp_path / "snap"
    shutil.copytree(FX / "snapshots", repo)
    (repo / "dc/pa-fw-01/show-config-running.txt").write_text("set deviceconfig system hostname pa-fw-01\n")
    platforms, _ = seccheck.load_settings()
    dev = next(d for d in seccheck.load_devices(repo) if d["name"] == "pa-fw-01")
    facts = seccheck.device_facts(dev, repo, platforms)
    assert facts["features"] == {} and facts["internet_facing"] is True
    assert any("parsed to no interfaces" in n for n in facts["notes"])


def test_junos_apply_groups():
    cfg = """set groups SEC system services telnet connection-limit 5
set groups SEC security zones security-zone untrust host-inbound-traffic system-services all
set apply-groups SEC
set system services web-management http interface ge-0/0/0.0
set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.18/30
set security zones security-zone untrust interfaces ge-0/0/0.0
"""
    facts, found = vendor_junos.analyze(cfg, {})
    assert "JUNOS-TELNET" in ids(found)
    assert facts["features"]["jweb"]["internet"] is True


def test_ios_banner_text_is_not_config():
    cfg = "hostname r1\nbanner motd ^C\nip http server\nsnmp-server community public RW\n^C\n" \
          "ip ssh version 2\nlogging host 10.0.0.5\nline vty 0 4\n access-class 5 in\n transport input ssh\n"
    _, found = vendor_ios.analyze(cfg, {})
    assert "IOS-HTTP-SERVER" not in ids(found) and "IOS-SNMP-COMMUNITY" not in ids(found)


def test_ios_public_ip_in_mgmt_vrf_is_not_internet():
    cfg = "hostname r1\ninterface GigabitEthernet0\n vrf forwarding Mgmt-intf\n ip address 198.51.100.9 255.255.255.0\n" \
          "ip http secure-server\nip ssh version 2\nlogging host syslog.lab.local\nline vty 0 4\n transport input ssh\n"
    facts, found = vendor_ios.analyze(cfg, {})
    assert facts["internet_facing"] is False
    assert "IOS-NO-REMOTE-LOG" not in ids(found)                 # hostname syslog target counts


def test_ios_dhcp_wan_with_nat_outside_is_internet():
    cfg = "hostname r1\ninterface Gi0/0\n ip address dhcp\n ip nat outside\nsnmp-server community public RO\n" \
          "ip ssh version 2\nlogging host 10.0.0.5\n"
    facts, found = vendor_ios.analyze(cfg, {})
    assert facts["internet_facing"] is True
    assert next(f for f in found if f["check"] == "IOS-SNMP-COMMUNITY")["exposed"] is True


def test_ios_vty_transport_none_is_not_flagged():
    cfg = "hostname r1\nip ssh version 2\nlogging host 10.0.0.5\nline vty 0 4\n access-class 5 in\n transport input ssh\n" \
          "line vty 5 15\n transport input none\n"
    _, found = vendor_ios.analyze(cfg, {})
    assert "IOS-VTY-ACL" not in ids(found)


def test_ios_guest_acl_with_first_deny_to_one_host_is_still_open():
    cfg = """hostname s1
vlan 40
 name GUEST
interface Vlan10
 ip address 10.1.10.1 255.255.255.0
interface Vlan40
 ip address 10.1.40.1 255.255.255.0
 ip access-group G in
ip access-list extended G
 10 deny ip any host 10.1.10.5
 20 permit ip any any
ip ssh version 2
logging host 10.0.0.5
"""
    _, found = vendor_ios.analyze(cfg, {})
    assert "IOS-SEGMENT-ROUTED" in ids(found)


def test_asa_management_nameif_and_single_jump_host():
    cfg = """hostname a1
interface Management1/1
 management-only
 nameif management
 security-level 100
 ip address 198.51.100.40 255.255.255.0
interface Gi1/1
 nameif outside
 security-level 0
 ip address 203.0.113.9 255.255.255.0
http server enable
http 198.51.100.0 255.255.255.0 management
ssh 203.0.113.50 255.255.255.255 outside
access-list OUT extended permit ip any4 any4 inactive
access-group OUT in interface outside
logging host management 10.0.0.5
"""
    facts, found = vendor_asa.analyze(cfg, {})
    assert facts["internet_interfaces"] == ["outside"]
    mg = [f for f in found if f["check"] == "ASA-MGMT-ON-OUTSIDE"]
    assert len(mg) == 1 and mg[0]["exposed"] is False and "http" not in mg[0]["detail"]
    assert "ASA-ANY-ANY" not in ids(found)


def test_asa_all_ports_nat_needs_an_open_acl():
    assert not [f for f in vendor_asa.analyze((FX / "snapshots/branch1/asa-01/show-running-config.txt").read_text(), {})[1]
                if f["check"] == "ASA-NAT-RISKY" and "all ports" in f["detail"]]


def test_fortios_profile_group_counts_as_ips_and_vipgrp_resolves():
    cfg = """config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.248
        set role wan
    next
end
config firewall vip
    edit "rdp"
        set extip 203.0.113.11
        set mappedip "10.0.0.5"
        set extintf "wan1"
        set portforward enable
        set extport 3389
        set mappedport 3389
    next
end
config firewall vipgrp
    edit "pub"
        set interface "wan1"
        set member "rdp"
    next
end
config firewall policy
    edit 7
        set srcintf "wan1"
        set dstintf "internal"
        set action accept
        set srcaddr "all"
        set dstaddr "pub"
        set service "RDP"
        set utm-status enable
        set profile-type group
        set profile-group "strict"
    next
end
"""
    _, found = vendor_fortios.analyze(cfg, {})
    assert "FGT-VIP-RISKY" in ids(found) and "FGT-INBOUND-NO-IPS" not in ids(found)


def test_panos_post_rulebase_is_read():
    text = (FX / "snapshots/dc/pa-fw-01/show-config-running.txt").read_text().replace(
        "          rulebase {", "          post-rulebase {")
    _, found = vendor_panos.analyze(text, {})
    assert "PAN-SEGMENT" in ids(found)


def test_truncated_panos_config_does_not_crash():
    parsers.panos_tree("config { devices { x { network { interface { ethernet { e1 { layer3 { ip [ 1.2.3.4/24")


@pytest.mark.parametrize("a,b,expect", [("4.31.1.1F", "4.31.1F", 1), ("4.28.10.1M", "4.28.10M", 1),
                                         ("7.6.0", "7.6", 0)])
def test_version_compare_round3(a, b, expect):
    assert versions.cmp(a, b) == expect


def test_train_wildcard_bound():
    assert versions.status_in_entry("21.4R3-S5", {"version": "21.4", "lessThan": "21.4*", "status": "affected"}) == "affected"


def test_corrupt_cache_record_is_skipped(tmp_path):
    shutil.copytree(FX / "advisories", tmp_path / "adv")
    (tmp_path / "adv/cve/CVE-2024-3400.json").write_text("{not json")
    cache = advisories.load(tmp_path / "adv")
    assert "CVE-2024-3400" not in cache["records"] and cache["records"]


# ---------- more vendors (snapshot profiles added by health-check v2) ----------
def test_dell_train_wildcard(report):
    assert "dell-sw-01" in [d["device"] for d in find(report, "CVE-2024-37125")[0]["devices"]]   # "10.5.5.x"


def test_exos_and_procurve_match_via_nvd(report):
    assert find(report, "CVE-2023-43119")[0]["devices"][0]["matched_by"] == "NVD CPE data"
    assert find(report, "CVE-2023-39267")[0]["devices"][0]["device"] == "hp-sw-01"


def test_manual_vendors_get_a_note_not_a_guess(report):
    d = {x["name"]: x for x in report["devices"]}
    assert d["huawei-sw-01"]["version"] == "V200R005C10SPC800"
    assert any("by hand" in n for n in d["nokia-pe-01"]["notes"])
    assert not [f for f in report["findings"] if f["type"] == "cve"
                and {"huawei-sw-01", "nokia-pe-01"} & {x["device"] for x in f["devices"]}]


def test_models_from_other_files(report):
    d = {x["name"]: x for x in report["devices"]}
    assert d["exos-sw-01"]["model"] == "X465-48W" and d["dell-sw-01"]["model"] == "S5248F-ON"


# ---------- round 4: real lab v2 output (IOL IOS-XE 17.16.1a, FortiGate-VM 8.0.1), sanitized ----------
LAB = FX / "lab-v2"


def _lab_ios(folder=LAB / "hq-edge-rtr-01"):
    text = (LAB / "hq-edge-rtr-01/show-running-config-view-full.txt").read_text(encoding="utf-8")
    return vendor_ios.analyze(text, {"_folder": folder})


def test_lab_versions_parse():
    platforms, _ = seccheck.load_settings()
    import re
    ios = re.search(platforms["cisco_ios"]["version"]["regex"],
                    (LAB / "hq-edge-rtr-01/show-version.txt").read_text(encoding="utf-8"), re.M)
    fgt = re.search(platforms["fortinet"]["version"]["regex"],
                    (LAB / "fw-01/get-system-status.txt").read_text(encoding="utf-8"), re.M)
    assert next(g for g in ios.groups() if g) == "17.16.1a"
    assert next(g for g in fgt.groups() if g) == "8.0.1"


def test_lab_ssh_v2_read_from_show_ip_ssh(tmp_path):
    # 17.x writes no "ip ssh version 2" line; "show ip ssh" says version 2.0
    _, found = _lab_ios()
    assert "IOS-SSH-V1" not in ids(found)
    # without the show output, the missing config line is still reported
    _, found = _lab_ios(folder=tmp_path)
    assert "IOS-SSH-V1" in ids(found)
    (tmp_path / "show-ip-ssh.txt").write_text("SSH Enabled - version 1.99\n")
    _, found = _lab_ios(folder=tmp_path)
    assert "IOS-SSH-V1" in ids(found)


def test_lab_feature_conditions_off():
    facts, _ = _lab_ios()
    for f in ("http_server", "ssl_vpn", "webauth", "nbar_capwap", "beep", "xmcp", "meraki"):
        assert facts["features"][f]["on"] is False, f


def test_feature_conditions_on():
    text = (LAB / "hq-edge-rtr-01/show-running-config-view-full.txt").read_text(encoding="utf-8")
    text = text.replace("no ip http server\n", "ip http server\n") + "\n".join([
        "crypto ssl policy RA", " ip address local 198.51.100.9 port 443", "!",
        "ip admission name WA proxy http", "ip nbar classification tunneled-traffic capwap",
        "netconf beep listener 26 acl 101 sasl P1 encrypt 25", "service-routing xmcp listen",
        "service meraki connect", "!"]) + "\n"
    facts, _ = vendor_ios.analyze(text, {})
    for f in ("http_server", "ssl_vpn", "webauth", "nbar_capwap", "beep", "xmcp", "meraki"):
        assert facts["features"][f]["on"] is True, f
    # crypto ssl policy with shutdown is off; webauth needs the HTTP server too
    off = text.replace(" ip address local 198.51.100.9 port 443", " shutdown").replace(
        "ip http server\n", "no ip http server\n")
    facts, _ = vendor_ios.analyze(off, {})
    assert not facts["features"]["ssl_vpn"]["on"] and not facts["features"]["webauth"]["on"]


@pytest.mark.parametrize("text,feat", [
    ("A vulnerability in the web services of Cisco Secure Firewall ASA, Cisco IOS XE Software", "ssl_vpn"),
    ("A vulnerability in the HTTP API subsystem of Cisco IOS XE Software", "http_server"),
    ("A vulnerability in the Web Authentication feature of Cisco IOS XE Software", "webauth"),
    ("A vulnerability in Cisco IOS XE Software for Cisco Meraki could allow", "meraki"),
    ("the Network-Based Application Recognition (NBAR) feature ... malformed CAPWAP packets", "nbar_capwap"),
    ("the Blocks Extensible Exchange Protocol (BEEP) feature of Cisco IOS XE", "beep"),
    ("the Extensible Messaging Client Protocol (XMCP) of Cisco IOS Software", "xmcp")])
def test_cve_text_names_the_feature(text, feat):
    import re
    platforms, _ = seccheck.load_settings()
    assert re.search(platforms["cisco_ios"]["features"][feat], text, re.I)


def _lab_fgt(text=None, user="claude-ro-cli"):
    text = text or (LAB / "fw-01/show.txt").read_text(encoding="utf-8")
    return vendor_fortios.analyze(text, {"username": user})


def test_lab_inbound_from_named_sources_is_not_internet():
    facts, found = _lab_fgt()
    hits = [f for f in found if f["check"] in ("FGT-INBOUND-ANY-SERVICE", "FGT-INBOUND-NO-IPS")]
    assert len(hits) == 2 and not any(f["exposed"] for f in hits)
    assert all("WAN side, limited to wan-side-lab-sources" in f["detail"] for f in hits)
    assert facts["internet_interfaces"] == ["port2"]


def test_lab_inbound_from_all_is_internet():
    text = (LAB / "fw-01/show.txt").read_text(encoding="utf-8").replace(
        'set srcaddr "wan-side-lab-sources"', 'set srcaddr "all"')
    _, found = _lab_fgt(text)
    hit = [f for f in found if f["check"] == "FGT-INBOUND-ANY-SERVICE"]
    assert hit and hit[0]["exposed"] and "from internet" in hit[0]["detail"]


def test_lab_admin_list_partial_gets_a_note():
    facts, found = _lab_fgt()
    assert any("trusted hosts of the other admin accounts were not checked" in n for n in facts["notes"])
    assert "FGT-ADMIN-NO-TRUSTHOST" not in ids(found)
    facts, _ = _lab_fgt(user="someone-else")
    assert not any("were not checked" in n for n in facts["notes"])
