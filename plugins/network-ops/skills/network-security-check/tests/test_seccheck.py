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
