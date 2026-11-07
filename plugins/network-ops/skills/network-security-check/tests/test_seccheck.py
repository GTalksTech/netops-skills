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
