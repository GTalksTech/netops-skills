# Tests for lifecycle.py (R8): software end-of-support per release train, CISA BOD 26-02.
# Dates are pinned with `today` so the tests do not change as the calendar moves.
import datetime as dt
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import lifecycle  # noqa: E402
import scoring  # noqa: E402
import seccheck  # noqa: E402

TODAY = dt.date(2026, 11, 13)
TABLE = lifecycle.load()


def _dev(platform, version, internet=False):
    return {"name": "d1", "platform": platform, "version": version, "internet_facing": internet, "kind": "router"}


def _st(results):
    return {r["check"]: r["status"] for r in results}


@pytest.mark.parametrize("version,expect", [
    ("17.09.04a", "17.9"), ("17.16.1a", "17.16"), ("v7.4.2", "7.4"), ("8.0.1", "8.0"),
    ("10.2.7-h3", "10.2"), ("21.4R3-S5.4", "21.4"), ("15.1X49-D200", None), ("", None)])
def test_train(version, expect):
    assert lifecycle.train(version) == expect


def test_every_check_in_catalog_and_table_valid():
    _, checks = seccheck.load_settings()
    assert set(lifecycle.CHECKS) <= set(checks)
    src = (HERE.parent / "research" / "sources.md").read_text(encoding="utf-8")
    keys = set(re.findall(r"^\| ([a-z0-9-]+) \|", src, re.M))
    assert lifecycle.validate(TABLE, keys) == []


def test_validate_catches_bad_rows():
    bad = {"x": {"name": "X", "vendor_page": "u", "as_of": "nope", "security_end": ["eos"], "labels": {"eos": "e"},
                 "trains": {"1.0": {"eos": "2026-13-40", "source": "missing-key"}, "2.0": {"source": "k"}}}}
    out = " ".join(lifecycle.validate(bad, {"k"}))
    assert "as_of" in out and "missing-key" in out and "2026-13-40" in out and "none of" in out


def test_ios_xe_17_16_past_security_support():
    res = lifecycle.evaluate(_dev("cisco_ios", "17.16.1a", internet=True), TABLE, TODAY)
    assert _st(res) == {"LIFECYCLE-EOS": "fail", "LIFECYCLE-SOON": "n/a"}
    eos = res[0]
    assert "2026-01-13" in eos["detail"] and "ios-xe-17-16-x-eol" in eos["detail"] and eos["exposed"]


def test_soon_and_pass():
    res = lifecycle.evaluate(_dev("paloalto_panos", "10.2.7-h3", internet=True), TABLE, TODAY)
    assert _st(res) == {"LIFECYCLE-EOS": "pass", "LIFECYCLE-SOON": "fail"}
    assert "2027-03-31" in res[1]["detail"] and res[1]["exposed"] is False   # planning item, never exposed
    res = lifecycle.evaluate(_dev("cisco_ios", "17.15.01"), TABLE, TODAY)
    assert _st(res) == {"LIFECYCLE-EOS": "pass", "LIFECYCLE-SOON": "pass"}


def test_boundary_last_day_still_supported():
    end = dt.date(2026, 9, 30)    # IOS-XE 17.9 end of vulnerability support
    assert _st(lifecycle.evaluate(_dev("cisco_ios", "17.9.4"), TABLE, end))["LIFECYCLE-EOS"] == "pass"
    assert _st(lifecycle.evaluate(_dev("cisco_ios", "17.9.4"), TABLE, end + dt.timedelta(1)))["LIFECYCLE-EOS"] == "fail"


def test_junos_uses_end_of_engineering_and_fortios_8_unknown():
    res = lifecycle.evaluate(_dev("juniper_junos", "21.4R3-S4.9"), TABLE, TODAY)
    assert _st(res)["LIFECYCLE-EOS"] == "fail" and "end of engineering" in res[0]["detail"]
    res = lifecycle.evaluate(_dev("fortinet", "8.0.1"), TABLE, TODAY)
    assert _st(res) == {"LIFECYCLE-EOS": "n/a", "LIFECYCLE-SOON": "n/a"}
    assert "lifecycle unknown for FortiOS train 8.0, check vendor page" in res[0]["detail"]


def test_no_table_and_no_version():
    assert set(_st(lifecycle.evaluate(_dev("cisco_asa", "9.18(3)56"), TABLE, TODAY)).values()) == {"n/a"}
    assert set(_st(lifecycle.evaluate(_dev("cisco_ios", None), TABLE, TODAY)).values()) == {"not-visible"}


def test_stale_table_note():
    assert lifecycle.stale_notes(TABLE, TODAY) == []
    notes = lifecycle.stale_notes(TABLE, TODAY + dt.timedelta(days=200))
    assert len(notes) == len(TABLE) and "re-read" in notes[0]


def test_apply_adds_results_findings_and_counts():
    facts = [{**_dev("cisco_ios", "17.16.1a", internet=True), "results": [], "findings": [],
              "result_counts": {"pass": 0, "fail": 0, "n/a": 0, "not-visible": 0}},
             {"name": "x", "platform": "unknown", "results": [], "findings": []}]     # no "kind": skipped
    notes = []
    lifecycle.apply(facts, notes, today=TODAY, table=TABLE)
    assert [f["check"] for f in facts[0]["findings"]] == ["LIFECYCLE-EOS"]
    assert facts[0]["result_counts"]["fail"] == 1 and facts[0]["result_counts"]["n/a"] == 1
    assert facts[1]["results"] == []
    assert any("hardware end of life" in n for n in notes)


def test_scoring_house_rule():
    """SCORING.md rule 10: internet-facing end of support = 3 days, internal = 60 days, soon = lowest band."""
    _, checks = seccheck.load_settings()
    c = checks["LIFECYCLE-EOS"]
    edge = scoring.score(True, c["known_exploited"], c["automatable"], c["total_control"], c["weight"], "3d", cve=False)
    inside = scoring.score(False, False, c["automatable"], c["total_control"], c["weight"], "3d", cve=False)
    assert edge["deadline"] == "3d" and inside["deadline"] == "60d"
    s = checks["LIFECYCLE-SOON"]
    assert scoring.score(False, False, s["automatable"], s["total_control"], s["weight"], "3d",
                         cve=False)["deadline"] == "upgrade"
