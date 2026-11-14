# Tests for rollup.py (B1): dependent checks fold into their parent, advisory checks move to
# hygiene notes, and counts_unique counts a check failing on 3+ devices in one band once.
import copy
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import report  # noqa: E402
import rollup  # noqa: E402
import scoring  # noqa: E402
import seccheck  # noqa: E402

FX = HERE / "fixtures"


def _f(cid, device, score=5, deadline="upgrade", exposed=False, detail="d"):
    return {"type": "config", "id": cid, "title": f"{cid} title", "device": device, "detail": detail,
            "evidence": [f"line {device}"], "score": score, "deadline": deadline, "action": "x",
            "inputs": {"publicly_exposed": exposed}, "why": {}}


CHECKS = {"PARENT": {}, "CHILD": {"suppressed_by": ["PARENT"]}, "HYG": {"tier": "advisory"}, "PLAIN": {}}


# ---------- units ----------
def test_child_folds_into_parent_on_same_device_only():
    fs = [_f("PARENT", "a"), _f("CHILD", "a"), _f("CHILD", "b")]
    kept = rollup.fold_dependents(fs, CHECKS)
    assert [(f["id"], f["device"]) for f in kept] == [("PARENT", "a"), ("CHILD", "b")]
    parent = kept[0]
    assert [a["id"] for a in parent["also"]] == ["CHILD"] and parent["also"][0]["suppressed_by"] == "PARENT"
    assert "Also: CHILD" in parent["detail"]


def test_advisory_moves_to_hygiene_with_tier():
    scored, hyg = rollup.split_tiers([_f("HYG", "a"), _f("PLAIN", "a")], CHECKS)
    assert [f["id"] for f in hyg] == ["HYG"] and hyg[0]["tier"] == "advisory"
    assert [f["id"] for f in scored] == ["PLAIN"] and scored[0]["tier"] == "standard"


def test_rollup_needs_three_devices_in_one_band():
    fs = [_f("PLAIN", d, score=s) for d, s in (("a", 5), ("b", 9), ("c", 7))]
    fs += [_f("PLAIN", "d", score=40, deadline="60d"), _f("TWO", "a"), _f("TWO", "b")]
    fs += [{"type": "cve", "id": "CVE-1", "deadline": "upgrade", "score": 1, "devices": []}]
    u = rollup.unique(fs)
    assert [(f["id"], f["deadline"]) for f in u] == [("PLAIN", "upgrade"), ("PLAIN", "60d"), ("TWO", "upgrade"),
                                                     ("TWO", "upgrade"), ("CVE-1", "upgrade")]
    r = u[0]
    assert r["rollup"] and r["devices"] == ["a", "b", "c"] and r["score_range"] == [5, 9] and r["score"] == 9
    assert r["example_device"] == "b" and [p["device"] for p in r["per_device"]] == ["a", "b", "c"]
    assert rollup.counts(u)["upgrade"] == 4 and rollup.counts(fs)["upgrade"] == 6


def test_every_finding_reaches_folded_children():
    rep = {"findings": [{**_f("PARENT", "a"), "also": [_f("CHILD", "a")]}], "accepted_risk": [_f("X", "a")],
           "hygiene": [_f("HYG", "a")]}
    assert sorted(f["id"] for f in rollup.every_finding(rep)) == ["CHILD", "HYG", "PARENT", "X"]


# ---------- catalog ----------
def test_catalog_tiers_and_dependencies():
    checks = seccheck.load_settings()[1]
    adv = {k for k, v in checks.items() if v.get("tier") == "advisory"}
    for check in ("IOS-BANNER",
                  "IOS-NTP-REDUNDANT",
                  "IOS-L2-UNUSED-PORTS",
                  "IOS-L2-PORT-AUTH",
                  "IOS-L2-TRUNK-VLANS",
                  "FGT-VIP-UNUSED"):
        assert check in adv, check
    assert checks["IOS-AAA-ACCOUNTING"]["suppressed_by"] == ["IOS-AAA-CENTRAL"]
    assert checks["IOS-L2-DAI"]["suppressed_by"] == ["IOS-L2-DHCP-SNOOPING"]
    # no known-exploited or total-control check is ever demoted to hygiene
    assert not [k for k in adv if checks[k]["known_exploited"] or checks[k]["total_control"]]


def test_check_settings_rejects_bad_tier_and_suppressed_by(capsys):
    platforms, checks = seccheck.load_settings()
    bad = copy.deepcopy(checks)
    bad["IOS-BANNER"]["tier"] = "info"
    bad["IOS-L2-DAI"]["suppressed_by"] = ["NO-SUCH-CHECK"]
    bad["IOS-L2-DHCP-SNOOPING"]["suppressed_by"] = ["IOS-L2-DAI"]
    assert seccheck.check_settings(platforms, bad) == 1
    out = capsys.readouterr().out
    assert "tier 'info'" in out and "NO-SUCH-CHECK" in out and "no chains" in out


# ---------- full run on the fixtures ----------
@pytest.fixture(scope="module")
def checks():
    return seccheck.load_settings()[1]


@pytest.fixture(scope="module")
def rep(tmp_path_factory):
    out = tmp_path_factory.mktemp("out")
    shutil.copytree(FX / "advisories", out / "advisories")
    args = type("A", (), {"repo": str(FX / "snapshots"), "out": str(out), "site": None, "device": None,
                          "events": None, "bucket_minutes": 60, "no_cves": False})()
    return seccheck.build(args)


def test_counts_and_lists_agree(rep, checks):
    assert rep["counts"] == rollup.counts(rep["findings"])
    assert rep["counts_unique"] == rollup.counts(rep["findings_unique"])
    assert all(rep["counts_unique"][b] <= rep["counts"][b] for b in scoring.ORDER)
    assert rep["summary"]["counts_unique"] == rep["counts_unique"]
    assert all(f["tier"] == "advisory" for f in rep["hygiene"])
    assert not [f for f in rep["findings"] if f.get("tier") == "advisory"]
    top = {c for a in rep["summary"]["actions"] for c in a["checks"]}
    assert not top & {f["id"] for f in rep["hygiene"]}
    fails = sum(d["result_counts"]["fail"] for d in rep["devices"])
    assert fails == len([f for f in rollup.every_finding(rep) if f["type"] == "config"])


def test_markdown_uses_unique_counts_and_lists_hygiene(rep, checks):
    md = report.markdown(rep, checks)
    summary = md.split("## Summary", 1)[1].split("### Top actions", 1)[0]
    for b in scoring.ORDER:
        assert f"| {report._band_title(b)} | {rep['counts_unique'][b]} |" in summary
    assert "Counts are distinct problems" in summary
    findings = md.split("## Findings by deadline", 1)[1].split("\n## ", 1)[0]
    if rep["hygiene"]:
        assert "## Hygiene notes" in md
        for f in rep["hygiene"]:
            assert f"**{f['id']}**" not in findings and f"- {f['id']}:" not in findings
    page = report.html_report(rep, checks)
    assert "Counts are distinct problems" in page
    assert "—" not in md and "—" not in page


def test_rolled_up_fleet_counts_once(rep, checks):
    """Twelve copies of one switch failing the same checks: unique counts stay flat."""
    fleet = copy.deepcopy(rep)
    base = [f for f in fleet["findings"] if f["type"] == "config" and f["deadline"] == "upgrade"]
    if not base:
        pytest.skip("fixture has no lowest-band config findings")
    one = base[0]
    clones = [{**one, "device": f"sw-{i:02d}"} for i in range(1, 13)]
    u = rollup.unique(clones)
    assert len(u) == 1 and len(u[0]["devices"]) == 12 and len(u[0]["per_device"]) == 12
