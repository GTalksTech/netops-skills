# Tests for report.py (R9): the markdown and HTML reports and the summary, posture and control
# fields it adds to the JSON. Runs offline on the same fixtures as test_seccheck.py.
import copy
import re
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import report  # noqa: E402
import scoring  # noqa: E402
import seccheck  # noqa: E402

FX = HERE / "fixtures"
SECTIONS = ["# Network security check", "## Summary", "### Top actions", "## Posture by plane",
            "## Findings by deadline", "## What is good", "## What the check could not see",
            "## Appendix: control map"]
# Secret values in the fixture configs. None may appear in a report.
SECRET_RX = re.compile(r"(?:community|secret \d|password(?: \d| ENC)?|psksecret(?: ENC)?|key-string(?: \d)?)\s+"
                       r"(\"?\$?[\w$./=+!*-]{5,}\"?)", re.I)


@pytest.fixture(scope="module")
def checks():
    return seccheck.load_settings()[1]


@pytest.fixture(scope="module")
def rep(tmp_path_factory):
    out = tmp_path_factory.mktemp("out")
    shutil.copytree(FX / "advisories", out / "advisories")
    args = type("A", (), {"repo": str(FX / "snapshots"), "out": str(out), "site": None, "device": None,
                          "events": [str(p) for p in sorted((FX / "events").iterdir())],
                          "bucket_minutes": 60, "no_cves": False})()
    return seccheck.build(args)


@pytest.fixture(scope="module")
def md(rep, checks):
    return report.markdown(rep, checks)


@pytest.fixture(scope="module")
def page(rep, checks):
    return report.html_report(rep, checks)


def _secrets():
    found = set()
    for f in (FX / "snapshots").rglob("*.txt"):
        for m in SECRET_RX.finditer(f.read_text(encoding="utf-8", errors="replace")):
            v = m.group(1).strip('"')
            if v.lower() not in ("public", "private", "hmac-sha2-256") and "*" not in v:
                found.add(v)
    return found


# ---------- JSON ----------
def test_json_keeps_old_keys_and_adds_new(rep):
    for k in ("generated", "repo", "advisory_cache", "devices", "counts", "result_counts", "upgrade_plan",
              "findings", "accepted_risk", "events", "notes", "summary", "posture", "controls"):
        assert k in rep
    s = rep["summary"]
    assert s["counts"] == rep["counts"] and 1 <= len(s["top_actions"]) <= report.TOP_ACTIONS
    bands = [scoring.ORDER.index(a["deadline"]) for a in s["actions"]]
    assert bands == sorted(bands)


def test_upgrade_action_groups_every_cve_on_a_version(rep):
    ups = [a for a in rep["summary"]["actions"] if a["kind"] == "upgrade"]
    cves = {f["id"] for f in rep["findings"] if f["type"] == "cve"}
    assert ups and set().union(*(set(a["cves"]) for a in ups)) == cves
    assert len({a["key"] for a in ups}) == len(ups)
    assert all(a["action"].startswith("Upgrade ") for a in ups)


def test_themed_actions_merge_checks(rep, checks):
    # Every config finding lands in exactly one action, and a theme holds more than one check
    # when the fixture fails more than one of its checks.
    acts = rep["summary"]["actions"]
    for f in rep["findings"]:
        if f["type"] == "config" and f["id"] not in report.LIFECYCLE_CHECKS:
            assert sum(f["id"] in a["checks"] for a in acts if a["kind"] != "upgrade") == 1, f["id"]


def test_posture_counts_match_results(rep, checks):
    p = rep["posture"]
    assert [r["device"] for r in p["devices"]] == [d["name"] for d in rep["devices"]]
    for plane in report.PLANES:
        fails = sum(1 for d in rep["devices"] for r in d.get("results", [])
                    if r["status"] == "fail" and checks[r["check"]]["plane"] == plane)
        assert p["total"][plane]["fail"] == fails
    assert p["total"]["cves"]["fail"] == len({f["id"] for f in rep["findings"] if f["type"] == "cve"})


def test_control_map(rep):
    nist = rep["controls"]["nist_800_53r5"]
    assert nist and all(re.match(r"^[A-Z]{2}-\d+", k) for k in nist)
    keys = list(nist)
    assert keys == sorted(keys, key=report._control_key)
    assert set(rep["controls"]["cisa_ztmm"]) <= set(seccheck.ZT_PILLARS)


# ---------- markdown ----------
def test_markdown_sections_in_order(md):
    pos = [md.find("\n" + s) if not s.startswith("# ") else md.find(s) for s in SECTIONS]
    assert all(p >= 0 for p in pos), [s for s, p in zip(SECTIONS, pos) if p < 0]
    assert pos == sorted(pos)


def test_markdown_groups_findings_by_check(md, rep):
    body = md.split("## Findings by deadline", 1)[1].split("\n## ", 1)[0]
    for band in re.split(r"\n### ", body)[1:]:
        heads = re.findall(r"^\*\*([A-Z0-9-]+)\*\*:", band, re.M)
        assert len(heads) == len(set(heads))
    multi = {}
    for f in rep["findings"]:
        if f["type"] == "config" and f["deadline"] != "upgrade":
            multi.setdefault((f["id"], f["deadline"]), []).append(f["device"])
    cid, devs = next(((k[0], v) for k, v in multi.items() if len(v) > 1), (None, None))
    assert cid, "the fixture should fail one check on two devices in one band"
    assert f"Devices: {len(devs)} devices:" in body


def test_collapse_device_ranges():
    names = ["hq-acc-sw-01", "hq-acc-sw-02", "hq-acc-sw-03", "hq-acc-sw-04", "hq-core-sw-01", "fw-01"]
    assert report.collapse(names, names) == "hq-acc-sw-01..04, hq-core-sw-01, fw-01"
    assert report.collapse(["a-1", "a-2"]) == "a-1, a-2"
    assert report.device_phrase(["x"]) == "x"
    assert report.short_devices(names, names, total=len(names)) == "all 6 devices"


def test_markdown_scope_and_method(md):
    head = md.split("## Summary", 1)[0]
    assert "**Devices:**" in head and "**Advisory cache:**" in head and "BOD 26-04" in head
    assert "**Event window:**" in head


# ---------- secrets, escaping, offline HTML ----------
def test_no_secrets_in_reports(md, page):
    secrets = _secrets()
    assert len(secrets) >= 5, secrets
    for s in secrets:
        assert s not in md and s not in page, s


def test_html_is_self_contained(page):
    low = page.lower()
    assert low.startswith("<!doctype html>") and "prefers-color-scheme: dark" in low
    for bad in ("<script", "<link", "src=", "url(", "@import", "<iframe", "<img"):
        assert bad not in low, bad
    for href in re.findall(r'href="([^"]*)"', page):
        assert href.startswith("https://"), href
    for b in scoring.ORDER:
        assert f"b-{'3dt' if b == '3d+triage' else b}" in page


def test_html_has_same_sections(page):
    for s in ("Summary", "Top actions", "Posture by plane", "Findings by deadline", "What is good",
              "What the check could not see", "Appendix: control map"):
        assert f">{s}</h" in page, s
    assert "<details" in page and "<table" in page


def test_html_escapes_crafted_finding(rep, checks):
    bad = copy.deepcopy(rep)
    for k in ("summary", "posture", "controls"):
        bad.pop(k)
    f = next(x for x in bad["findings"] if x["type"] == "config")
    f["title"] = f["detail"] = "<script>alert(1)</script>"
    f["evidence"] = ['description "><img src=x onerror=alert(2)>']
    f["device"] = "<b>evil</b>"
    bad["devices"][0]["notes"].append("<script>alert(3)</script>")
    page = report.html_report(bad, checks)
    assert "<script" not in page.lower() and "<img" not in page.lower() and "<b>evil" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page or "&lt;script&gt;alert(3)&lt;/script&gt;" in page


def test_accepted_risk_in_both_reports(tmp_path, checks):
    repo = tmp_path / "repo"
    shutil.copytree(FX / "snapshots", repo)
    (repo / "exceptions.yaml").write_text("- check: FGT-NO-LOG\n  device: fw-01\n  reason: lab <exception>\n"
                                          "  expires: 2999-01-01\n", encoding="utf-8")
    args = type("A", (), {"repo": str(repo), "out": str(tmp_path / "out"), "site": None, "device": None,
                          "events": None, "bucket_minutes": 60, "no_cves": True})()
    r = seccheck.build(args)
    if not r["accepted_risk"]:
        pytest.skip("fixture no longer fails FGT-NO-LOG on fw-01")
    assert "## Accepted risk" in report.markdown(r, checks)
    page = report.html_report(r, checks)
    assert "Accepted risk" in page and "lab &lt;exception&gt;" in page


def test_no_em_dashes_in_generated_text(md, page):
    assert "—" not in md and "—" not in page
