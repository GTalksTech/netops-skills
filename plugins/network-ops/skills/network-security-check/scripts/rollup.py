# ============================================================
# Script:       rollup.py
# Purpose:      Turns per device-check findings into counts that mean "distinct problems to fix",
#               without dropping anything: dependent checks fold into the check they depend on
#               (suppressed_by), low-value hygiene checks move to a separate list (tier:
#               advisory), and a check that fails the same way on 3 or more devices becomes one
#               rolled-up finding with a per-device list.
# Author:       G Talks Tech
# Notes:        House rules 11-13 in SCORING.md. Scores never change here: only how findings are
#               counted and grouped. The per device-check findings stay in the JSON report.
# ============================================================
import scoring

TIERS = ("standard", "advisory")
ROLLUP_MIN = 3          # devices: a check failing in one band on this many becomes one finding


def tier(checks, cid):
    return (checks.get(cid) or {}).get("tier") or "standard"


def fold_dependents(findings, checks):
    """A config finding whose check lists a suppressed_by parent that also fails on the same
    device moves into that parent's `also` list, and the parent's detail says so. Returns the
    findings that stay listed. Waived parents are not in `findings`, so their children stay."""
    present = {(f["id"], f.get("device")): f for f in findings if f["type"] == "config"}
    kept = []
    for f in findings:
        parent = None
        if f["type"] == "config":
            for p in (checks.get(f["id"]) or {}).get("suppressed_by") or []:
                parent = present.get((p, f.get("device")))
                if parent is not None:
                    break
        if parent is None:
            kept.append(f)
            continue
        parent.setdefault("also", []).append({**f, "suppressed_by": parent["id"]})
        parent["detail"] = f"{parent.get('detail') or ''} Also: {f['id']} ({f['title']}).".strip()
    return kept


def split_tiers(findings, checks):
    """Every config finding gets `tier`. Advisory ones leave the deadline list."""
    scored, hygiene = [], []
    for f in findings:
        if f["type"] == "config":
            f["tier"] = tier(checks, f["id"])
        (hygiene if f.get("tier") == "advisory" else scored).append(f)
    return scored, hygiene


def unique(findings):
    """One entry per distinct problem. Config findings of one check in one band on ROLLUP_MIN or
    more devices become one rolled-up finding; the rest (CVEs, events, smaller groups) pass
    through unchanged. Order follows the first finding of each group."""
    groups = {}
    for f in findings:
        if f["type"] == "config" and f.get("device"):
            groups.setdefault((f["id"], f["deadline"]), []).append(f)
    out, done = [], set()
    for f in findings:
        key = (f["id"], f["deadline"])
        fs = groups.get(key) if f["type"] == "config" and f.get("device") else None
        if not fs or len(fs) < ROLLUP_MIN:
            out.append(f)
            continue
        if key in done:
            continue
        done.add(key)
        best = max(fs, key=lambda x: x["score"])
        scores = [x["score"] for x in fs]
        also = sorted({a["id"] for x in fs for a in x.get("also") or []})
        out.append({"type": "config", "rollup": True, "id": f["id"], "title": best["title"],
                    "tier": best.get("tier", "standard"), "deadline": best["deadline"],
                    "action": best["action"], "score": max(scores), "score_range": [min(scores), max(scores)],
                    "inputs": best["inputs"], "why": best["why"], "devices": [x["device"] for x in fs],
                    "internet_facing": sorted(x["device"] for x in fs if x["inputs"]["publicly_exposed"]),
                    "example_device": best["device"], "detail": best.get("detail"),
                    "evidence": best.get("evidence") or [], "also": also,
                    "why_it_matters": best.get("why_it_matters"), "fix": best.get("fix"),
                    "sources": best.get("sources", []), "plane": best.get("plane"),
                    "controls": best.get("controls", []), "validated": best.get("validated"),
                    "per_device": [{"device": x["device"], "score": x["score"], "detail": x.get("detail"),
                                    "evidence": x.get("evidence") or [],
                                    "also": [a["id"] for a in x.get("also") or []]} for x in fs]})
    return out


def every_finding(rep):
    """Every per device-check finding in a report, wherever it was filed: the deadline list,
    accepted risk, hygiene notes, and the dependents folded into a parent (`also`)."""
    out = []
    for f in (rep.get("findings") or []) + (rep.get("accepted_risk") or []) + (rep.get("hygiene") or []):
        out.append(f)
        out += f.get("also") or []
    return out


def counts(findings):
    return {b: sum(1 for f in findings if f["deadline"] == b) for b in scoring.ORDER}
