# ============================================================
# Script:       scoring.py
# Purpose:      One security impact score (0-100) for every finding: CVEs, misconfigurations
#               and firewall events. The priority comes from CISA BOD 26-04 Table 1
#               (Publicly Exposed, In the KEV, Automatable, Technical Impact -> deadline).
#               The number inside each band only orders findings that share a deadline.
# Author:       G Talks Tech
# Notes:        Method and sources: SCORING.md in the skill folder. Keep the two in step.
# ============================================================

# BOD 26-04, Appendix A, Table 1: Remediation Timelines (CISA, 2026-06-10).
# key: (publicly_exposed, in_kev, automatable, total_control) -> deadline
BOD_26_04 = {
    (True, True, True, True): "3d+triage",
    (True, True, True, False): "3d",
    (True, True, False, True): "3d+triage",
    (True, True, False, False): "14d",
    (True, False, True, True): "3d",
    (True, False, True, False): "14d",
    (True, False, False, True): "14d",
    (True, False, False, False): "60d",
    (False, True, True, True): "3d+triage",
    (False, True, True, False): "14d",
    (False, True, False, True): "14d",
    (False, True, False, False): "14d",
    (False, False, True, True): "60d",
    (False, False, True, False): "60d",
    (False, False, False, True): "upgrade",
    (False, False, False, False): "upgrade",
}

# Score band per deadline: (floor, ceiling). Bands never overlap, so a higher score always
# means a shorter deadline.
BANDS = {
    "3d+triage": (90, 100, "Fix within 3 days and check the device for compromise"),
    "3d": (80, 89, "Fix within 3 days"),
    "14d": (60, 79, "Fix within 14 days"),
    "60d": (35, 59, "Fix within 60 days"),
    "upgrade": (0, 34, "Fix at the next planned upgrade"),
}
ORDER = ["3d+triage", "3d", "14d", "60d", "upgrade"]
# A config or event finding has no software upgrade to wait for: the lowest band is a change in
# the next maintenance window. Same band and score, different words (SCORING.md).
MAINTENANCE_WINDOW = "Fix in the next maintenance window"


def deadline(exposed, kev, automatable, total):
    return BOD_26_04[(bool(exposed), bool(kev), bool(automatable), bool(total))]


def score(exposed, kev, automatable, total, tiebreak=0.0, cap=None, cve=True):
    """tiebreak: 0..1 position inside the band (EPSS percentile for CVEs, check weight for
    config findings, volume for events). cap: never above this deadline band (house rule).
    cve=False (config and event findings) words the lowest band as a maintenance window."""
    d = deadline(exposed, kev, automatable, total)
    if cap and ORDER.index(d) < ORDER.index(cap):
        d = cap
    lo, hi, words = BANDS[d]
    if d == "upgrade" and not cve:
        words = MAINTENANCE_WINDOW
    t = min(max(float(tiebreak or 0), 0.0), 1.0)
    return {"score": round(lo + (hi - lo) * t), "deadline": d, "action": words,
            "inputs": {"publicly_exposed": bool(exposed), "known_exploited": bool(kev),
                       "automatable": bool(automatable),
                       "technical_impact": "total" if total else "partial"}}


def from_cvss(vector):
    """Fallback when CISA Vulnrichment has no SSVC answer for a CVE.
    Automatable ~ network attack, no privileges, no user interaction (CISA SSVC guide notes
    automatable exploits are network-reachable without a user). Total control ~ high
    confidentiality AND integrity impact. Returns (automatable, total) or (None, None)."""
    if not vector:
        return None, None
    m = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    av, pr, ui = m.get("AV"), m.get("PR"), m.get("UI")
    automatable = av == "N" and pr == "N" and ui in ("N",)
    c, i = m.get("C", m.get("VC")), m.get("I", m.get("VI"))
    total = c == "H" and i == "H"
    return automatable, total
