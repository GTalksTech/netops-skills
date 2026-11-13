# ============================================================
# Script:       report.py
# Purpose:      Turns the seccheck JSON report into what a person reads: a short markdown report
#               and a self-contained HTML report (inline CSS, no scripts, no external assets,
#               light and dark). Also adds the summary, posture grid and control map to the JSON.
# Author:       G Talks Tech
# Notes:        The JSON stays the source of truth: everything here is derived from it. Evidence
#               lines are masked again before they are printed (common.mask), and every string
#               that goes into the HTML is escaped.
# ============================================================
import html
import re
from collections import OrderedDict

import lifecycle
import scoring
from common import mask

PLANES = ("management", "control", "data", "l2", "visibility", "lifecycle")
PLANE_LABEL = {"management": "Management", "control": "Control", "data": "Data", "l2": "Layer 2",
               "visibility": "Visibility", "lifecycle": "Lifecycle"}
SHORT = {"3d+triage": "3 days + compromise check", "3d": "3 days", "14d": "14 days", "60d": "60 days",
         "upgrade": "next upgrade or window"}
LIFECYCLE_CHECKS = ("LIFECYCLE-EOS", "LIFECYCLE-SOON")
TOP_ACTIONS = 7
FULL_BLOCK_LIMIT = 6        # the lowest band gets full blocks only when it has this few groups
# Checks that one change fixes together are one action in "Top actions". Checks not listed, and
# not layer 2, stand alone. Layer 2 checks group by plane (one access-port baseline).
THEMES = {
    "IOS-BGP-NO-POLICY": "Harden the eBGP sessions (route filters, maximum-prefix, GTSM)",
    "IOS-BGP-MAX-PREFIX": "Harden the eBGP sessions (route filters, maximum-prefix, GTSM)",
    "IOS-BGP-NO-GTSM": "Harden the eBGP sessions (route filters, maximum-prefix, GTSM)",
    "IOS-BGP-INBOUND-PERMISSIVE": "Harden the eBGP sessions (route filters, maximum-prefix, GTSM)",
    "IOS-EDGE-NO-ANTISPOOF": "Harden the internet-facing interfaces (anti-spoofing, IP services, CDP/LLDP)",
    "IOS-EDGE-IP-SERVICES": "Harden the internet-facing interfaces (anti-spoofing, IP services, CDP/LLDP)",
    "IOS-EDGE-CDP-LLDP": "Harden the internet-facing interfaces (anti-spoofing, IP services, CDP/LLDP)",
    "IOS-ROUTING-NO-AUTH": "Authenticate routing protocol neighbors",
    "IOS-ROUTING-WEAK-AUTH": "Authenticate routing protocol neighbors",
    "FGT-INBOUND-ANY-SERVICE": "Tighten inbound firewall policy (named services, IPS on every inbound rule)",
    "FGT-INBOUND-NO-IPS": "Tighten inbound firewall policy (named services, IPS on every inbound rule)",
    "PAN-INBOUND-ANY-SERVICE": "Tighten inbound firewall policy (named services, IPS on every inbound rule)",
    "PAN-INBOUND-NO-PROFILE": "Tighten inbound firewall policy (named services, IPS on every inbound rule)",
    "IOS-AAA-CENTRAL": "Apply a management-access baseline (central AAA, lockout, timeouts, banner)",
    "IOS-LOGIN-BLOCK": "Apply a management-access baseline (central AAA, lockout, timeouts, banner)",
    "IOS-EXEC-TIMEOUT": "Apply a management-access baseline (central AAA, lockout, timeouts, banner)",
    "IOS-LOGIN-NONE": "Apply a management-access baseline (central AAA, lockout, timeouts, banner)",
    "IOS-BANNER": "Apply a management-access baseline (central AAA, lockout, timeouts, banner)",
}
THEMES.update({
    "IOS-NTP-AUTH": "Authenticate NTP and use two or more servers",
    "IOS-NTP-REDUNDANT": "Authenticate NTP and use two or more servers",
    "IOS-NO-REMOTE-LOG": "Send syslog and command accounting to two or more remote servers",
    "IOS-LOG-DEPTH": "Send syslog and command accounting to two or more remote servers",
    "IOS-AAA-ACCOUNTING": "Send syslog and command accounting to two or more remote servers",
    "FGT-ADMIN-LOCKOUT": "Apply the FortiGate admin-access baseline (lockout, password policy, timeout, 2FA)",
    "FGT-PASSWORD-POLICY": "Apply the FortiGate admin-access baseline (lockout, password policy, timeout, 2FA)",
    "FGT-ADMIN-TIMEOUT": "Apply the FortiGate admin-access baseline (lockout, password policy, timeout, 2FA)",
    "FGT-ADMIN-NO-2FA": "Apply the FortiGate admin-access baseline (lockout, password policy, timeout, 2FA)",
})
L2_THEME = "Apply an access-port and first-hop baseline (layer 2)"
# Short imperative wording for checks that stand alone in "Top actions". Others read "Fix: <title>".
ACTION_LABELS = {
    "IOS-NO-COPP": "Add control plane policing (CoPP)",
    "FGT-IPS-STALE": "Get the FortiGate IPS signatures updating again",
    "FGT-AV-STALE": "Get the FortiGate antivirus definitions updating again",
    "IOS-HTTP-SERVER": "Turn off the IOS web UI, or limit it to the management subnet",
    "IOS-SNMP-V2C": "Move SNMP to v3 with authentication and privacy",
    "IOS-SNMP-COMMUNITY": "Remove weak SNMP communities (default, read-write or without an ACL)",
    "IOS-TELNET": "Allow only SSH on the VTY lines",
    "IOS-VTY-ACL": "Put an access-class on every VTY line",
}
KIND_NAMES = {"router_switch": ("router or switch", "routers or switches"), "firewall": ("firewall", "firewalls"),
              "router": ("router", "routers"), "switch": ("switch", "switches")}


# ---------- small helpers ----------
def _first_sentence(text, limit=200):
    s = re.split(r"(?<=[a-z0-9)\]])\.\s", str(text or "").strip(), maxsplit=1)[0].rstrip(".")
    return s if len(s) <= limit else s[:limit - 3].rstrip() + "..."


def _clip(text, limit):
    """Whitespace collapsed, cut at a word boundary with a "(...)" marker when too long."""
    t = " ".join(str(text or "").split())
    if len(t) <= limit:
        return t
    cut = t[:limit - 6].rsplit(" ", 1)[0].rstrip(" ,;:.")
    return cut + " (...)"


def _band_order(b):
    return scoring.ORDER.index(b)


def collapse(names, order=None, limit=8):
    """'hq-acc-sw-01, hq-acc-sw-02, hq-acc-sw-03' -> 'hq-acc-sw-01..03'. Runs of three or more
    consecutive numbers with the same prefix collapse; parts keep inventory order."""
    names = list(dict.fromkeys(names))
    pos = {n: i for i, n in enumerate(order or [])}
    parsed = []
    for n in names:
        m = re.match(r"^(.*?)(\d+)$", n)
        parsed.append((m.group(1), m.group(2)) if m else (n, None))
    keyed = sorted(range(len(names)), key=lambda i: (parsed[i][0], len(parsed[i][1] or ""),
                                                      int(parsed[i][1]) if parsed[i][1] else -1))
    runs, cur = [], []
    for i in keyed:
        p, num = parsed[i]
        if cur and num is not None and parsed[cur[-1]][1] is not None and parsed[cur[-1]][0] == p \
                and len(parsed[cur[-1]][1]) == len(num) and int(num) == int(parsed[cur[-1]][1]) + 1:
            cur.append(i)
        else:
            if cur:
                runs.append(cur)
            cur = [i]
    if cur:
        runs.append(cur)
    parts = []
    for r in runs:
        if len(r) >= 3:
            parts.append(([names[i] for i in r], f"{names[r[0]]}..{parsed[r[-1]][1]}"))
        else:
            parts += [([names[i]], names[i]) for i in r]
    parts.sort(key=lambda x: min(pos.get(n, 10 ** 6) for n in x[0]))
    text = [t for _, t in parts]
    if len(text) > limit:
        text = text[:limit] + [f"and {sum(len(x[0]) for x in parts[limit:])} more"]
    return ", ".join(text)


def short_devices(names, order=None, total=None):
    """For one-line actions: the names when there are few, else a count."""
    names = list(dict.fromkeys(names))
    if len(names) == 1:
        return names[0]
    if total and len(names) == total:
        return f"all {len(names)} devices"
    if len(names) <= 4:
        return f"{len(names)} devices ({collapse(names, order)})"
    return f"{len(names)} devices"


def _cap(xs):
    return [xs[0][:1].upper() + xs[0][1:]] + xs[1:] if xs else xs


def device_phrase(names, order=None):
    names = list(dict.fromkeys(names))
    if len(names) == 1:
        return names[0]
    return f"{len(names)} devices: {collapse(names, order)}"


def _plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


# ---------- analysis: summary, posture, controls (added to the JSON) ----------
def _check_meta(checks, cid):
    return checks.get(cid) or {}


def upgrade_actions(rep):
    """One action per (platform, running version): every CVE and end-of-support finding on those
    devices is cleared by one upgrade."""
    devs = {d["name"]: d for d in rep["devices"]}
    try:
        table = lifecycle.load()
    except Exception:  # noqa: BLE001 - a missing table only loses the upgrade hint
        table = {}
    groups = OrderedDict()

    def grp(dev_name, version):
        d = devs.get(dev_name, {})
        key = (d.get("platform"), version)
        if key not in groups:
            plat = table.get(d.get("platform")) or {}
            row = (plat.get("trains") or {}).get(lifecycle.train(version)) or {}
            note = row.get("note") or ""
            groups[key] = {"kind": "upgrade", "platform": d.get("platform"), "version": version,
                           "label_name": plat.get("name") or d.get("vendor") or d.get("platform") or "software",
                           "hint": note if re.search(r"recommend", note, re.I) else "",
                           "devices": [], "cves": set(), "kev": set(), "eos": [], "soon": [],
                           "worst": "upgrade", "score": 0, "exposed": set()}
        return groups[key]

    for f in rep["findings"]:
        if f["type"] == "cve":
            for x in f["devices"]:
                g = grp(x["device"], x["version"])
                g["devices"].append(x["device"])
                g["cves"].add(f["id"])
                if f.get("kev"):
                    g["kev"].add(f["id"])
                if _band_order(x["deadline"]) < _band_order(g["worst"]):
                    g["worst"] = x["deadline"]
                g["score"] = max(g["score"], x["score"])
        elif f["type"] == "config" and f["id"] in LIFECYCLE_CHECKS:
            d = devs.get(f["device"], {})
            g = grp(f["device"], d.get("version"))
            g["devices"].append(f["device"])
            g["eos" if f["id"] == "LIFECYCLE-EOS" else "soon"].append(f["device"])
            if _band_order(f["deadline"]) < _band_order(g["worst"]):
                g["worst"] = f["deadline"]
            g["score"] = max(g["score"], f["score"])
    out = []
    plat_total = {}
    for d in rep["devices"]:
        plat_total[d.get("platform")] = plat_total.get(d.get("platform"), 0) + 1
    for g in groups.values():
        names = list(dict.fromkeys(g["devices"]))
        exposed = [n for n in names if devs.get(n, {}).get("internet_facing")]
        reasons = []
        if g["eos"]:
            n = len(set(g["eos"]))
            reasons.append("past end of security support" + ("" if n == len(names) else f" on {n}"))
        if g["soon"]:
            reasons.append("end of security support within 12 months")
        if g["cves"]:
            reasons.append(_plural(len(g["cves"]), "CVE") + (f" ({len(g['kev'])} in CISA KEV)" if g["kev"] else ""))
        if exposed:
            reasons.append(f"{len(exposed)} internet-facing" if len(names) > 1 else "internet-facing")
        hint = f" ({g['hint']})" if g["hint"] else " (fixed release: see the vendor advisory)"
        out.append({"kind": "upgrade", "key": f"upgrade:{g['platform']}:{g['version']}",
                    "action": f"Upgrade {g['label_name']} {g['version']} on "
                              f"{short_devices(names, list(devs), plat_total.get(g['platform']))}{hint}",
                    "reasons": _cap(reasons), "deadline": g["worst"], "score": g["score"], "devices": names,
                    "internet_facing": len(exposed), "checks": [c for c in LIFECYCLE_CHECKS
                                                                if (c == "LIFECYCLE-EOS" and g["eos"])
                                                                or (c == "LIFECYCLE-SOON" and g["soon"])],
                    "cves": sorted(g["cves"]), "kev": sorted(g["kev"])})
    return out


def config_actions(rep, checks):
    devs = {d["name"]: d for d in rep["devices"]}
    groups = OrderedDict()
    for f in rep["findings"]:
        if f["type"] == "cve" or f["id"] in LIFECYCLE_CHECKS:
            continue
        meta = _check_meta(checks, f["id"])
        theme = THEMES.get(f["id"]) or (L2_THEME if meta.get("plane") == "l2" else None)
        key = theme or f["id"]
        g = groups.setdefault(key, {"theme": theme, "checks": [], "devices": [], "exposed": set(),
                                    "worst": "upgrade", "score": 0, "type": f["type"]})
        if f["id"] not in g["checks"]:
            g["checks"].append(f["id"])
        if f.get("device"):
            g["devices"].append(f["device"])
            if f["inputs"]["publicly_exposed"]:
                g["exposed"].add(f["device"])
        if _band_order(f["deadline"]) < _band_order(g["worst"]):
            g["worst"] = f["deadline"]
        g["score"] = max(g["score"], f["score"])
    out = []
    for key, g in groups.items():
        names = list(dict.fromkeys(g["devices"]))
        where = f" on {short_devices(names, list(devs), len(devs))}" if names else ""
        if g["theme"]:
            action = f"{g['theme']}{where}"
            reasons = [f"checks {', '.join(g['checks'])}"]
        else:
            meta = _check_meta(checks, key)
            label = ACTION_LABELS.get(key) or f"Fix: {_first_sentence(meta.get('title', key), 120)}"
            action = f"{label}{where}"
            reasons = [f"check {key}"]
        if g["exposed"]:
            reasons.append(f"{len(g['exposed'])} internet-facing" if len(names) > 1 else "internet-facing")
        out.append({"kind": g["type"], "key": key, "action": action, "reasons": _cap(reasons),
                    "deadline": g["worst"], "score": g["score"], "devices": names,
                    "internet_facing": len(g["exposed"]), "checks": g["checks"], "cves": [], "kev": []})
    return out


def actions(rep, checks):
    acts = upgrade_actions(rep) + config_actions(rep, checks)
    acts.sort(key=lambda a: (_band_order(a["deadline"]), -a["score"], -a["internet_facing"], -len(a["devices"])))
    return acts


def posture(rep, checks):
    """Device x plane: fail and pass counts from devices[].results, plus the worst deadline of
    the open (not waived) findings in that cell. CVEs get their own column."""
    worst = {}
    for f in rep["findings"]:
        if f["type"] == "config":
            plane = _check_meta(checks, f["id"]).get("plane") or f.get("plane")
            k = (f["device"], plane)
            if k not in worst or _band_order(f["deadline"]) < _band_order(worst[k]):
                worst[k] = f["deadline"]
        elif f["type"] == "cve":
            for x in f["devices"]:
                k = (x["device"], "cves")
                if k not in worst or _band_order(x["deadline"]) < _band_order(worst[k]):
                    worst[k] = x["deadline"]
    cve_count = {}
    for f in rep["findings"]:
        if f["type"] == "cve":
            for x in f["devices"]:
                cve_count[x["device"]] = cve_count.get(x["device"], 0) + 1
    rows, total = [], {p: {"fail": 0, "pass": 0, "worst": None} for p in PLANES + ("cves",)}
    for d in rep["devices"]:
        cells = {}
        for p in PLANES:
            rs = [r for r in d.get("results", []) if (_check_meta(checks, r["check"]).get("plane") or "") == p]
            c = {"fail": sum(r["status"] == "fail" for r in rs), "pass": sum(r["status"] == "pass" for r in rs),
                 "worst": worst.get((d["name"], p))}
            cells[p] = c
        cells["cves"] = {"fail": cve_count.get(d["name"], 0), "pass": 0, "worst": worst.get((d["name"], "cves"))}
        for p, c in cells.items():
            t = total[p]
            t["fail"] += c["fail"]
            t["pass"] += c["pass"]
            if c["worst"] and (t["worst"] is None or _band_order(c["worst"]) < _band_order(t["worst"])):
                t["worst"] = c["worst"]
        rows.append({"device": d["name"], "site": d.get("site"), "internet_facing": bool(d.get("internet_facing")),
                     "cells": cells})
    total["cves"]["fail"] = len({f["id"] for f in rep["findings"] if f["type"] == "cve"})
    return {"planes": list(PLANES) + ["cves"], "devices": rows, "total": total}


def check_status(rep):
    """Per check across all devices: fail devices, pass devices, n/a and not-visible devices."""
    st = OrderedDict()
    for d in rep["devices"]:
        for r in d.get("results", []):
            s = st.setdefault(r["check"], {"fail": [], "pass": [], "n/a": [], "not-visible": []})
            s[r["status"]].append(d["name"])
    return st


def _control_key(c):
    m = re.match(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$", c)
    return (m.group(1), int(m.group(2)), int(m.group(3) or 0)) if m else (c, 0, 0)


def controls(rep, checks):
    """NIST SP 800-53r5 control and CISA ZTMM pillar -> checks failing and passing on this network.
    A check passes here when it passed on at least one device and failed on none."""
    st = check_status(rep)
    nist, zt = {}, {}
    for cid, s in st.items():
        meta = _check_meta(checks, cid)
        state = "fail" if s["fail"] else ("pass" if s["pass"] else None)
        if not state:
            continue
        for c in meta.get("controls", []):
            nist.setdefault(c, {"fail": [], "pass": []})[state].append(cid)
        if meta.get("zt_pillar"):
            zt.setdefault(meta["zt_pillar"], {"fail": [], "pass": []})[state].append(cid)
    nist = OrderedDict(sorted(nist.items(), key=lambda kv: _control_key(kv[0])))
    return {"nist_800_53r5": nist, "cisa_ztmm": dict(sorted(zt.items())),
            "note": "A mapping, not a compliance claim. CVE findings fall under SI-2 (flaw remediation) "
                    "and RA-5 (vulnerability monitoring and scanning)."}


def analysis(rep, checks):
    """The fields report.py adds to the JSON: summary, posture, controls."""
    acts = actions(rep, checks)
    top = [a for a in acts if a["deadline"] != "upgrade"][:TOP_ACTIONS]
    if len(top) < 5:
        top += [a for a in acts if a["deadline"] == "upgrade"][:5 - len(top)]
    return {"summary": {"counts": rep["counts"], "accepted": len(rep.get("accepted_risk") or []),
                        "result_counts": rep.get("result_counts"), "devices": len(rep["devices"]),
                        "top_actions": top, "actions": acts},
            "posture": posture(rep, checks), "controls": controls(rep, checks)}


def _ensure(rep, checks):
    if not all(k in rep for k in ("summary", "posture", "controls")):
        rep = {**rep, **analysis(rep, checks)}
    return rep


# ---------- shared section data ----------
def _scope(rep):
    devs = rep["devices"]
    sites = list(dict.fromkeys(d.get("site") or "unassigned" for d in devs))
    kinds = {}
    for d in devs:
        kinds[d.get("kind") or "unknown"] = kinds.get(d.get("kind") or "unknown", 0) + 1
    snap = rep.get("snapshot") or {}
    cache = rep.get("advisory_cache") or {}
    ev = rep.get("events") or {}
    kind_txt = ", ".join(f"{v} {KIND_NAMES.get(k, (k, k))[v != 1]}" for k, v in kinds.items())
    items = [("Devices", f"{len(devs)} ({kind_txt}), "
                         f"{sum(bool(d.get('internet_facing')) for d in devs)} internet-facing"),
             ("Sites", ", ".join(sites))]
    if snap.get("commit"):
        items.append(("Snapshot", f"commit {snap['commit']}, {snap.get('date', '')[:16].replace('T', ' ')}"))
    else:
        items.append(("Snapshot", rep.get("repo", "")))
    items.append(("Advisory cache", f"fetched {cache['fetched'][:10]}, CISA KEV {cache.get('kev_version')}"
                  if cache else "none (CVE matching skipped)"))
    items.append(("Event window", f"{ev.get('first', '')[:16]} to {ev.get('last', '')[:16]}, {ev.get('events')} events"
                  if ev else "no firewall events given"))
    return items


METHOD = ("Method: each finding is scored on four questions (publicly exposed, in CISA KEV, automatable, "
          "total control) and given the deadline from CISA BOD 26-04 Table 1. Read-only: built from snapshot "
          "files, no device was contacted.")


def _band_title(b):
    if b == "upgrade":
        return "Next planned upgrade (CVEs) or next maintenance window (config)"
    return scoring.BANDS[b][2]


def _band_groups(rep, checks, band):
    """Config and event findings in one band grouped by check; CVEs listed one per CVE."""
    order = [d["name"] for d in rep["devices"]]
    groups = OrderedDict()
    cves = []
    for f in rep["findings"]:
        if f["deadline"] != band:
            continue
        if f["type"] == "cve":
            cves.append(f)
            continue
        g = groups.setdefault(f["id"], {"id": f["id"], "type": f["type"], "title": f["title"],
                                        "why": f.get("why_it_matters", ""), "fix": f.get("fix", ""),
                                        "sources": f.get("sources", []), "findings": [],
                                        "validated": _check_meta(checks, f["id"]).get("validated"),
                                        "controls": _check_meta(checks, f["id"]).get("controls", [])})
        g["findings"].append(f)
    out = []
    for g in groups.values():
        fs = g["findings"]
        scores = [f["score"] for f in fs]
        names = [f["device"] for f in fs if f.get("device")]
        ex = fs[0]
        out.append({**g, "lo": min(scores), "hi": max(scores), "devices": names,
                    "device_text": device_phrase(names, order) if names else "",
                    "exposed": sorted({f["device"] for f in fs if f.get("device") and f["inputs"]["publicly_exposed"]}),
                    "example_device": ex.get("device"), "example_detail": _clip(ex.get("detail"), 200),
                    "example_evidence": mask(ex["evidence"][0]) if ex.get("evidence") else ""})
    out.sort(key=lambda g: (-g["hi"], g["id"]))
    return out, cves


def _range(vals, fmt="{}"):
    vals = [v for v in vals if v is not None]
    if not vals:
        return "n/a"
    lo, hi = min(vals), max(vals)
    return fmt.format(lo) if lo == hi else f"{fmt.format(lo)}-{fmt.format(hi)}"


def cve_lines(cves, band, order):
    """CVEs in one band, merged when they share title, devices and advisory (one vendor bundle)."""
    groups = OrderedDict()
    for f in cves:
        ref = next((r for r in f.get("refs") or [] if str(r).startswith("https://")), "")
        key = (f.get("title"), tuple(sorted(x["device"] for x in f["devices"])), ref)
        groups.setdefault(key, []).append(f)
    out = []
    for (title, _, ref), fs in groups.items():
        f0 = fs[0]
        names = [x["device"] for x in f0["devices"]]
        at = [x["device"] for x in f0["devices"] if x["deadline"] == band]
        epss = [(f.get("epss") or {}).get("epss") for f in fs]
        epss = [e for e in epss if e is not None]
        facts = [f"score {_range([f['score'] for f in fs])}",
                 f"CVSS {_range([(f.get('cvss') or {}).get('score') for f in fs])}",
                 f"EPSS {max(epss):.3f}" if len(epss) == 1 else (f"EPSS up to {max(epss):.3f}" if epss else "EPSS n/a"),
                 ("in CISA KEV" if all(f.get("kev") for f in fs) else
                  "some in CISA KEV" if any(f.get("kev") for f in fs) else "not in KEV")]
        if any(f.get("attacks_seen") for f in fs):
            facts.append("attempts seen in your events")
        devices = device_phrase(names, order)
        if at and len(at) < len(names):
            devices += f"; at this deadline on {collapse(at, order)}, later on the rest"
        top = f0["devices"][0]
        out.append({"ids": [f["id"] for f in fs], "title": _clip(title, 110).rstrip(". "), "facts": ", ".join(facts),
                    "devices": devices, "exposure": _clip((top.get("why") or {}).get("publicly_exposed", ""), 120),
                    "exposure_device": top["device"] if len(names) > 1 else "", "ref": ref})
    return out


def _cve_text(x):
    exp = f"Exposure ({x['exposure_device']}): " if x["exposure_device"] else "Exposure: "
    return f"{x['title']}. Devices: {x['devices']}. {exp}{x['exposure']}."


def _lowest_cve_summary(rep, cves):
    devs = {d["name"]: d for d in rep["devices"]}
    try:
        names = {k: v.get("name", k) for k, v in lifecycle.load().items()}
    except Exception:  # noqa: BLE001
        names = {}
    by = OrderedDict()
    for f in cves:
        vers = {(devs.get(x["device"], {}).get("platform"), x["version"]) for x in f["devices"]}
        for p, v in sorted(vers, key=str):
            by.setdefault(f"{names.get(p, p)} {v}", []).append(f["id"])
    off = sum(1 for f in cves if all(x.get("feature_off") for x in f["devices"]))
    return by, off


def _good(rep, checks):
    st = check_status(rep)
    out = OrderedDict((p, []) for p in PLANES)
    for cid, s in st.items():
        if s["pass"] and not s["fail"]:
            meta = _check_meta(checks, cid)
            out.setdefault(meta.get("plane") or "other", []).append(
                (cid, meta.get("title", cid), len(s["pass"])))
    return OrderedDict((p, v) for p, v in out.items() if v)


def _not_seen(rep, checks):
    """(heading, lines) pairs for the coverage section, deduplicated."""
    order = [d["name"] for d in rep["devices"]]
    st = check_status(rep)
    hidden = []
    for cid, s in st.items():
        if s["not-visible"]:
            det = next((r["detail"] for d in rep["devices"] for r in d.get("results", [])
                        if r["check"] == cid and r["status"] == "not-visible"), "")
            hidden.append(f"{cid} ({_check_meta(checks, cid).get('title', '')}) on "
                          f"{device_phrase(s['not-visible'], order)}: {_clip(det, 160)}")
    life = OrderedDict()
    for d in rep["devices"]:
        for r in d.get("results", []):
            if r["check"] == "LIFECYCLE-EOS" and r["status"] in ("n/a", "not-visible"):
                life.setdefault(_clip(r["detail"], 200), []).append(d["name"])
    life_lines = [f"{device_phrase(v, order)}: {k}" for k, v in life.items()]
    no_ver = [d["name"] for d in rep["devices"] if not d.get("version")]
    notes = OrderedDict()
    for d in rep["devices"]:
        for n in d.get("notes", []):
            notes.setdefault(n, []).append(d["name"])
    note_lines = [f"{device_phrase(v, order)}: {_clip(k, 300)}" for k, v in notes.items()]
    note_lines += [_clip(n, 300) for n in dict.fromkeys(rep.get("notes") or [])]
    fixture_hits = sorted({f["id"] for f in rep["findings"] if f["type"] != "cve"
                           and _check_meta(checks, f["id"]).get("validated") == "fixture"})
    rc = rep.get("result_counts") or {}
    out = []
    if hidden:
        out.append(("Config sections missing from the snapshot (not-visible)", hidden))
    if life_lines or no_ver:
        out.append(("End of support unknown", life_lines + ([f"no software version found: "
                                                            f"{device_phrase(no_ver, order)}"] if no_ver else [])))
    if note_lines:
        out.append(("Notes", note_lines))
    misc = [f"{rc.get('n/a', 0)} check results did not apply (n/a), for example routing checks on a "
            "switch with no routing."] if rc.get("n/a") else []
    if fixture_hits:
        misc.append("Findings from checks tested on sample configs only, not yet on real devices: "
                    + ", ".join(fixture_hits) + ". Read them with that in mind.")
    if misc:
        out.append(("Other limits", misc))
    return out


# ---------- markdown ----------
def _md_cell(c):
    if not c["fail"] and not c["pass"]:
        return "-"
    txt = f"{c['fail']} / {c['pass']}"
    return f"**{txt}**" if c["worst"] in ("3d+triage", "3d", "14d") else txt


def markdown(rep, checks):
    rep = _ensure(rep, checks)
    order = [d["name"] for d in rep["devices"]]
    L = [f"# Network security check, {rep['generated'][:16].replace('T', ' ')}", ""]
    L += [f"- **{k}:** {v}" for k, v in _scope(rep)]
    L += ["", METHOD, ""]

    # 2. summary
    s = rep["summary"]
    c = rep["counts"]
    L.append("## Summary\n")
    L.append("| Deadline | Findings |\n|---|---|")
    for b in scoring.ORDER:
        L.append(f"| {_band_title(b)} | {c.get(b, 0)} |")
    rc = rep.get("result_counts") or {}
    L.append("")
    L.append(f"Config check results: {rc.get('fail', 0)} fail, {rc.get('pass', 0)} pass, {rc.get('n/a', 0)} n/a, "
             f"{rc.get('not-visible', 0)} not visible."
             + (f" {s['accepted']} finding(s) accepted as risk, not counted above." if s["accepted"] else ""))
    L.append("\n### Top actions\n")
    for i, a in enumerate(s["top_actions"], 1):
        L.append(f"{i}. **{SHORT[a['deadline']]}**: {a['action']}. {'; '.join(a['reasons'])}.")
    L.append("")

    # 3. posture
    p = rep["posture"]
    L.append("## Posture by plane\n")
    L.append("Each cell: failing checks / passing checks. **Bold**: a finding there is due within 14 days. "
             "CVEs: open CVEs on the device. `-`: nothing checked.\n")
    L.append("| Device | " + " | ".join(PLANE_LABEL.get(x, "CVEs") for x in p["planes"]) + " |")
    L.append("|---|" + "---|" * len(p["planes"]))
    for row in p["devices"]:
        name = row["device"] + (" (internet)" if row["internet_facing"] else "")
        cells = [(_md_cell(row["cells"][x]) if x != "cves" else
                  (f"**{row['cells'][x]['fail']}**" if row["cells"][x]["worst"] in ("3d+triage", "3d", "14d")
                   else str(row["cells"][x]["fail"] or "-"))) for x in p["planes"]]
        L.append(f"| {name} | " + " | ".join(cells) + " |")
    tot = p["total"]
    L.append("| **Total** | " + " | ".join((f"{tot[x]['fail']} / {tot[x]['pass']}" if x != "cves"
                                           else str(tot[x]["fail"])) for x in p["planes"]) + " |")
    L.append("")

    # 4. findings
    L.append("## Findings by deadline\n")
    for b in scoring.ORDER:
        if not c.get(b):
            continue
        groups, cves = _band_groups(rep, checks, b)
        L.append(f"### {_band_title(b)} ({c[b]})\n")
        compact = b == "upgrade" and len(groups) + len(cves) > FULL_BLOCK_LIMIT
        if compact:
            for g in groups:
                L.append(f"- {g['id']}: {g['title']} ({_plural(len(set(g['devices'])) or len(g['findings']), 'device')}"
                         f"{'' if g['devices'] else ' finding'}, score {g['lo']}"
                         + (f"-{g['hi']}" if g["hi"] != g["lo"] else "") + ")")
            if cves:
                by, off = _lowest_cve_summary(rep, cves)
                L.append(f"- {_plural(len(cves), 'CVE')} cleared by the upgrades in Top actions"
                         + (f" ({off} need a feature that is off in the config)" if off else "") + ": "
                         + "; ".join(f"{k}: {', '.join(v)}" for k, v in by.items()))
            L.append("")
            continue
        for g in groups:
            rng = f"{g['lo']}" + (f"-{g['hi']}" if g["hi"] != g["lo"] else "")
            L.append(f"**{g['id']}**: {g['title']} (score {rng})")
            if g["devices"]:
                ex = f"; internet-facing: {collapse(g['exposed'], order)}" if g["exposed"] else ""
                L.append(f"- Devices: {g['device_text']}{ex}")
            ev = f" `{g['example_evidence']}`" if g["example_evidence"] else ""
            who = f"{g['example_device']}: " if g["example_device"] else ""
            L.append(f"- Evidence: {who}{g['example_detail']}{ev}")
            L.append(f"- Why: {_first_sentence(g['why'], 220)}.")
            L.append(f"- Fix: {_clip(g['fix'], 300)}")
            L.append(f"- Sources: {', '.join(g['sources'])}. NIST 800-53: {', '.join(g['controls']) or 'n/a'}."
                     + (" Tested on sample configs only." if g["validated"] == "fixture" else ""))
            L.append("")
        if cves:
            L.append(f"CVEs ({len(cves)}):\n")
            for x in cve_lines(cves, b, order):
                L.append(f"- **{', '.join(x['ids'])}** ({x['facts']}): {_cve_text(x)}"
                         + (f" Advisory: {x['ref']}" if x["ref"] else ""))
            L.append("")

    # 5. accepted risk
    if rep.get("accepted_risk"):
        L.append(f"## Accepted risk ({len(rep['accepted_risk'])})\n")
        L.append("Waived in exceptions.yaml (NIST SP 800-53 CA-5, RA-7). Still open, not counted against a "
                 "deadline until the waiver expires.\n")
        for f in rep["accepted_risk"]:
            a = f["accepted"]
            L.append(f"- {f['id']} on {f['device']} (score {f['score']}): {a['reason']}"
                     + (f" Owner: {a['owner']}." if a.get("owner") else "") + f" Expires {a['expires']}.")
        L.append("")

    # 6. what is good
    good = _good(rep, checks)
    if good:
        L.append("## What is good\n")
        L.append("Checks that passed on every device they apply to: the problem each one looks for was not found.\n")
        for plane, items in good.items():
            L.append(f"- **{PLANE_LABEL.get(plane, plane)}**")
            L += [f"  - Not found on {_plural(n, 'device')}: {_first_sentence(t, 90)} ({cid})" for cid, t, n in items]
        L.append("")

    # 7. could not see
    ns = _not_seen(rep, checks)
    if ns:
        L.append("## What the check could not see\n")
        for head, lines in ns:
            L.append(f"**{head}**")
            L += [f"- {x}" for x in lines]
            L.append("")

    # 8. control map
    ctl = rep["controls"]
    if ctl["nist_800_53r5"]:
        L.append("## Appendix: control map\n")
        L.append(ctl["note"] + "\n")
        L.append("NIST SP 800-53r5, per control: failing checks / passing checks.\n")
        L.append("| Family | Controls |\n|---|---|")
        fam = OrderedDict()
        for k, v in ctl["nist_800_53r5"].items():
            fam.setdefault(k.split("-")[0], []).append(f"{k} {len(v['fail'])} / {len(v['pass'])}")
        L += [f"| {k} | {', '.join(v)} |" for k, v in fam.items()]
        L.append("")
        L.append("| CISA ZTMM pillar | Failing checks | Passing checks |\n|---|---|---|")
        for k, v in ctl["cisa_ztmm"].items():
            L.append(f"| {k} | {len(v['fail'])} | {len(v['pass'])} |")
        L.append("")
    L.append("CVE data: CVE.org, CISA KEV, FIRST EPSS. This product uses data from the NVD API but is not "
             "endorsed or certified by the NVD. Full detail per device: the JSON report (devices[].results).")
    return "\n".join(L) + "\n"


# ---------- HTML ----------
CSS = """
:root{--bg:#ffffff;--fg:#1d2330;--muted:#5b6475;--line:#d9dde5;--card:#f5f7fa;--link:#1f5fbf;
--d0:#7a0f1d;--d1:#c62828;--d2:#e8711a;--d3:#e9c13a;--d4:#9db4cf;--ok:#3f9b5a;--none:#eef0f3;--ink:#ffffff;--ink3:#1d2330}
@media (prefers-color-scheme: dark){:root{--bg:#14171c;--fg:#e4e7ec;--muted:#9aa3b2;--line:#2c323c;--card:#1b1f26;
--link:#7fb0ff;--d0:#b3263a;--d1:#d84343;--d2:#d9822b;--d3:#c9a634;--d4:#46607e;--ok:#2f7d48;--none:#23272f;--ink3:#14171c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{font-size:24px;margin:0 0 8px}
h2{font-size:19px;margin:32px 0 10px;padding-bottom:4px;border-bottom:1px solid var(--line)}h3{font-size:16px;margin:20px 0 8px}
a{color:var(--link)}.muted{color:var(--muted)}code{font:13px Consolas,Menlo,monospace;background:var(--card);
padding:1px 4px;border-radius:3px;word-break:break-all}
dl.scope{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;margin:8px 0}dl.scope dt{color:var(--muted)}dl.scope dd{margin:0}
.bars{display:grid;grid-template-columns:minmax(150px,max-content) 1fr 40px;gap:6px 10px;align-items:center;max-width:720px}
.bar{height:14px;border-radius:3px;min-width:3px}.bar.zero{min-width:0}.num{text-align:right;font-variant-numeric:tabular-nums}
ol.actions li{margin:6px 0}.tag{display:inline-block;font-size:12px;padding:0 6px;border-radius:3px;margin-right:6px;
color:var(--ink);white-space:nowrap}
.wrap{overflow-x:auto}table{border-collapse:collapse;font-size:13px;margin:8px 0}
th,td{border:1px solid var(--line);padding:4px 8px;text-align:center}th{background:var(--card)}td.dev{text-align:left;white-space:nowrap}
.b-3dt{background:var(--d0);color:var(--ink)}.b-3d{background:var(--d1);color:var(--ink)}
.b-14d{background:var(--d2);color:var(--ink)}.b-60d{background:var(--d3);color:var(--ink3)}
.b-upgrade{background:var(--d4);color:var(--fg)}.b-ok{background:var(--ok);color:var(--ink)}.b-none{background:var(--none);color:var(--muted)}
details{border:1px solid var(--line);border-radius:6px;margin:6px 0;background:var(--card)}
summary{cursor:pointer;padding:6px 10px}details>div{padding:0 12px 8px}details ul{margin:4px 0;padding-left:20px}
.legend span{display:inline-block;padding:0 8px;margin:2px 4px 2px 0;border-radius:3px;font-size:12px}
ul.tight li{margin:3px 0}footer{margin-top:40px;font-size:13px;color:var(--muted)}
"""

_CLS = {"3d+triage": "b-3dt", "3d": "b-3d", "14d": "b-14d", "60d": "b-60d", "upgrade": "b-upgrade"}


def _e(x):
    return html.escape(str(x if x is not None else ""), quote=True)


def _link(url):
    u = str(url or "")
    if not u.startswith("https://"):
        return _e(u)
    return f'<a href="{_e(u)}" rel="noreferrer noopener">{_e(u)}</a>'


def _cell_class(c):
    if c["worst"]:
        return _CLS[c["worst"]]
    if c["fail"]:
        return "b-upgrade"
    return "b-ok" if c["pass"] else "b-none"


def html_report(rep, checks):
    rep = _ensure(rep, checks)
    order = [d["name"] for d in rep["devices"]]
    c = rep["counts"]
    s = rep["summary"]
    H = ["<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width, initial-scale=1">',
         f"<title>Network security check {_e(rep['generated'][:10])}</title>",
         f"<style>{CSS}</style></head><body><main>",
         f"<h1>Network security check, {_e(rep['generated'][:16].replace('T', ' '))}</h1>", '<dl class="scope">']
    H += [f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in _scope(rep)]
    H += ["</dl>", f'<p class="muted">{_e(METHOD)}</p>']

    # summary
    H.append("<h2>Summary</h2>")
    mx = max([c.get(b, 0) for b in scoring.ORDER] + [1])
    H.append('<div class="bars">')
    for b in scoring.ORDER:
        n = c.get(b, 0)
        H.append(f"<div>{_e(_band_title(b))}</div><div><div class=\"bar {_CLS[b] if n else 'zero'}\" "
                 f"style=\"width:{(n / mx * 100) if n else 0:.1f}%\"></div></div><div class=\"num\">{n}</div>")
    H.append("</div>")
    rc = rep.get("result_counts") or {}
    H.append(f"<p>Config check results: {rc.get('fail', 0)} fail, {rc.get('pass', 0)} pass, {rc.get('n/a', 0)} n/a, "
             f"{rc.get('not-visible', 0)} not visible."
             + (f" {s['accepted']} finding(s) accepted as risk, not counted above." if s["accepted"] else "") + "</p>")
    H.append("<h3>Top actions</h3><ol class=\"actions\">")
    for a in s["top_actions"]:
        H.append(f"<li><span class=\"tag {_CLS[a['deadline']]}\">{_e(SHORT[a['deadline']])}</span>"
                 f"<strong>{_e(a['action'])}</strong>. {_e('; '.join(a['reasons']))}.</li>")
    H.append("</ol>")

    # posture
    p = rep["posture"]
    H.append("<h2>Posture by plane</h2>")
    H.append('<p class="legend muted">Each cell: failing checks / passing checks, colored by the shortest deadline '
             'of an open finding in it. <span class="b-3dt">3 days + check</span><span class="b-3d">3 days</span>'
             '<span class="b-14d">14 days</span><span class="b-60d">60 days</span><span class="b-upgrade">next '
             'upgrade or window</span><span class="b-ok">all pass</span><span class="b-none">not checked</span></p>')
    H.append('<div class="wrap"><table><tr><th>Device</th>'
             + "".join(f"<th>{_e(PLANE_LABEL.get(x, 'CVEs'))}</th>" for x in p["planes"]) + "</tr>")
    for row in p["devices"]:
        tds = []
        for x in p["planes"]:
            cell = row["cells"][x]
            if x == "cves":
                cls = _CLS[cell["worst"]] if cell["worst"] else "b-none"
                tds.append(f'<td class="{cls}">{cell["fail"] or "-"}</td>')
            else:
                txt = f"{cell['fail']} / {cell['pass']}" if cell["fail"] or cell["pass"] else "-"
                tds.append(f'<td class="{_cell_class(cell)}">{txt}</td>')
        tag = ' <span class="muted">(internet)</span>' if row["internet_facing"] else ""
        H.append(f'<tr><td class="dev">{_e(row["device"])}{tag}</td>' + "".join(tds) + "</tr>")
    tot = p["total"]
    tot_txt = [str(tot[x]["fail"]) if x == "cves" else "%d / %d" % (tot[x]["fail"], tot[x]["pass"]) for x in p["planes"]]
    H.append("<tr><th>Total</th>" + "".join(f"<th>{t}</th>" for t in tot_txt) + "</tr></table></div>")

    # findings
    H.append("<h2>Findings by deadline</h2>")
    for b in scoring.ORDER:
        if not c.get(b):
            continue
        groups, cves = _band_groups(rep, checks, b)
        H.append(f"<h3><span class=\"tag {_CLS[b]}\">{c[b]}</span>{_e(_band_title(b))}</h3>")
        compact = b == "upgrade" and len(groups) + len(cves) > FULL_BLOCK_LIMIT
        for g in groups:
            rng = f"{g['lo']}" + (f"-{g['hi']}" if g["hi"] != g["lo"] else "")
            n = len(set(g["devices"]))
            H.append(f"<details><summary><strong>{_e(g['id'])}</strong>: {_e(g['title'])} "
                     f"<span class=\"muted\">(score {rng}{', ' + _plural(n, 'device') if n else ''})</span></summary><div><ul>")
            if g["devices"]:
                ex = f"; internet-facing: {collapse(g['exposed'], order)}" if g["exposed"] else ""
                H.append(f"<li>Devices: {_e(g['device_text'] + ex)}</li>")
            who = f"{g['example_device']}: " if g["example_device"] else ""
            ev = f" <code>{_e(g['example_evidence'])}</code>" if g["example_evidence"] else ""
            H.append(f"<li>Evidence: {_e(who + g['example_detail'])}{ev}</li>")
            H.append(f"<li>Why: {_e(_first_sentence(g['why'], 220))}.</li><li>Fix: {_e(g['fix'])}</li>")
            H.append(f"<li>Sources: {_e(', '.join(g['sources']))}. NIST 800-53: {_e(', '.join(g['controls']) or 'n/a')}."
                     + (" Tested on sample configs only." if g["validated"] == "fixture" else "") + "</li></ul></div></details>")
        if cves:
            H.append(f"<details{' open' if not compact else ''}><summary><strong>CVEs ({len(cves)})</strong></summary>"
                     "<div><ul class=\"tight\">")
            for x in cve_lines(cves, b, order):
                H.append(f"<li><strong>{_e(', '.join(x['ids']))}</strong> <span class=\"muted\">({_e(x['facts'])})</span>: "
                         f"{_e(_cve_text(x))}" + (f" Advisory: {_link(x['ref'])}" if x["ref"] else "") + "</li>")
            H.append("</ul></div></details>")

    if rep.get("accepted_risk"):
        H.append(f"<h2>Accepted risk ({len(rep['accepted_risk'])})</h2><p>Waived in exceptions.yaml (NIST SP 800-53 "
                 "CA-5, RA-7). Still open, not counted against a deadline until the waiver expires.</p><ul>")
        for f in rep["accepted_risk"]:
            a = f["accepted"]
            H.append(f"<li>{_e(f['id'])} on {_e(f['device'])} (score {f['score']}): {_e(a['reason'])}"
                     + (f" Owner: {_e(a['owner'])}." if a.get("owner") else "") + f" Expires {_e(a['expires'])}.</li>")
        H.append("</ul>")

    good = _good(rep, checks)
    if good:
        H.append("<h2>What is good</h2><p class=\"muted\">Checks that passed on every device they apply to "
                 "the problem each one looks for was not found.</p>")
        for plane, items in good.items():
            H.append(f"<details><summary><strong>{_e(PLANE_LABEL.get(plane, plane))}</strong> "
                     f"<span class=\"muted\">({len(items)} checks)</span></summary><div><ul class=\"tight\">")
            H += [f"<li>Not found on {_plural(n, 'device')}: {_e(_first_sentence(t, 90))} "
                  f"<span class=\"muted\">({_e(cid)})</span></li>" for cid, t, n in items]
            H.append("</ul></div></details>")

    ns = _not_seen(rep, checks)
    if ns:
        H.append("<h2>What the check could not see</h2>")
        for head, lines in ns:
            H.append(f"<h3>{_e(head)}</h3><ul class=\"tight\">" + "".join(f"<li>{_e(x)}</li>" for x in lines) + "</ul>")

    ctl = rep["controls"]
    if ctl["nist_800_53r5"]:
        H.append(f"<h2>Appendix: control map</h2><p class=\"muted\">{_e(ctl['note'])}</p>")
        H.append("<details><summary><strong>NIST SP 800-53r5</strong> "
                 f"<span class=\"muted\">({len(ctl['nist_800_53r5'])} controls)</span></summary><div class=\"wrap\">"
                 "<table><tr><th>Control</th><th>Failing</th><th>Passing</th><th>Failing checks</th></tr>")
        for k, v in ctl["nist_800_53r5"].items():
            H.append(f"<tr><td>{_e(k)}</td><td>{len(v['fail'])}</td><td>{len(v['pass'])}</td>"
                     f"<td class=\"dev\">{_e(', '.join(v['fail']))}</td></tr>")
        H.append("</table></div></details>")
        H.append("<table><tr><th>CISA ZTMM pillar</th><th>Failing checks</th><th>Passing checks</th></tr>")
        for k, v in ctl["cisa_ztmm"].items():
            H.append(f"<tr><td>{_e(k)}</td><td>{len(v['fail'])}</td><td>{len(v['pass'])}</td></tr>")
        H.append("</table>")
    H.append("<footer>CVE data: CVE.org, CISA KEV, FIRST EPSS. This product uses data from the NVD API but is not "
             "endorsed or certified by the NVD. Full detail per device: the JSON report (devices[].results). "
             "This report names real weaknesses: keep it local.</footer></main></body></html>")
    return "\n".join(H) + "\n"
