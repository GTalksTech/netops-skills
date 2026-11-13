#!/usr/bin/env python3
# ============================================================
# Script:       seccheck.py
# Purpose:      Read-only network security check. Works from files only: the configs and
#               show-command output that network-snapshot saved, a local cache of public
#               advisory data (CVE.org, NVD, CISA KEV, FIRST EPSS), and firewall event
#               exports. Finds CVEs that affect the versions you run, risky configuration,
#               and IPS event spikes, and scores each one with CISA BOD 26-04 Table 1.
# Usage:        python seccheck.py fetch [--repo DIR] [--out DIR]
#               python seccheck.py run   [--repo DIR] [--out DIR] [--events FILE ...]
#                                        [--site S | --device D] [--no-cves]
#               python seccheck.py check-settings
# Dependencies: Python 3.9+, pyyaml. fetch needs HTTPS to the public sources above.
# Author:       G Talks Tech
# GitHub:       github.com/GTalksTech/netops-skills (plugins/network-ops)
# Notes:        Never connects to a network device and never changes config. Scoring method:
#               SCORING.md. Sources for every check: research/sources.md.
# ============================================================
import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import advisories  # noqa: E402
import events as events_mod  # noqa: E402
import lifecycle  # noqa: E402
import scoring  # noqa: E402
import vendor_asa  # noqa: E402
import vendor_fortios  # noqa: E402
import vendor_ios  # noqa: E402
import vendor_junos  # noqa: E402
import vendor_panos  # noqa: E402
from common import STATUSES, result  # noqa: E402

SETTINGS = HERE.parent / "settings"
SWITCH_MODELS = r"(?i)^(C9[2-6]\d\d|WS-C|C[1-3]\d{3}|IE-|C1000|CBS)"
PLANES = ("management", "control", "data", "l2", "visibility", "lifecycle")
VALIDATED = ("lab-v2", "fixture")
ZT_PILLARS = ("identity", "devices", "networks", "applications", "data", "visibility")
STALE_SIGNATURE_DAYS = 30   # house rule, SCORING.md: FortiGuard pushes IPS updates daily
FEATURE_LABELS = {"http_server": "the web UI (ip http server)", "smart_install": "Smart Install",
                  "snmp": "SNMP", "webvpn": "AnyConnect / WebVPN", "mgmt_http": "ASDM (http server)",
                  "sslvpn": "SSL VPN", "admin_web": "the admin web interface",
                  "globalprotect": "GlobalProtect", "sdwan": "SD-WAN mode", "dhcp_snooping": "DHCP snooping", "iox": "IOx app hosting", "ike": "IKE / IPsec VPN", "fgfm": "FortiManager access (fgfm)", "mgmt_web": "the management web interface",
                  "jweb": "J-Web", "ssl_vpn": "Remote Access SSL VPN (crypto ssl policy)",
                  "webauth": "Web Authentication", "nbar_capwap": "NBAR CAPWAP classification",
                  "beep": "BEEP (netconf beep listener)", "xmcp": "XMCP (service-routing xmcp)",
                  "meraki": "Meraki dashboard management"}
PARSERS = {"ios": vendor_ios, "fortios": vendor_fortios, "panos": vendor_panos, "asa": vendor_asa,
           "junos_set": vendor_junos}


def load_settings():
    platforms = yaml.safe_load((SETTINGS / "platforms.yaml").read_text(encoding="utf-8"))
    checks = yaml.safe_load((SETTINGS / "checks.yaml").read_text(encoding="utf-8"))
    return platforms, checks


def load_devices(repo, site=None, device=None):
    inv = yaml.safe_load((repo / "inventory.yaml").read_text(encoding="utf-8"))
    defaults = inv.get("defaults", {})
    devs = [{**defaults, **d} for d in inv["devices"]]
    if site:
        devs = [d for d in devs if d.get("site") == site]
    if device:
        devs = [d for d in devs if d["name"] == device]
    return devs


def device_facts(dev, repo, platforms):
    """Version, model, kind, exposure and config findings for one device, from its snapshot."""
    p = dev.get("device_type", "")
    out = {"name": dev["name"], "site": dev.get("site", "unassigned"), "platform": p,
           "version": None, "model": None, "findings": [], "results": [], "features": {}, "notes": [],
           "interface_ips": []}
    pcfg = platforms.get(p)
    folder = repo / out["site"] / dev["name"]
    if not pcfg:
        out["notes"].append(f"no security settings for device_type '{p}': not checked")
        return out
    out["vendor"] = pcfg["vendor"]
    out["kind"] = dev.get("kind", pcfg["kind"])
    if not folder.exists():
        out["notes"].append(f"no snapshot folder {folder}: run network-snapshot first")
        return out
    vf = folder / pcfg["version"]["file"]
    if vf.exists():
        txt = vf.read_text(encoding="utf-8", errors="replace")
        m = re.search(pcfg["version"]["regex"], txt, re.M)
        if m:
            out["version"] = next(g for g in m.groups() if g)
        if pcfg["version"].get("model"):
            mf = folder / pcfg["version"].get("model_file", pcfg["version"]["file"])
            mtxt = mf.read_text(encoding="utf-8", errors="replace") if mf.exists() else ""
            mm = re.search(pcfg["version"]["model"], mtxt, re.M | re.I)
            out["model"] = mm.group(1).strip() if mm else None
    if not out["version"]:
        out["notes"].append(f"software version not found in {vf.name}: CVE matching skipped")

    cfg = folder / pcfg["config"]["file"]
    mod = PARSERS.get(pcfg["config"]["parser"])
    facts = None
    dev = {**dev, "_is_switch": bool(re.match(SWITCH_MODELS, out["model"] or "")), "_folder": folder}
    if mod and cfg.exists():
        try:
            facts, found = mod.analyze(cfg.read_text(encoding="utf-8", errors="replace"), dev)
        except Exception as e:  # one unreadable config never stops the run
            facts, found = None, []
            out["notes"].append(f"config parser failed on {cfg.name} ({type(e).__name__}: {e}): config checks "
                                "skipped. Please report this with a sanitized copy of the config.")
    if facts is not None:
        out["findings"] = found
        out["results"] = facts.get("results") or found
        out["features"] = facts["features"] if facts["interfaces"] else {}
        out["notes"] += facts["notes"]
        out["interface_ips"] = [ip.split("/")[0] for i in facts["interfaces"] for ip in i.get("ips", [])]
        if not facts["interfaces"]:
            # Nothing the parser read can be trusted as a pass when it found no interfaces.
            out["results"] = [r if r["status"] == "fail" else
                              {**r, "status": "not-visible", "detail": "config parsed to no interfaces"}
                              for r in out["results"]]
            out["notes"].append(f"config in {cfg.name} parsed to no interfaces: the format may be one this "
                                "parser doesn't read (for PAN-OS, the default brace format is needed, not "
                                "'set cli config-output-format set/json/xml'). Config checks are unreliable "
                                "for this device.")
    elif mod and not cfg.exists():
        out["notes"].append(f"config file {cfg.name} missing: config checks skipped")
    elif not mod:
        out["notes"].append("no config checks for this platform yet (CVE matching only)")

    override = dev.get("exposure")
    if override in ("public", "internal"):
        out["internet_facing"] = override == "public"
        out["exposure_reason"] = f"set in inventory (exposure: {override})"
    elif facts is not None:
        out["internet_facing"] = facts["internet_facing"]
        out["exposure_reason"] = facts["exposure_reason"]
        if not facts["internet_facing"] and out["kind"] == "firewall" and not facts["interfaces"]:
            out["internet_facing"], out["exposure_reason"] = True, "firewall with no interfaces parsed: assumed edge"
    else:
        edge = out["kind"] == "firewall"
        out["internet_facing"] = edge
        out["exposure_reason"] = ("firewall: assumed internet-facing" if edge else
                                  "assumed internal (no config parser): set exposure: public in the "
                                  "inventory if it faces the internet")
    if p == "fortinet" and vf.exists():
        m = re.search(r"^IPS-DB:\s*\S+\((\d{4}-\d{2}-\d{2})", vf.read_text(encoding="utf-8", errors="replace"), re.M)
        try:
            when = dt.date.fromisoformat(m.group(1)) if m else None
        except ValueError:
            when = None
        if when:
            taken = dt.date.fromtimestamp(vf.stat().st_mtime)   # the snapshot run, not today
            age = (taken - when).days
            stale = age > STALE_SIGNATURE_DAYS
            r = result("FGT-IPS-STALE", "fail" if stale else "pass", f"IPS-DB dated {m.group(1)}, {age} days old "
                       "when the snapshot was taken", [m.group(0)], exposed=out["internet_facing"])
            if stale:
                out["findings"].append(r)
        else:
            r = result("FGT-IPS-STALE", "not-visible", f"no IPS-DB date in {vf.name}")
        out["results"].append(r)
    out["result_counts"] = {st: sum(1 for r in out["results"] if r["status"] == st) for st in STATUSES}

    return out


def cve_inputs(hit, dev, pcfg, cache, attacked):
    """BOD 26-04 inputs for one CVE on one device, with the reason for each."""
    rec = hit["record"]
    cid = rec["id"]
    why = {}
    kev = cid in cache["kev"] or bool(rec.get("kev_adp"))
    if kev:
        why["known_exploited"] = "CISA KEV" + (" (ransomware use: Known)" if
                                              cache["kev"].get(cid, {}).get("knownRansomwareCampaignUse") == "Known" else "")
    elif rec.get("vendor_exploited"):
        kev, why["known_exploited"] = True, "vendor advisory reports exploitation"
    if cid in attacked:
        kev, why["known_exploited"] = True, why.get("known_exploited", "") + "; attack attempts seen in your IPS events"
    ssvc = rec.get("ssvc") or {}
    if "automatable" in ssvc and "technical_impact" in ssvc:
        auto, total = ssvc["automatable"] == "yes", ssvc["technical_impact"] == "total"
        why["automatable"] = why["technical_impact"] = "CISA Vulnrichment"
    else:
        auto, total = scoring.from_cvss((rec.get("cvss") or {}).get("vector"))
        if auto is None:
            auto, total = True, True
            why["automatable"] = why["technical_impact"] = "no CISA or CVSS data: assumed worst case"
        else:
            why["automatable"] = why["technical_impact"] = "derived from CVSS vector (no CISA answer yet)"

    vector = (rec.get("cvss") or {}).get("vector") or ""
    av = dict(p.split(":", 1) for p in vector.split("/") if ":" in p).get("AV")
    text = f"{rec.get('title', '')} {rec.get('description', '')} {rec.get('configurations', '')}"
    named = [f for f, rx in (pcfg.get("features") or {}).items() if re.search(rx, text, re.I)]
    feats = dev.get("features", {})
    known = [f for f in named if f in feats]
    feature_off = False
    if known:
        exposed = any(feats[f]["internet"] for f in known)
        on = [f for f in known if feats[f]["on"]]
        lab = lambda fs: " / ".join(FEATURE_LABELS.get(f, f) for f in fs)  # noqa: E731
        if exposed:
            why["publicly_exposed"] = f"{lab([f for f in known if feats[f]['internet']])} is reachable on an " \
                                      "internet-facing interface"
        elif on:
            why["publicly_exposed"] = f"{lab(on)} is on, but not on an internet-facing interface"
        else:
            feature_off = True
            why["publicly_exposed"] = f"the affected feature ({lab(known)}) looks off in the config"
    else:
        exposed = bool(dev.get("internet_facing"))
        why["publicly_exposed"] = dev.get("exposure_reason", "")
    if av in ("A", "L", "P") and exposed:
        # CVSS: Adjacent attacks can't cross a routed boundary; Local and Physical need access
        # to the device itself. Not reachable from the internet, whatever the device faces.
        exposed = False
        why["publicly_exposed"] = {"A": "attack vector Adjacent: the attacker must be on the same network segment",
                                   "L": "attack vector Local: the attacker needs a session on the device",
                                   "P": "attack vector Physical: the attacker needs the device in hand"}[av]
    return exposed, kev, auto, total, why, feature_off, named


def cve_title(rec, cache):
    """KEV name, else the vendor's title, else the first sentence of the description."""
    kev = cache["kev"].get(rec["id"])
    if kev:
        return kev["vulnerabilityName"]
    title = rec.get("title") or ""
    if title and not title.startswith(rec.get("description", "")[:40]):
        return title
    return re.split(r"(?<=[a-z0-9)])\. ", rec.get("description", ""), maxsplit=1)[0][:160]


def build(args):
    repo = Path(args.repo).expanduser()
    out_dir = Path(args.out).expanduser()
    platforms, checks = load_settings()
    devices = load_devices(repo, args.site, args.device)
    facts = [device_facts(d, repo, platforms) for d in devices]
    by_name = {f["name"]: f for f in facts}
    findings, notes = [], []
    lifecycle.apply(facts, notes)   # R8: end-of-support results, scored below as config findings

    # ---------- events first: attack attempts raise the CVE findings they hit ----------
    ev_summary = None
    if args.events:
        evs = []
        for f in args.events:
            evs += events_mod.read_events(f)
        sig_cves = {}
        for rec in (advisories.load(out_dir / "advisories") or {}).get("records", {}).values():
            for sid in rec.get("sig_ids", []):
                sig_cves.setdefault(sid, set()).add(rec["id"])
        for e in evs:
            e["cves"] = sorted(set(e["cves"]) | sig_cves.get(e["sig_id"], set()))
        ev_summary = events_mod.summarize(evs, args.bucket_minutes) if evs else None
        if not evs:
            notes.append("event files given, but no IPS/threat events could be read from them")
    attacked = set((ev_summary or {}).get("cve_events", {}))

    # ---------- CVEs ----------
    cache = None if args.no_cves else advisories.load(out_dir / "advisories")
    if not args.no_cves and cache is None:
        notes.append("no advisory cache: run 'seccheck.py fetch' first. CVE matching skipped.")
    cve_groups = {}
    if cache:
        try:
            fetched = dt.datetime.fromisoformat(cache.get("fetched", ""))
            fetched = fetched if fetched.tzinfo else fetched.replace(tzinfo=dt.timezone.utc)
            age = dt.datetime.now(dt.timezone.utc) - fetched
        except ValueError:
            age = dt.timedelta(days=999)
        if age.days > 7:
            notes.append(f"advisory cache is {age.days} days old: run fetch again for current KEV and EPSS")
        for d in facts:
            if not d.get("version"):
                continue
            pcfg = platforms[d["platform"]]
            if pcfg.get("cve_matching") == "manual":
                d["notes"].append(f"{pcfg['vendor']} CVE records aren't machine-readable: check version "
                                  f"{d['version']} by hand at {pcfg['psirt']}")
                continue
            if d["platform"] not in cache["platform_cves"]:
                d["notes"].append("no advisory data for this platform in the cache: run fetch again")
                continue
            hits, stats = advisories.match(d, pcfg, cache)
            d["cve_stats"] = stats
            for h in hits:
                cid = h["cve"]
                exposed, kev, auto, total, why, off, named = cve_inputs(h, d, pcfg, cache, attacked)
                epss = cache["epss"].get(cid, {})
                s = scoring.score(exposed, kev, auto, total, epss.get("percentile", 0),
                                  cap="upgrade" if off else None)
                g = cve_groups.setdefault(cid, {"type": "cve", "id": cid, "title": cve_title(h["record"], cache),
                                                "record": h["record"], "epss": epss,
                                                "kev": cache["kev"].get(cid), "devices": []})
                g["devices"].append({"device": d["name"], "version": d["version"], "model": d.get("model"),
                                     "matched_by": h["matched_by"], "feature_off": off,
                                     "features_named": named, "why": why, **s})
    for g in cve_groups.values():
        g["devices"].sort(key=lambda x: -x["score"])
        best = g["devices"][0]
        rec = g.pop("record")
        findings.append({**g, "score": best["score"], "deadline": best["deadline"], "action": best["action"],
                         "inputs": best["inputs"], "why": best["why"], "cvss": rec.get("cvss"),
                         "published": rec.get("published"), "refs": rec.get("refs"),
                         "vendor_exploited": rec.get("vendor_exploited"),
                         "conditions": rec.get("configurations") or None,
                         "attacks_seen": g["id"] in attacked})

    # ---------- config findings ----------
    for d in facts:
        for f in d["findings"]:
            c = checks[f["check"]]
            # House rules (SCORING.md): the exploitation a config check cites happened against
            # internet-reachable devices, so it only counts when this one is reachable too; and a
            # misconfiguration alone is not evidence of compromise, so never "+ forensic triage".
            s = scoring.score(f["exposed"], c["known_exploited"] and f["exposed"], c["automatable"],
                              c["total_control"], c["weight"], cap="3d", cve=False)
            findings.append({"type": "config", "id": f["check"], "title": c["title"], "device": d["name"],
                             "detail": f["detail"], "evidence": f["evidence"], "where": f.get("where"),
                             "why_it_matters": c["why"], "fix": c["fix"], "sources": c["sources"],
                             "plane": c.get("plane"), "controls": c.get("controls", []),
                             "validated": c.get("validated"),
                             "why": {"publicly_exposed": d.get("exposure_reason") if f["exposed"] else
                                     "not reachable from a public network per this config"}, **s})

    # ---------- event findings ----------
    if ev_summary:
        findings += event_findings(ev_summary, checks, cve_groups, by_name, cache)

    findings.sort(key=lambda f: (-f["score"], f["id"]))
    findings, accepted = apply_waivers(findings, load_waivers(repo, notes), notes)
    rollup = []
    for d in facts:
        mine = [(f, x) for f in findings if f["type"] == "cve" for x in f["devices"] if x["device"] == d["name"]]
        if not mine:
            continue
        by = {b: sum(1 for _, x in mine if x["deadline"] == b) for b in scoring.ORDER}
        worst = next(b for b in scoring.ORDER if by[b])
        rollup.append({"device": d["name"], "version": d["version"], "model": d.get("model"), "cves": len(mine),
                       "kev": sum(1 for f, _ in mine if f["kev"]), "by_deadline": by, "worst": worst,
                       "feature_off": sum(1 for _, x in mine if x["feature_off"]),
                       "check_fixed_release": platforms[d["platform"]].get("psirt")})
    rollup.sort(key=lambda r: (scoring.ORDER.index(r["worst"]), -r["kev"], -r["cves"]))
    return {"generated": dt.datetime.now().isoformat(timespec="seconds"), "repo": str(repo),
            "advisory_cache": {"fetched": cache["fetched"], "kev_version": cache["kev_version"]} if cache else None,
            "devices": [{k: v for k, v in d.items() if k != "findings"} for d in facts],
            "counts": {b: sum(1 for f in findings if f["deadline"] == b) for b in scoring.ORDER},
            "result_counts": {st: sum(d.get("result_counts", {}).get(st, 0) for d in facts) for st in STATUSES},
            "upgrade_plan": rollup,
            "findings": findings, "accepted_risk": accepted, "events": _ev_light(ev_summary), "notes": notes}


# ---------- accepted risk (exceptions.yaml) ----------
# NIST SP 800-53r5 CA-5 (plan of action and milestones) and RA-7 (risk response): a finding the
# owner decides to accept is recorded with a reason and a date to look at it again. It is never
# dropped: the report lists it under "Accepted risk", outside the deadline counts.
def load_waivers(repo, notes, today=None):
    """Active waivers from <repo>/exceptions.yaml. Bad and expired entries are skipped with a note."""
    f = repo / "exceptions.yaml"
    if not f.exists():
        return []
    today = today or dt.date.today()
    try:
        raw = yaml.safe_load(f.read_text(encoding="utf-8")) or []
    except yaml.YAMLError as e:
        notes.append(f"exceptions.yaml could not be read ({type(e).__name__}): no waivers applied")
        return []
    if isinstance(raw, dict):
        raw = raw.get("exceptions") or []
    out = []
    for n, w in enumerate(raw if isinstance(raw, list) else [], 1):
        if not isinstance(w, dict):
            notes.append(f"exceptions.yaml entry {n} is not a mapping: ignored")
            continue
        missing = [k for k in ("check", "device", "reason", "expires") if not w.get(k)]
        if missing:
            notes.append(f"exceptions.yaml entry {n} is missing {', '.join(missing)}: ignored")
            continue
        try:
            exp = w["expires"] if isinstance(w["expires"], dt.date) else dt.date.fromisoformat(str(w["expires"]))
        except ValueError:
            notes.append(f"exceptions.yaml entry {n}: expires '{w['expires']}' is not YYYY-MM-DD: ignored")
            continue
        label = f"{w['check']} on {w['device']}"
        if exp < today:
            notes.append(f"waiver for {label} expired on {exp}: no longer applied, the finding counts again")
            continue
        out.append({"check": str(w["check"]), "device": str(w["device"]), "reason": str(w["reason"]),
                    "expires": exp.isoformat(), "owner": w.get("owner"), "label": label})
    return out


def apply_waivers(findings, waivers, notes):
    """Split config findings matched by an active waiver into the accepted list. CVE and event
    findings are never waived: they are cleared by patching or by blocking the attack."""
    kept, accepted, used = [], [], set()
    for f in findings:
        w = next((w for w in waivers if f["type"] == "config" and w["check"] == f["id"]
                  and w["device"] in ("*", f["device"])), None)
        if w:
            used.add(w["label"])
            accepted.append({**f, "accepted": {k: w[k] for k in ("reason", "expires", "owner")}})
        else:
            kept.append(f)
    notes += [f"waiver for {w['label']} matches no finding in this run: remove it from exceptions.yaml"
              for w in waivers if w["label"] not in used]
    return kept, accepted


def event_findings(summ, checks, cve_groups, by_name, cache):
    """One finding per attack campaign. A signature tied to a CVE you are vulnerable to becomes
    one EV-TARGETS-VULNERABLE finding that carries its spike and not-blocked counts; spikes
    and not-blocked findings are only kept for what is left."""
    out = []
    ip_owner = {ip: n for n, d in by_name.items() for ip in d.get("interface_ips", [])}
    kev = (cache or {}).get("kev", {})

    def add(check, detail, exposed, kev_, auto, total, tiebreak, cap=None, **extra):
        c = checks[check]
        s = scoring.score(exposed, kev_, auto, total, tiebreak, cap, cve=False)
        out.append({"type": "event", "id": check, "title": c["title"], "detail": detail,
                    "why_it_matters": c["why"], "fix": c["fix"], "sources": c["sources"], **s, **extra})

    covered_sigs = set()
    for cid, e in summ["cve_events"].items():
        g = cve_groups.get(cid)
        if not g:
            continue
        covered_sigs |= set(e["signatures"])
        devs = [x["device"] for x in g["devices"]]
        hit_dev = sorted({ip_owner[t] for t, _ in e["targets"] if ip_owner.get(t) in devs})
        spike = next((sp for sp in summ["signature_spikes"] if sp["key"] in e["signatures"]), None)
        not_blocked = e["count"] - e["blocked"]
        top_in = max(g["devices"], key=lambda x: x["score"])["inputs"]
        add("EV-TARGETS-VULNERABLE",
            f"{e['count']} attempt(s) at {cid} ({e['signatures'][0]}); vulnerable: {', '.join(devs)}"
            + (f", aimed at {', '.join(hit_dev)} directly" if hit_dev else "")
            + (f"; {not_blocked} NOT blocked" if not_blocked else "; all blocked"),
            e["public_source"], True, top_in["automatable"], top_in["technical_impact"] == "total",
            1.0, cve=cid, targets=e["targets"],
            sources_seen=e["sources"], spike=spike)

    campaign_srcs = {s for sp in summ["signature_spikes"] if sp["key"] in covered_sigs for s, _ in sp["sources"]}
    for sig, e in summ["not_blocked"].items():
        if sig in covered_sigs:
            continue
        add("EV-NOT-BLOCKED", f"'{sig}' ({e['severity']}) seen {e['count']} time(s), action "
            f"{'/'.join(e['actions']) or 'none'}; targets {', '.join(t for t, _ in e['targets'])}",
            e["public_source"], any(c in kev for c in e["cves"]), True, e["severity"] == "critical",
            min(e["count"] / 100, 1), signature=sig, targets=e["targets"], sources_seen=e["sources"],
            cves=e["cves"])
    for kind, key in (("signature_spikes", "EV-SPIKE-SIGNATURE"), ("source_spikes", "EV-SPIKE-SOURCE")):
        for sp in summ[kind]:
            if (key == "EV-SPIKE-SIGNATURE" and sp["key"] in covered_sigs) or \
                    (key == "EV-SPIKE-SOURCE" and sp["key"] in campaign_srcs):
                continue
            what = f"'{sp['key']}'" if key == "EV-SPIKE-SIGNATURE" else \
                f"source {sp['key']} ({sp['distinct_signatures']} different signatures)"
            base = (f"not seen in the {sp['history_buckets']} hour(s) before" if sp["new"] else
                    f"normal {sp['median']:g} per hour, modified z {sp['z'] if sp['z'] is not None else 'n/a'}")
            add(key, f"{what}: {sp['count']} events {sp['start'][5:16]} to {sp['end'][11:16]} ({base}); "
                + ("all blocked" if sp["all_blocked"] else f"{sp['count'] - sp['blocked']} NOT blocked"),
                sp["public_source"], any(c in kev for c in sp["cves"]), True,
                any(s == "critical" for s in sp.get("severities", [])),
                min(sp["count"] / 1000, 1), cap="60d" if sp["all_blocked"] else None, spike=sp)
    return out


def _ev_light(s):
    if not s:
        return None
    return {k: s[k] for k in ("events", "rows", "buckets", "bucket_minutes", "first", "last", "top_signatures")}


def markdown(rep, checks):
    L = [f"# Network security check, {rep['generated'][:16].replace('T', ' ')}", ""]
    c = rep["counts"]
    L.append("| Deadline (CISA BOD 26-04) | Findings |\n|---|---|")
    for b in scoring.ORDER:
        label = scoring.BANDS[b][2] + (" (CVEs) / in the next maintenance window (config)" if b == "upgrade" else "")
        L.append(f"| {label} | {c.get(b, 0)} |")
    L.append("")
    rc = rep.get("result_counts") or {}
    if any(rc.values()):
        L.append(f"Config checks run: {rc.get('pass', 0)} pass, {rc.get('fail', 0)} fail, {rc.get('n/a', 0)} not "
                 f"applicable, {rc.get('not-visible', 0)} not visible in the snapshot. Per-device results are in "
                 "the JSON report (devices[].results).")
        if rep.get("accepted_risk"):
            L.append(f"{len(rep['accepted_risk'])} finding(s) accepted as risk (see Accepted risk): not in the "
                     "counts above.")
        L.append("")
    if rep["upgrade_plan"]:
        L.append("## Upgrade plan (one upgrade clears every CVE listed for a device)\n")
        L.append("| Device | Version | CVEs | In KEV | 3d+triage | 3d | 14d | 60d | Upgrade | Feature off |")
        L.append("|---|---|---|---|---|---|---|---|---|---|")
        for r in rep["upgrade_plan"]:
            b = r["by_deadline"]
            L.append(f"| {r['device']} | {r['version']} | {r['cves']} | {r['kev']} | {b['3d+triage']} | {b['3d']} | "
                     f"{b['14d']} | {b['60d']} | {b['upgrade']} | {r['feature_off']} |")
        L.append("")
    urgent = ("3d+triage", "3d", "14d")
    for title, typ in (("CVEs on your devices", "cve"), ("Configuration", "config"), ("Firewall events", "event")):
        rows = [f for f in rep["findings"] if f["type"] == typ]
        if not rows:
            continue
        L.append(f"## {title} ({len(rows)})\n")
        shown = [f for f in rows if f["deadline"] in urgent] if typ == "cve" else rows
        for f in shown:
            if typ == "cve":
                devs = ", ".join(f"{d['device']} ({d['version']}, {d['score']})" for d in f["devices"])
                epss = f["epss"].get("epss")
                L.append(f"- **{f['score']}** {f['id']}: {f['title']}. Devices: {devs}. "
                         f"KEV: {'yes' if f['kev'] else 'no'}. EPSS: {f'{epss:.3f}' if epss is not None else 'n/a'}. "
                         f"CVSS: {(f['cvss'] or {}).get('score', 'n/a')}. Exposure: {f['why'].get('publicly_exposed')}.")
            elif typ == "config":
                L.append(f"- **{f['score']}** {f['id']} on {f['device']}: {f['detail']}. Fix: {f['fix']}")
            else:
                L.append(f"- **{f['score']}** {f['id']}: {f['detail']}")
        rest = len(rows) - len(shown)
        if rest:
            L.append(f"- ...and {rest} more CVEs at 60 days or next upgrade: see the JSON report.")
        L.append("")
    if rep.get("accepted_risk"):
        L.append(f"## Accepted risk ({len(rep['accepted_risk'])})\n")
        L.append("Waived in exceptions.yaml (NIST SP 800-53 CA-5, RA-7). Still open: not counted against "
                 "a deadline until the waiver expires.\n")
        for f in rep["accepted_risk"]:
            a = f["accepted"]
            L.append(f"- **{f['score']}** {f['id']} on {f['device']}: {f['detail']}. Accepted: {a['reason']}"
                     + (f" (owner {a['owner']})" if a.get("owner") else "") + f". Expires {a['expires']}.")
        L.append("")
    hidden = [f"{d['name']}: {r['check']}" for d in rep["devices"] for r in d.get("results", [])
              if r["status"] == "not-visible"]
    if hidden:
        L.append("## Not visible in the snapshot\n")
        L.append("These checks could not run because the config section they need is missing or unreadable: "
                 + "; ".join(hidden) + ".\n")
    if rep["notes"] or any(d["notes"] for d in rep["devices"]):
        L.append("## Coverage notes\n")
        L += [f"- {n}" for n in rep["notes"]]
        L += [f"- {d['name']}: {n}" for d in rep["devices"] for n in d["notes"]]
    L.append("\nCVE data: CVE.org, CISA KEV, FIRST EPSS. This product uses data from the NVD API but "
             "is not endorsed or certified by the NVD.")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Read-only network security check from snapshot files.")
    ap.add_argument("action", choices=["fetch", "run", "check-settings"])
    ap.add_argument("--repo", default="~/network-snapshots", help="network-snapshot repo")
    ap.add_argument("--out", default="~/network-security", help="advisory cache and reports")
    ap.add_argument("--site")
    ap.add_argument("--device")
    ap.add_argument("--events", nargs="*", help="exported IPS / threat event files")
    ap.add_argument("--bucket-minutes", type=int, default=60)
    ap.add_argument("--no-cves", action="store_true", help="skip CVE matching")
    ap.add_argument("--cves", nargs="*", help="fetch only these CVE IDs (testing)")
    ap.add_argument("--max-age-days", type=int, default=30, help="refetch cached CVE records older than this")
    args = ap.parse_args()
    platforms, checks = load_settings()

    if args.action == "check-settings":
        return check_settings(platforms, checks)
    if args.action == "fetch":
        repo = Path(args.repo).expanduser()
        used = sorted(p for p in {d.get("device_type") for d in load_devices(repo)} & set(platforms)
                      if platforms[p].get("cve_matching") != "manual")
        idx = advisories.fetch(platforms, used, Path(args.out).expanduser() / "advisories", args.cves,
                               args.max_age_days, log=lambda m: print(m, file=sys.stderr))
        print(json.dumps({"fetched": idx["fetched"], "kev_version": idx["kev_version"],
                          "platforms": {p: len(v) for p, v in idx["platform_cves"].items()}}, indent=1))
        return
    rep = build(args)
    out = Path(args.out).expanduser() / "reports"
    out.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y-%m-%d-%H%M")
    (out / f"{stamp}.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    (out / f"{stamp}.md").write_text(markdown(rep, checks), encoding="utf-8")
    (out / "last-report.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    print(json.dumps({"report_json": str(out / f"{stamp}.json"), "report_md": str(out / f"{stamp}.md"),
                      "counts": rep["counts"], "findings": len(rep["findings"]),
                      "top": [{k: f.get(k) for k in ("score", "deadline", "type", "id", "device", "title")}
                              for f in rep["findings"][:10]],
                      "notes": rep["notes"]}, indent=1, default=str))


def check_settings(platforms, checks):
    keys = set(re.findall(r"^\| ([a-z0-9-]+) \|", (HERE.parent / "research" / "sources.md").read_text(
        encoding="utf-8"), re.M))
    bad = []
    for cid, c in checks.items():
        for k in ("title", "why", "fix", "known_exploited", "automatable", "total_control", "weight", "sources",
                  "plane", "validated"):
            if k not in c:
                bad.append(f"{cid}: missing {k}")
        if "plane" in c and c["plane"] not in PLANES:
            bad.append(f"{cid}: plane '{c['plane']}' is not one of {', '.join(PLANES)}")
        if "validated" in c and c["validated"] not in VALIDATED:
            bad.append(f"{cid}: validated '{c['validated']}' is not one of {', '.join(VALIDATED)}")
        bad += [f"{cid}: control '{x}' is not an 800-53 ID like AC-17 or SC-7(5)"
                for x in c.get("controls", []) if not re.match(r"^[A-Z]{2}-\d{1,2}(\(\d{1,2}\))?$", str(x))]
        if c.get("zt_pillar") not in (None, *ZT_PILLARS):
            bad.append(f"{cid}: zt_pillar '{c['zt_pillar']}' is not one of {', '.join(ZT_PILLARS)}")
        bad += [f"{cid}: source '{s}' not in research/sources.md" for s in c.get("sources", []) if s not in keys]
    for p, cfg in platforms.items():
        for k in ("vendor", "kind", "version", "config", "cpe", "cna_product"):
            if k not in cfg:
                bad.append(f"platform {p}: missing {k}")
    bad += lifecycle.validate(lifecycle.load(), keys)
    print("\n".join(bad) or f"OK: {len(checks)} checks, {len(platforms)} platforms, every check sourced")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
