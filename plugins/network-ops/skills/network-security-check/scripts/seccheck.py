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
import scoring  # noqa: E402
import vendor_asa  # noqa: E402
import vendor_fortios  # noqa: E402
import vendor_ios  # noqa: E402
import vendor_junos  # noqa: E402
import vendor_panos  # noqa: E402

SETTINGS = HERE.parent / "settings"
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
    p = dev["device_type"]
    out = {"name": dev["name"], "site": dev.get("site", "unassigned"), "platform": p,
           "version": None, "model": None, "findings": [], "features": {}, "notes": [],
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
            mm = re.search(pcfg["version"]["model"], txt, re.M | re.I)
            out["model"] = mm.group(1).strip() if mm else None
    if not out["version"]:
        out["notes"].append(f"software version not found in {vf.name}: CVE matching skipped")

    cfg = folder / pcfg["config"]["file"]
    mod = PARSERS.get(pcfg["config"]["parser"])
    facts = None
    if mod and cfg.exists():
        facts, found = mod.analyze(cfg.read_text(encoding="utf-8", errors="replace"), dev)
        out["findings"] = found
        out["features"] = facts["features"]
        out["notes"] += facts["notes"]
        out["interface_ips"] = [ip.split("/")[0] for i in facts["interfaces"] for ip in i.get("ips", [])]
    elif mod:
        out["notes"].append(f"config file {cfg.name} missing: config checks skipped")
    else:
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

    text = f"{rec.get('title', '')} {rec.get('description', '')} {rec.get('configurations', '')}"
    named = [f for f, rx in (pcfg.get("features") or {}).items() if re.search(rx, text, re.I)]
    feats = dev.get("features", {})
    known = [f for f in named if f in feats]
    feature_off = False
    if known:
        exposed = any(feats[f]["internet"] for f in known)
        on = [f for f in known if feats[f]["on"]]
        if exposed:
            why["publicly_exposed"] = f"{', '.join(on)} is on an internet-facing interface"
        elif on:
            why["publicly_exposed"] = f"{', '.join(on)} is on, but not on an internet-facing interface"
        else:
            feature_off = True
            why["publicly_exposed"] = f"the affected feature ({', '.join(known)}) looks off in the config"
    else:
        exposed = bool(dev.get("internet_facing"))
        why["publicly_exposed"] = dev.get("exposure_reason", "")
    return exposed, kev, auto, total, why, feature_off, named


def build(args):
    repo = Path(args.repo).expanduser()
    out_dir = Path(args.out).expanduser()
    platforms, checks = load_settings()
    devices = load_devices(repo, args.site, args.device)
    facts = [device_facts(d, repo, platforms) for d in devices]
    by_name = {f["name"]: f for f in facts}
    findings, notes = [], []

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
        age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(cache["fetched"])
        if age.days > 7:
            notes.append(f"advisory cache is {age.days} days old: run fetch again for current KEV and EPSS")
        for d in facts:
            if not d.get("version"):
                continue
            pcfg = platforms[d["platform"]]
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
                                  cap="14d" if off else None)
                g = cve_groups.setdefault(cid, {"type": "cve", "id": cid, "title": h["record"]["title"],
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
            s = scoring.score(f["exposed"], c["known_exploited"], c["automatable"], c["total_control"],
                              c["weight"])
            findings.append({"type": "config", "id": f["check"], "title": c["title"], "device": d["name"],
                             "detail": f["detail"], "evidence": f["evidence"], "why_it_matters": c["why"],
                             "fix": c["fix"], "sources": c["sources"],
                             "why": {"publicly_exposed": d.get("exposure_reason") if f["exposed"] else
                                     "not reachable from a public network per this config"}, **s})

    # ---------- event findings ----------
    if ev_summary:
        findings += event_findings(ev_summary, checks, cve_groups, by_name, cache)

    findings.sort(key=lambda f: (-f["score"], f["id"]))
    return {"generated": dt.datetime.now().isoformat(timespec="seconds"), "repo": str(repo),
            "advisory_cache": {"fetched": cache["fetched"], "kev_version": cache["kev_version"]} if cache else None,
            "devices": [{k: v for k, v in d.items() if k != "findings"} for d in facts],
            "counts": {b: sum(1 for f in findings if f["deadline"] == b) for b in scoring.ORDER},
            "findings": findings, "events": _ev_light(ev_summary), "notes": notes}


def event_findings(summ, checks, cve_groups, by_name, cache):
    out = []
    ip_owner = {ip: n for n, d in by_name.items() for ip in d.get("interface_ips", [])}

    def add(check, detail, exposed, kev, auto, total, tiebreak, cap=None, **extra):
        c = checks[check]
        s = scoring.score(exposed, kev, auto, total, tiebreak, cap)
        out.append({"type": "event", "id": check, "title": c["title"], "detail": detail,
                    "why_it_matters": c["why"], "fix": c["fix"], "sources": c["sources"], **s, **extra})

    for cid, e in summ["cve_events"].items():
        g = cve_groups.get(cid)
        if not g:
            continue
        devs = [x["device"] for x in g["devices"]]
        hit_dev = sorted({ip_owner[t] for t, _ in e["targets"] if ip_owner.get(t) in devs})
        add("EV-TARGETS-VULNERABLE",
            f"{e['count']} event(s) for {cid} ({', '.join(e['signatures'][:2])}); vulnerable device(s): "
            f"{', '.join(devs)}" + (f"; events aimed at {', '.join(hit_dev)} directly" if hit_dev else "")
            + f"; {e['blocked']} of {e['count']} blocked",
            e["public_source"], True, True, True, 1.0, cve=cid, targets=e["targets"], sources_seen=e["sources"])
    for sig, e in summ["not_blocked"].items():
        kev = any(c in (cache or {}).get("kev", {}) for c in e["cves"])
        add("EV-NOT-BLOCKED", f"'{sig}' ({e['severity']}) seen {e['count']} time(s), action "
            f"{'/'.join(e['actions']) or 'none'}", e["public_source"], kev, True,
            e["severity"] == "critical", min(e["count"] / 100, 1), signature=sig, targets=e["targets"],
            sources_seen=e["sources"], cves=e["cves"])
    for kind, key in (("signature_spikes", "EV-SPIKE-SIGNATURE"), ("source_spikes", "EV-SPIKE-SOURCE")):
        for sp in summ[kind]:
            kev = any(c in (cache or {}).get("kev", {}) for c in sp["cves"])
            what = f"'{sp['key']}'" if key == "EV-SPIKE-SIGNATURE" else f"source {sp['key']}"
            add(key, f"{what}: {sp['count']} events in the hour from {sp['bucket_start']} (normal "
                f"{sp['median']:g}, modified z {sp['z'] if sp['z'] is not None else 'n/a, flat baseline'})"
                + ("; all blocked" if sp["all_blocked"] else "; NOT all blocked"),
                sp["public_source"], kev, True, False, min(sp["count"] / 1000, 1),
                cap="60d" if sp["all_blocked"] else None, spike=sp)
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
        L.append(f"| {scoring.BANDS[b][2]} | {c.get(b, 0)} |")
    L.append("")
    for title, typ in (("CVEs on your devices", "cve"), ("Configuration", "config"), ("Firewall events", "event")):
        rows = [f for f in rep["findings"] if f["type"] == typ]
        if not rows:
            continue
        L.append(f"## {title} ({len(rows)})\n")
        for f in rows:
            if typ == "cve":
                devs = ", ".join(f"{d['device']} ({d['version']}, {d['score']})" for d in f["devices"])
                epss = f["epss"].get("epss")
                L.append(f"- **{f['score']}** {f['id']}: {f['title']}. Devices: {devs}. "
                         f"KEV: {'yes' if f['kev'] else 'no'}. EPSS: {f'{epss:.3f}' if epss is not None else 'n/a'}. "
                         f"CVSS: {(f['cvss'] or {}).get('score', 'n/a')}. Why: {f['why'].get('publicly_exposed')}.")
            elif typ == "config":
                L.append(f"- **{f['score']}** {f['id']} on {f['device']}: {f['detail']}. Fix: {f['fix']}")
            else:
                L.append(f"- **{f['score']}** {f['id']}: {f['detail']}")
        L.append("")
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
        used = sorted({d["device_type"] for d in load_devices(repo)} & set(platforms))
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
        for k in ("title", "why", "fix", "known_exploited", "automatable", "total_control", "weight", "sources"):
            if k not in c:
                bad.append(f"{cid}: missing {k}")
        bad += [f"{cid}: source '{s}' not in research/sources.md" for s in c.get("sources", []) if s not in keys]
    for p, cfg in platforms.items():
        for k in ("vendor", "kind", "version", "config", "cpe", "cna_product"):
            if k not in cfg:
                bad.append(f"platform {p}: missing {k}")
    print("\n".join(bad) or f"OK: {len(checks)} checks, {len(platforms)} platforms, every check sourced")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
