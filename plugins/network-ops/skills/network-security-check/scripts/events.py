# ============================================================
# Script:       events.py
# Purpose:      Read exported firewall IPS / threat events and find what matters: attacks on a
#               CVE you are vulnerable to, critical attacks that were not blocked, and spikes
#               per signature or per source.
# Formats:      CSV with a header row (PAN-OS threat log export, FMC intrusion event export,
#               most SIEM exports), FortiGate key=value logs (type=utm subtype=ips), and JSON
#               lines (Suricata / OPNsense eve.json). Columns are found by name, not position.
# Author:       G Talks Tech
# Notes:        Spike test: modified z-score (NIST/SEMATECH e-Handbook 1.3.5.17).
# ============================================================
import csv
import datetime as dt
import io
import json
import re
import statistics
from collections import Counter, defaultdict

from common import is_public

ALIASES = {
    "time": ["receive time", "generate time", "time generated", "time_generated", "timestamp",
             "date/time", "eventtime", "datetime", "time", "first packet"],
    "signature": ["threat/content name", "threat name", "threat_name", "attack", "attack name",
                  "signature", "message", "msg", "alert.signature", "threat"],
    "sig_id": ["threat id", "threatid", "attackid", "attack id", "signature id", "signature_id",
               "sid", "alert.signature_id", "snort id"],
    "src": ["source address", "source ip", "srcip", "src_ip", "src", "initiator ip", "source"],
    "dst": ["destination address", "destination ip", "dstip", "dest_ip", "dst_ip", "dst",
            "responder ip", "destination"],
    "severity": ["severity", "crlevel", "priority", "alert.severity", "level", "impact"],
    "action": ["action", "inline result", "alert.action"],
    "count": ["repeat count", "count"],
}
BLOCKED = re.compile(r"^(drop|dropped|drop-all-packets|drop-packet|block|blocked|block-ip|deny|denied|"
                     r"reset|reset-both|reset-client|reset-server|sinkhole|blocked by policy)$", re.I)
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SEV_MAP = {"1": "high", "2": "medium", "3": "low", "4": "info"}  # Suricata / FMC numeric priority


def _norm_sev(v):
    v = str(v or "").strip().lower()
    v = SEV_MAP.get(v, v)
    return {"crit": "critical", "informational": "info", "information": "info", "notice": "low",
            "warning": "medium", "alert": "high", "emergency": "critical"}.get(v, v)


def _parse_time(v):
    v = str(v or "").strip().strip('"')
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S",
                "%Y-%m-%d %H:%M"):
        try:
            return dt.datetime.strptime(v[:19], fmt)
        except ValueError:
            pass
    try:
        return dt.datetime.fromisoformat(v.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _flat(d, prefix=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(_flat(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}".lower()] = v
    return out


def _pick(row, field):
    for a in ALIASES[field]:
        if a in row and row[a] not in (None, ""):
            return row[a]
    return None


def _event(row, source):
    sig = _pick(row, "signature")
    if not sig:
        return None
    sig_id = _pick(row, "sig_id")
    m = re.search(r"\((\d+)\)\s*$", str(sig))      # PAN-OS: "Name(95187)"
    if m and not sig_id:
        sig_id = m.group(1)
    if row.get("type") == "utm" and row.get("subtype") not in (None, "ips"):
        return None
    when = _parse_time(_pick(row, "time"))
    if not when and row.get("date") and row.get("time"):
        when = _parse_time(f"{row['date']} {row['time']}")
    action = str(_pick(row, "action") or "").strip().lower()
    cves = sorted({c.upper() for c in CVE_RX.findall(" ".join(str(v) for v in row.values()))})
    try:
        count = int(_pick(row, "count") or 1)
    except ValueError:
        count = 1
    return {"time": when, "signature": str(sig).strip(), "sig_id": str(sig_id or ""),
            "src": str(_pick(row, "src") or ""), "dst": str(_pick(row, "dst") or ""),
            "severity": _norm_sev(_pick(row, "severity")), "action": action,
            "blocked": bool(BLOCKED.match(action)), "cves": cves, "count": max(count, 1),
            "file": source}


def read_events(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    first = next((l for l in text.splitlines() if l.strip()), "")
    rows = []
    if first.lstrip().startswith("{"):
        for l in text.splitlines():
            if l.strip():
                try:
                    rows.append(_flat(json.loads(l)))
                except json.JSONDecodeError:
                    continue
    elif re.search(r"\b\w+=(\"[^\"]*\"|\S+)\s+\w+=", first):
        for l in text.splitlines():
            rows.append({k.lower(): v.strip('"') for k, v in re.findall(r"([\w.]+)=(\"[^\"]*\"|\S+)", l)})
    else:
        rd = csv.DictReader(io.StringIO(text))
        rows = [{(k or "").strip().lower(): v for k, v in r.items()} for r in rd]
    evs = [e for e in (_event(r, str(path)) for r in rows) if e]
    return evs


def modified_z(series):
    """Iglewicz-Hoaglin modified z-scores. None when MAD is 0 (most buckets equal)."""
    med = statistics.median(series)
    mad = statistics.median([abs(x - med) for x in series])
    if mad == 0:
        return med, None
    return med, [0.6745 * (x - med) / mad for x in series]


def _buckets(evs, key, size):
    first = min(e["time"] for e in evs)
    t0 = dt.datetime.min + ((first - dt.datetime.min) // size) * size   # align to the clock
    n = int((max(e["time"] for e in evs) - t0) / size) + 1
    per = defaultdict(lambda: [0] * n)
    for e in evs:
        per[key(e)][int((e["time"] - t0) / size)] += e["count"]
    return t0, n, per


def spikes(evs, key, size, z_limit=3.5, min_count=20, min_buckets=8):
    """Buckets where one key (signature or source) jumps. House rules (SCORING.md): at least
    min_buckets of history, at least min_count events in the bucket, and when MAD is 0 the
    bucket must also be 5x above (median + 1)."""
    timed = [e for e in evs if e["time"]]
    if not timed:
        return [], 0
    t0, n, per = _buckets(timed, key, size)
    if n < min_buckets:
        return [], n
    out = []
    for k, series in per.items():
        med, zs = modified_z(series)
        hot = [i for i, c in enumerate(series) if c >= min_count and (
            (zs and zs[i] > z_limit) or (not zs and c >= 5 * (med + 1)))]
        # back-to-back spike buckets are one event window
        runs = []
        for i in hot:
            if runs and i == runs[-1][-1] + 1:
                runs[-1].append(i)
            else:
                runs.append([i])
        for run in runs:
            start, end = t0 + run[0] * size, t0 + (run[-1] + 1) * size
            inside = [e for e in timed if key(e) == k and start <= e["time"] < end]
            peak = max(run, key=lambda i: series[i])
            out.append({"key": k, "start": start.isoformat(sep=" "), "end": end.isoformat(sep=" "),
                        "count": sum(series[i] for i in run), "peak": series[peak],
                        "median": med, "z": round(zs[peak], 1) if zs else None,
                        "new": med == 0 and sum(series[:run[0]]) == 0,
                        "history_buckets": run[0],
                        "sources": Counter(e["src"] for e in inside).most_common(3),
                        "targets": Counter(e["dst"] for e in inside).most_common(3),
                        "signatures": Counter(e["signature"] for e in inside).most_common(3),
                        "distinct_signatures": len({e["signature"] for e in inside}),
                        "blocked": sum(e["count"] for e in inside if e["blocked"]),
                        "all_blocked": all(e["blocked"] for e in inside),
                        "public_source": any(is_public(e["src"]) for e in inside),
                        "cves": sorted({c for e in inside for c in e["cves"]})})
    return out, n


def summarize(evs, bucket_minutes=60):
    size = dt.timedelta(minutes=bucket_minutes)
    sig_spikes, n = spikes(evs, lambda e: e["signature"], size)
    src_spikes, _ = spikes(evs, lambda e: e["src"], size)
    not_blocked = defaultdict(list)
    for e in evs:
        if not e["blocked"] and e["severity"] in ("critical", "high"):
            not_blocked[e["signature"]].append(e)
    times = [e["time"] for e in evs if e["time"]]
    return {"events": sum(e["count"] for e in evs), "rows": len(evs), "buckets": n,
            "bucket_minutes": bucket_minutes,
            "first": min(times).isoformat(sep=" ") if times else None,
            "last": max(times).isoformat(sep=" ") if times else None,
            "signature_spikes": sig_spikes, "source_spikes": src_spikes,
            "not_blocked": {k: {"count": sum(e["count"] for e in v), "severity": v[0]["severity"],
                                "actions": sorted({e["action"] for e in v}),
                                "sources": Counter(e["src"] for e in v).most_common(3),
                                "targets": Counter(e["dst"] for e in v).most_common(3),
                                "public_source": any(is_public(e["src"]) for e in v),
                                "cves": sorted({c for e in v for c in e["cves"]})}
                            for k, v in not_blocked.items()},
            "cve_events": _by_cve(evs),
            "top_signatures": Counter({s: sum(e["count"] for e in evs if e["signature"] == s)
                                       for s in {e["signature"] for e in evs}}).most_common(5)}


def _by_cve(evs):
    out = defaultdict(lambda: {"count": 0, "blocked": 0, "targets": Counter(), "sources": Counter(),
                               "signatures": set(), "public_source": False})
    for e in evs:
        for c in e["cves"]:
            o = out[c]
            o["count"] += e["count"]
            o["blocked"] += e["count"] if e["blocked"] else 0
            o["targets"][e["dst"]] += e["count"]
            o["sources"][e["src"]] += e["count"]
            o["signatures"].add(e["signature"])
            o["public_source"] |= is_public(e["src"])
    return {c: {**o, "targets": o["targets"].most_common(5), "sources": o["sources"].most_common(3),
                "signatures": sorted(o["signatures"])} for c, o in out.items()}
