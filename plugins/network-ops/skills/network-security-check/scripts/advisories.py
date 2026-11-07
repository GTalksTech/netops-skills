# ============================================================
# Script:       advisories.py
# Purpose:      Build and read the local advisory cache: which CVEs exist for each network
#               OS in use, which versions they affect, whether they are exploited (CISA KEV),
#               how likely exploitation is (FIRST EPSS), and CISA's SSVC answers.
#               fetch() needs the internet; match() works offline from the cache.
# Sources:      CVE.org records (vendor affected versions, CISA Vulnrichment), NVD API 2.0
#               (finding CVE IDs per product), CISA KEV, FIRST EPSS, Palo Alto JSON advisories.
# Author:       G Talks Tech
# Notes:        Public data only. Nothing about the user's network is sent out: queries name
#               a product (e.g. "FortiOS") or a CVE ID, never a device, address or version.
# ============================================================
import datetime as dt
import json
import os
import re
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import versions

UA = "Mozilla/5.0 (compatible; netops-skills network-security-check)"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_URL = "https://cveawg.mitre.org/api/cve/"
PAN_URL = "https://security.paloaltonetworks.com/json/"
EXPLOITED = re.compile(r"aware of (?:\w+ ){0,4}exploit|actively exploited|exploited in the wild|"
                       r"(?:limited|malicious|active) exploitation|attempts? to exploit .* in the wild", re.I)


def http_json(url, headers=None, tries=4):
    for n in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if n == tries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if n == tries - 1:
                raise
        time.sleep(2 ** (n + 1))


def _nvd_ids(params, key):
    """All CVE IDs (with lastModified and NVD cpeMatch) for one NVD query, paged."""
    out, start = {}, 0
    hdr = {"apiKey": key} if key else {}
    while True:
        q = urllib.parse.urlencode({**params, "resultsPerPage": 2000, "startIndex": start})
        data = http_json(f"{NVD_URL}?{q}", hdr) or {}
        for v in data.get("vulnerabilities", []):
            c = v["cve"]
            matches = [m for cfg in c.get("configurations", []) for n in cfg.get("nodes", [])
                       for m in n.get("cpeMatch", []) if m.get("vulnerable")]
            out[c["id"]] = {"lastModified": c.get("lastModified"), "cpe": matches}
        start += data.get("resultsPerPage", 0)
        time.sleep(0.7 if key else 6.5)  # NVD: 50 or 5 requests per 30 s
        if not data or start >= data.get("totalResults", 0):
            return out


def _cvss(containers):
    for c in containers:
        for m in c.get("metrics", []):
            for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if k in m:
                    x = m[k]
                    return {"version": x.get("version"), "score": x.get("baseScore"),
                            "vector": x.get("vectorString"), "severity": x.get("baseSeverity")}
    return None


def trim(record, cpe=None, pan=None):
    """Keep only what matching and scoring need from a CVE 5 record."""
    cna = record["containers"]["cna"]
    adp = record["containers"].get("adp", [])
    ssvc, kev_adp = {}, None
    for a in adp:
        for m in a.get("metrics", []):
            o = m.get("other", {})
            if o.get("type") == "ssvc":
                for opt in o["content"].get("options", []):
                    ssvc.update({k.lower().replace(" ", "_"): v for k, v in opt.items()})
            elif o.get("type") == "kev":
                kev_adp = o["content"].get("dateAdded")
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "en").startswith("en")), "")
    affected = [{k: b[k] for k in ("product", "versions", "defaultStatus") if k in b}
                for b in cna.get("affected", [])]
    if pan and pan.get("containers", {}).get("cna", {}).get("affected"):
        # CVE.org's copy of Palo Alto records flags fixed hotfixes as affected, and Palo Alto's
        # x_affectedList alone misses some releases. Keep Palo Alto's ranges (read per release)
        # plus its list; a version is affected if either says so.
        pcna = pan["containers"]["cna"]
        listed = [re.sub(r"^PAN-OS\s+", "", s) for s in pcna.get("x_affectedList", []) if s.startswith("PAN-OS")]
        affected = [{"product": b["product"], "versions": b.get("versions", []), "x_per_release": True,
                     "x_affectedList": listed if b.get("product") == "PAN-OS" else []}
                    for b in pcna["affected"]]
    texts = [desc] + [e.get("value", "") for e in cna.get("exploits", [])]
    vendor_exploited = next((t[:300] for t in texts if EXPLOITED.search(t)), None)
    refs = [r["url"] for r in cna.get("references", []) if "url" in r][:3]
    conf = " ".join(c.get("value", "") for c in cna.get("configurations", []))[:400]
    # Palo Alto names the IPS threat IDs that cover a CVE in its workarounds text. Kept so
    # threat-log events can be tied to the CVE.
    work = " ".join(w.get("value", "") for w in cna.get("workarounds", []))
    sig_ids = sorted({i for m in re.finditer(r"Threat IDs? ((?:\d{4,6}(?:,? (?:and )?)?)+)", work)
                      for i in re.findall(r"\d{4,6}", m.group(1))})
    return {"id": record["cveMetadata"]["cveId"], "title": cna.get("title") or desc[:120],
            "description": desc[:600], "published": record["cveMetadata"].get("datePublished", "")[:10],
            "cvss": _cvss([cna] + adp), "ssvc": ssvc, "kev_adp": kev_adp, "affected": affected,
            "cpe": cpe or [], "vendor_exploited": vendor_exploited, "refs": refs,
            "configurations": conf, "sig_ids": sig_ids}


def fetch(platforms, used, out_dir, only=None, max_age_days=30, log=print):
    """Refresh the cache for the platforms in use. only: list of CVE IDs (for tests/fixtures)."""
    out_dir = Path(out_dir)
    rec_dir = out_dir / "cve"
    rec_dir.mkdir(parents=True, exist_ok=True)
    key = os.environ.get("NVD_API_KEY")  # optional; never stored
    log("CISA KEV ...")
    kev_raw = http_json(KEV_URL)
    kev = {v["cveID"]: {k: v.get(k) for k in ("vendorProject", "product", "vulnerabilityName",
                                              "dateAdded", "knownRansomwareCampaignUse", "notes")}
           for v in kev_raw["vulnerabilities"]}
    plat_ids, nvd_cpe = {}, {}
    for p in used:
        cfg = platforms[p]
        ids = {}
        if only:
            ids = {c: {} for c in only}
        else:
            for cpe in cfg.get("cpe", []):
                log(f"NVD: CVEs for cpe {cpe} ...")
                ids.update(_nvd_ids({"virtualMatchString": f"cpe:2.3:o:{cpe}"}, key))
            if cfg.get("nvd_keyword"):
                log(f"NVD: keyword '{cfg['nvd_keyword']}' ...")
                for cid, v in _nvd_ids({"keywordSearch": cfg["nvd_keyword"], "keywordExactMatch": ""}, key).items():
                    ids.setdefault(cid, v)
            rx = re.compile(cfg.get("kev", "^$"), re.I)
            for cid, v in kev.items():
                if rx.search(f"{v['vendorProject']}:{v['product']}"):
                    ids.setdefault(cid, {})
        plat_ids[p] = sorted(ids)
        for cid, v in ids.items():
            if v.get("cpe"):
                nvd_cpe[cid] = v["cpe"]
        log(f"{p}: {len(ids)} candidate CVEs")

    wanted = sorted({c for ids in plat_ids.values() for c in ids})
    pan_ids = set(plat_ids.get("paloalto_panos", []))
    cutoff = time.time() - max_age_days * 86400

    def get_one(cid):
        f = rec_dir / f"{cid}.json"
        if f.exists() and f.stat().st_mtime > cutoff:
            return
        rec = http_json(CVE_URL + cid)
        if not rec or rec.get("cveMetadata", {}).get("state") != "PUBLISHED":
            return
        pan = http_json(PAN_URL + cid) if cid in pan_ids else None
        f.write_text(json.dumps(trim(rec, nvd_cpe.get(cid), pan)), encoding="utf-8")

    log(f"CVE.org: {len(wanted)} records (cached ones younger than {max_age_days} days are kept) ...")
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(get_one, wanted))
    for cid in wanted:  # NVD cpe data can arrive after the record was cached
        f = rec_dir / f"{cid}.json"
        if f.exists() and nvd_cpe.get(cid):
            r = json.loads(f.read_text(encoding="utf-8"))
            if r.get("cpe") != nvd_cpe[cid]:
                r["cpe"] = nvd_cpe[cid]
                f.write_text(json.dumps(r), encoding="utf-8")

    log("FIRST EPSS ...")
    epss = {}
    for i in range(0, len(wanted), 100):
        data = http_json(EPSS_URL + ",".join(wanted[i:i + 100])) or {}
        for e in data.get("data", []):
            epss[e["cve"]] = {"epss": float(e["epss"]), "percentile": float(e["percentile"]), "date": e["date"]}
    index = {"fetched": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
             "kev_version": kev_raw.get("catalogVersion"), "platform_cves": plat_ids,
             "kev": {c: kev[c] for c in wanted if c in kev}, "epss": epss}
    (out_dir / "index.json").write_text(json.dumps(index, indent=1), encoding="utf-8")
    return index


def load(cache_dir):
    cache_dir = Path(cache_dir)
    idx_file = cache_dir / "index.json"
    if not idx_file.exists():
        return None
    idx = json.loads(idx_file.read_text(encoding="utf-8"))
    recs = {}
    for f in (cache_dir / "cve").glob("CVE-*.json"):
        recs[f.stem] = json.loads(f.read_text(encoding="utf-8"))
    idx["records"] = recs
    return idx


def match(device, pcfg, cache):
    """Every cached CVE that affects this device's version. Returns (hits, stats)."""
    hits, stats = [], {"checked": 0, "no_version_data": 0}
    ver = device.get("version")
    if not ver:
        return hits, stats
    for cid in cache["platform_cves"].get(device["platform"], []):
        rec = cache["records"].get(cid)
        if not rec:
            continue
        stats["checked"] += 1
        state, product = versions.affected_by(ver, rec["affected"], pcfg["cna_product"])
        how = "vendor CVE record"
        if state == "unknown":
            state = versions.affected_by_cpe(ver, rec.get("cpe", []), pcfg.get("cpe", []))
            how = "NVD CPE data"
        if state == "unknown":
            stats["no_version_data"] += 1
        if state == "affected":
            hits.append({"cve": cid, "record": rec, "matched_by": how, "product": product})
    return hits, stats
