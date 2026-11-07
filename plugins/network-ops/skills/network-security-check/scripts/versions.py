# ============================================================
# Script:       versions.py
# Purpose:      Compare network OS versions the way vendors write them, and decide whether
#               one version is affected by a CVE record. Handles IOS-XE (17.09.04a),
#               ASA and NX-OS (9.18(3)56), PAN-OS (10.2.7-h3), FortiOS (7.4.2),
#               Junos (21.4R3-S5.4), EOS (4.30.2F) and AOS-CX (FL.10.10.1000).
# Author:       G Talks Tech
# Notes:        Matching follows the CVE JSON 5 "affected" rules (version, lessThan,
#               lessThanOrEqual, changes, defaultStatus). For PAN-OS, Palo Alto's own data
#               is used instead: its list of affected releases (x_affectedList) OR its ranges
#               read per maintenance release (x_per_release). See research/sources.md.
# ============================================================
import re


def tokens(v):
    """Split a version into comparable parts. '17.09.04a' -> (17, 9, 4, 'a')."""
    v = str(v).strip().lower()
    v = re.sub(r"^[a-z]{2}\.", "", v)            # AOS-CX platform prefix: FL.10.10.1000
    v = re.sub(r"^(pan-os|fortios|junos|eos)\s+", "", v)
    out = []
    for t in re.findall(r"\d+|[a-z]+", v):
        out.append(int(t) if t.isdigit() else t)
    return tuple(out)


def _key(v):
    # ints sort before letters at the same position: 17.9.4 < 17.9.4a, 10.2.7 < 10.2.7-h1
    return tuple((0, t, "") if isinstance(t, int) else (1, 0, t) for t in tokens(v))


def cmp(a, b):
    ka, kb = _key(a), _key(b)
    return (ka > kb) - (ka < kb)


def same(a, b):
    return tokens(a) == tokens(b)


def _open_start(v):
    return str(v).strip() in ("", "0", "*", "n/a", "unspecified")


def _release(v):
    """PAN-OS maintenance release without the hotfix: 10.2.7-h3 -> (10, 2, 7)."""
    t = tokens(v)
    return t[: t.index("h")] if "h" in t else t


def status_per_release(version, entry):
    """Palo Alto's own ranges: {version: 10.2, changes: [{at: 10.2.7-h8, ...}, ...]} list the
    first fixed hotfix of each maintenance release. A version is affected when it is older than
    the fix on its own release, or when its release is older than every fixed release listed.
    Returns None when the entry is for another train."""
    train = tokens(entry.get("version", ""))
    t = tokens(version)
    if not train or t[: len(train)] != train or entry.get("status") != "affected":
        return None
    fixes = [c["at"] for c in entry.get("changes", []) if c.get("status") == "unaffected"]
    if not fixes:
        return "affected"
    rel = _release(version)
    same = [f for f in fixes if _release(f) == rel]
    if same:
        return "affected" if cmp(version, min(same, key=_key)) < 0 else "unaffected"
    newest = max((_release(f) for f in fixes), key=lambda r: _key(".".join(map(str, r))))
    return "affected" if _key(".".join(map(str, rel))) < _key(".".join(map(str, newest))) else "unaffected"


def status_in_entry(version, entry):
    """Status ('affected' / 'unaffected') that one CVE 5 versions[] entry gives this version,
    or None when the entry does not cover it."""
    start = entry.get("version", "")
    upper_lt, upper_le = entry.get("lessThan"), entry.get("lessThanOrEqual")
    status = entry.get("status", "affected")
    if not upper_lt and not upper_le:
        return status if same(version, start) else None
    if not _open_start(start) and cmp(version, start) < 0:
        return None
    if upper_lt and not (upper_lt == "*" or cmp(version, upper_lt) < 0):
        return None
    if upper_le and not (upper_le == "*" or cmp(version, upper_le) <= 0):
        return None
    for ch in sorted(entry.get("changes", []), key=lambda c: _key(c["at"])):
        if cmp(version, ch["at"]) >= 0:
            status = ch["status"]
    return status


def affected_by(version, affected_blocks, product_regex):
    """Return (state, product) where state is 'affected', 'unaffected' or 'unknown'.
    affected_blocks: the CNA 'affected' list from a CVE 5 record (plus our x_affectedList)."""
    rx = re.compile(product_regex, re.I)
    seen_product = None
    for blk in affected_blocks:
        if not rx.search(blk.get("product", "")):
            continue
        seen_product = blk.get("product")
        listed = blk.get("x_affectedList")
        if listed and any(same(version, x) for x in listed):
            return "affected", seen_product
        if blk.get("x_per_release"):
            st = [status_per_release(version, e) for e in blk.get("versions", [])]
            if "affected" in st:
                return "affected", seen_product
            continue
        if listed:
            continue
        result = None
        for entry in blk.get("versions", []):
            st = status_in_entry(version, entry)
            if st is not None:
                result = st
                if st == "affected":
                    break
        if result == "affected":
            return "affected", seen_product
        if result is None and blk.get("defaultStatus") == "affected":
            return "affected", seen_product
    if seen_product:
        return "unaffected", seen_product
    return "unknown", None


def affected_by_cpe(version, cpe_matches, cpe_prefixes):
    """Fallback on NVD configurations when the CNA record has no usable version data.
    cpe_matches: list of NVD cpeMatch dicts (vulnerable=true)."""
    for m in cpe_matches:
        parts = m.get("criteria", "").split(":")
        if len(parts) < 6 or f"{parts[3]}:{parts[4]}" not in cpe_prefixes or not m.get("vulnerable", True):
            continue
        exact = parts[5]
        bounds = [k for k in ("versionStartIncluding", "versionStartExcluding",
                              "versionEndIncluding", "versionEndExcluding") if k in m]
        if exact not in ("*", "-") and not bounds:
            if same(version, exact):
                return "affected"
            continue
        ok = True
        if "versionStartIncluding" in m:
            ok &= cmp(version, m["versionStartIncluding"]) >= 0
        if "versionStartExcluding" in m:
            ok &= cmp(version, m["versionStartExcluding"]) > 0
        if "versionEndIncluding" in m:
            ok &= cmp(version, m["versionEndIncluding"]) <= 0
        if "versionEndExcluding" in m:
            ok &= cmp(version, m["versionEndExcluding"]) < 0
        if ok and bounds:
            return "affected"
    return "unaffected" if cpe_matches else "unknown"
