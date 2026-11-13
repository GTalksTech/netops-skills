# ============================================================
# Script:       common.py
# Purpose:      Helpers shared by the vendor modules: public vs private addresses,
#               segment names, risky ports, and the check result record.
# Author:       G Talks Tech
# ============================================================
import ipaddress
import re
from pathlib import Path

import yaml

SETTINGS = Path(__file__).resolve().parent.parent / "settings"
_SEG = yaml.safe_load((SETTINGS / "segments.yaml").read_text(encoding="utf-8"))
SEGMENTED = re.compile(_SEG["segmented"], re.I)
INTERNET_NAMES = re.compile(_SEG["internet_names"], re.I)
RISKY_PORTS = {int(k): v for k, v in _SEG["risky_ports"].items()}

NOT_PUBLIC = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
    "fc00::/7", "fe80::/10", "::1/128")]


def is_public(addr):
    """True for an address reachable from the internet. RFC 5737 / 3849 documentation ranges
    count as public on purpose: lab and vendor-doc examples use them for internet addresses."""
    try:
        ip = ipaddress.ip_interface(str(addr).strip()).ip
    except ValueError:
        return False
    return not any(ip in n for n in NOT_PUBLIC if n.version == ip.version)


def mask_to_prefix(mask):
    try:
        return ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def is_segmented(*names):
    return any(n and SEGMENTED.search(str(n)) for n in names)


def looks_internet(name):
    return bool(name and INTERNET_NAMES.search(str(name)))


# Result statuses. Only "fail" is scored; the others go into the report as coverage.
#   pass         the check ran and found nothing wrong
#   fail         a finding (scored with BOD 26-04 Table 1)
#   n/a          the check does not apply to this device (no routing, no vty lines, no SNMP)
#   not-visible  the config section the check needs is missing or could not be read
STATUSES = ("pass", "fail", "n/a", "not-visible")

# Secret values that may sit on a config line. The value after the keyword (and after a type
# digit or ENC) is replaced, so evidence can quote the line without the secret.
# The value must not itself be a keyword: in "md5 key-string 7 X" the match skips "md5" and masks
# the value after "key-string 7". HSRP/VRRP/GLBP clear-text keys ("standby 1 authentication X",
# "authentication text X") are covered by the last two keywords.
_SECRET = re.compile(r"(?<![\w-])(community|secret|password|passwd|psksecret|key-string|authentication-key|"
                     r"encrypted-password|md5|sha|aes|key|auth-password|priv-password|authentication\s+text|"
                     r"(?:standby|vrrp|glbp)\s+\d+\s+authentication)"
                     r"(\s+(?:\d{1,3}|ENC|encrypted)\b)?\s+"
                     r"(?!<hidden>|chain\b|generate\b|key-string\b|key-chain\b|key\b|md5\b|text\b)\S+", re.I)


def mask(line):
    """A config line with any secret value replaced by <hidden>."""
    return _SECRET.sub(lambda m: f"{m.group(1)}{m.group(2) or ''} <hidden>", str(line))


def result(check, status, detail, evidence=None, exposed=False, where=None, **extra):
    """One check outcome on one device. Evidence lines are masked here, so a module can pass
    config lines as they are."""
    if status not in STATUSES:
        raise ValueError(f"unknown status {status}")
    return {"check": check, "status": status, "detail": detail,
            "evidence": [mask(e) for e in list(evidence or [])[:6]],
            "exposed": bool(exposed) and status == "fail", "where": where, **extra}


def finding(check, detail, evidence=None, exposed=False, where=None, **extra):
    """A failed check (kept for the modules that only report failures)."""
    return result(check, "fail", detail, evidence, exposed, where, **extra)


def fill_passes(results, checks, detail="no failing config found"):
    """Add a pass for every check in `checks` that produced no result. For modules that only
    look for failures: the pass means "searched and found nothing", not a positive check."""
    seen = {r["check"] for r in results}
    return results + [result(c, "pass", detail) for c in checks if c not in seen]


def fails(results):
    return [r for r in results if r["status"] == "fail"]


def new_facts():
    return {"interfaces": [], "internet_interfaces": [], "features": {}, "notes": [],
            "hostname": None}


def feature(facts, name, on, internet=False, where=None):
    facts["features"][name] = {"on": bool(on), "internet": bool(on and internet), "where": where}
