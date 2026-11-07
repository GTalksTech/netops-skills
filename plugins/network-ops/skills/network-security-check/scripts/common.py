# ============================================================
# Script:       common.py
# Purpose:      Helpers shared by the vendor modules: public vs private addresses,
#               segment names, risky ports, and the finding record.
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


def finding(check, detail, evidence=None, exposed=False, where=None, **extra):
    return {"check": check, "detail": detail, "evidence": list(evidence or [])[:6],
            "exposed": bool(exposed), "where": where, **extra}


def new_facts():
    return {"interfaces": [], "internet_interfaces": [], "features": {}, "notes": [],
            "hostname": None}


def feature(facts, name, on, internet=False, where=None):
    facts["features"][name] = {"on": bool(on), "internet": bool(on and internet), "where": where}
