# ============================================================
# Script:       net.py
# Purpose:      Address and name rules behind every device fact: public vs private
#               addresses, netmask to prefix, and the names (naming.yaml) that mark an
#               interface or zone as internet-facing or as a segment kept apart.
# Author:       G Talks Tech
# ============================================================
import ipaddress
import re
from pathlib import Path

import yaml

_NAMES = yaml.safe_load((Path(__file__).resolve().parent / "naming.yaml").read_text(encoding="utf-8"))
SEGMENTED = re.compile(_NAMES["segmented"], re.I)
INTERNET_NAMES = re.compile(_NAMES["internet_names"], re.I)

NOT_PUBLIC = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
    "fc00::/7", "fe80::/10", "::1/128")]
# IPv6 global unicast: IANA allocates it from 2000::/3 only. Multicast, unspecified, loopback,
# IPv4-mapped, link-local and ULA all fall outside it.
GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")


def is_public(addr):
    """True for an address reachable from the internet. RFC 5737 / 3849 documentation ranges
    count as public on purpose: lab and vendor-doc examples use them for internet addresses.
    IPv6: only global unicast (2000::/3) counts."""
    try:
        ip = ipaddress.ip_interface(str(addr).strip()).ip
    except ValueError:
        return False
    if ip.version == 6 and ip not in GLOBAL_UNICAST_V6:
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
