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


# Result statuses. Only "fail" is scored; the others go into the report as coverage.
#   pass         the check ran and found nothing wrong
#   fail         a finding (scored with BOD 26-04 Table 1)
#   n/a          the check does not apply to this device (no routing, no vty lines, no SNMP)
#   not-visible  the config section the check needs is missing or could not be read
STATUSES = ("pass", "fail", "n/a", "not-visible")

# Secret values that may sit on a config line. mask() walks the words of a line: after a secret
# keyword it skips an encryption type (0, 6, 7, ENC...), an algorithm or format word (md5,
# hmac-sha2-256, ascii, local...) and hides the next word. Words that name things rather than
# hold a secret (key-chain, key-string, address...) stop the walk, so key chain NAMES stay visible.
# Covered: IOS/IOS-XE enable/username secrets, line passwords, SNMP communities and v3 user keys,
# snmp-server host communities, NTP keys, TACACS+/RADIUS keys, IKE pre-shared keys, OSPF/EIGRP/BGP
# keys, HSRP/VRRP/GLBP keys, WPA PSKs; FortiOS 'set <secret-name> ENC ...'; Junos and ASA forms
# that use the same keywords.
_KEYWORDS = {"community", "secret", "password", "passwd", "psksecret", "key-string", "authentication-key",
             "encrypted-password", "md5", "key", "auth-password", "priv-password", "passphrase", "auth-pwd",
             "secondary-secret", "ldap-password", "private-key", "server-key", "pre-shared-key", "wpa-psk",
             "password-encrypt", "message-digest-key"}
_TYPE = re.compile(r"^(\d{1,3}|ENC|encrypted)$", re.I)
_ALG = re.compile(r"^(md5|sha|sha1|sha-1|sha2?-?(224|256|384|512)|sha256|sha384|sha512|hmac-\S+|cmac-\S+|aes|"
                  r"des|3des|ascii|hex|ascii-text|hexadecimal|local|remote|unencrypted)$", re.I)
_KEEP = {"chain", "key-chain", "key-string", "generate", "key", "md5", "text", "<hidden>", "config-key",
         "address", "hostname", "mode", "algorithm-type", "level"}
# FortiOS: 'set <name> [ENC] <value>' where the name holds a secret.
_FGT_SECRET = re.compile(r"^([\w-]*-)?(password|passwd|pwd|secret|passphrase|psksecret|private-key|key|"
                         r"ppk-secret|ldap-password)(-l\d|\d)?$", re.I)
_FHRP = {"standby", "vrrp", "glbp"}
# Words that never hold a secret when masking prose (a finding's detail): stops a sentence such as
# "VTP mode server with no password on a switch" losing the word "on".
_PROSE = {"a", "an", "and", "as", "at", "by", "for", "from", "in", "is", "it", "no", "not", "of", "on", "or",
          "the", "to", "with", "was", "are", "be", "only", "set", "line", "lines", "string", "strings", "types",
          "name", "names", "list", "lists"}


def _hide_after(w, i, out, prose):
    """Mark the secret word after the keyword at w[i]: skip a type and algorithm/format words."""
    j = i + 1
    skipped_type = None
    while j < len(w) and (_TYPE.match(w[j]) or _ALG.match(w[j])) and w[j].lower() not in _KEEP:
        if _TYPE.match(w[j]):
            skipped_type = j
        j += 1
    if j < len(w):
        tok = w[j]
        if tok.lower() in _KEEP or tok == "<hidden>":
            return
        core = tok.rstrip(":,;.)")
        if prose and (core.lower() in _PROSE or core.isdigit() or tok[:1] in "('\""
                      or (skipped_type is None and re.fullmatch(r"[a-z][a-z()/-]*", core))):
            return
        out.add(j)
    elif skipped_type is not None and w[i].lower() != "key" and not prose:
        out.add(skipped_type)       # "password 1234": a numeric secret, not a type


def mask(line, prose=False):
    """A config line with any secret value replaced by <hidden>. prose=True for free text (a
    finding's detail): common words and words ending in punctuation are never hidden."""
    text = str(line)
    parts = re.split(r"(\s+)", text)
    w = [p for p in parts[::2]]           # words at even positions, whitespace at odd ones
    low = [x.lower() for x in w]
    hide = set()
    first = next((k for k, x in enumerate(low) if x), None)
    if first is not None and low[first] == "set" and first + 1 < len(w) and _FGT_SECRET.match(w[first + 1]):
        hide |= {k for k in range(first + 2, len(w)) if w[k] and low[k] not in ("enc",)}
    for i, x in enumerate(low):
        if x in _KEYWORDS:
            _hide_after(w, i, hide, prose)
        elif x == "text" and i and low[i - 1] == "authentication" and i + 1 < len(w):
            hide.add(i + 1)
        elif x == "authentication" and i + 1 < len(w) and (
                (i >= 1 and low[i - 1] in _FHRP) or (i >= 2 and low[i - 2] in _FHRP and low[i - 1].isdigit())) \
                and low[i + 1] not in ("md5", "text") and w[i + 1]:
            hide.add(i + 1)
    # SNMPv3 user keys: snmp-server user U G [remote ..] v3 [encrypted] auth ALG KEY [priv ALG [BITS] KEY]
    if first is not None and low[first:first + 2] == ["snmp-server", "user"]:
        for i, x in enumerate(low):
            if x in ("auth", "priv"):
                _hide_after(w, i, hide, prose)
    # snmp-server host ADDR [vrf V] [informs|traps] [version 1|2c|3 [auth|noauth|priv]] COMMUNITY ...
    if first is not None and low[first:first + 2] == ["snmp-server", "host"] and len(w) > first + 3:
        i = first + 3
        while i < len(w):
            if low[i] == "vrf":
                i += 2
            elif low[i] == "version":
                i += 2
            elif low[i] in ("informs", "traps", "auth", "noauth", "priv"):
                i += 1
            else:
                if w[i] and w[i] != "<hidden>":
                    hide.add(i)
                break
    for k in hide:
        parts[2 * k] = "<hidden>"
    return "".join(parts)


def result(check, status, detail, evidence=None, exposed=False, where=None, **extra):
    """One check outcome on one device. Evidence lines are masked here, so a module can pass
    config lines as they are."""
    if status not in STATUSES:
        raise ValueError(f"unknown status {status}")
    return {"check": check, "status": status, "detail": mask(detail, prose=True) if detail else detail,
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
