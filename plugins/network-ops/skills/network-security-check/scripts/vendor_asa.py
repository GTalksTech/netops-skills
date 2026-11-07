# ============================================================
# Script:       vendor_asa.py
# Purpose:      Cisco ASA: facts and config checks from "show running-config".
# Author:       G Talks Tech
# Notes:        Read-only. Single context. Object NAT and basic twice NAT.
# ============================================================
import re

from common import (RISKY_PORTS, feature, finding, is_public, looks_internet, mask_to_prefix,
                    new_facts)
from parsers import ios_blocks

WEAK = {"public", "private", "cisco"}
NAMED_PORTS = {"ssh": 22, "telnet": 23, "smb": 445, "rdp": 3389, "sqlnet": 1521, "netbios-ssn": 139}


def _port(tok):
    if tok.isdigit():
        return int(tok)
    return NAMED_PORTS.get(tok)


def analyze(text, dev):
    blocks = ios_blocks(text)
    top = [h for h, _ in blocks]
    facts = new_facts()
    found = []
    for h in top:
        if h.startswith("hostname "):
            facts["hostname"] = h.split()[1]

    nameif = {}
    for h, ch in blocks:
        if not h.startswith("interface "):
            continue
        itf = {"name": h.split()[1], "nameif": None, "level": None, "ips": []}
        for c in ch:
            if c.startswith("nameif "):
                itf["nameif"] = c.split()[1]
            elif c.startswith("security-level "):
                itf["level"] = int(c.split()[1])
            m = re.match(r"ip address (\S+) (\S+)", c)
            if m and "dhcp" not in c:
                itf["ips"].append(f"{m.group(1)}/{mask_to_prefix(m.group(2))}")
            elif c.startswith("ip address dhcp"):
                itf["ips"].append("dhcp")
        itf["public"] = any(is_public(i) for i in itf["ips"] if i != "dhcp")
        if itf["nameif"]:
            nameif[itf["nameif"]] = itf
        facts["interfaces"].append(itf)
    inet = {n for n, i in nameif.items() if i["public"] or looks_internet(n)}
    facts["internet_interfaces"] = sorted(inet)

    # --- management on outside ---
    mgmt = [h for h in top if re.match(r"(http|ssh|telnet) \S+ \S+ \S+$", h)
            and not h.startswith(("http server", "ssh version", "ssh timeout", "ssh key-exchange",
                                  "ssh cipher", "telnet timeout", "ssh stricthostkeycheck"))]
    http_on = "http server enable" in top or any(h.startswith("http server enable") for h in top)
    out_mgmt = [h for h in mgmt if h.split()[-1] in inet and (not h.startswith("http") or http_on)]
    if out_mgmt:
        found.append(finding("ASA-MGMT-ON-OUTSIDE", "; ".join(out_mgmt), out_mgmt, exposed=True))
    feature(facts, "mgmt_http", http_on, http_on and any(h.startswith("http ") for h in out_mgmt))
    if any(h.startswith("telnet ") for h in mgmt):
        found.append(finding("ASA-TELNET", "telnet management lines present",
                             [h for h in mgmt if h.startswith("telnet ")],
                             exposed=any(h.startswith("telnet") for h in out_mgmt)))

    webvpn = next((ch for h, ch in blocks if h == "webvpn"), [])
    vpn_if = [c.split()[1] for c in webvpn if c.startswith("enable ")]
    feature(facts, "webvpn", bool(vpn_if), any(i in inet for i in vpn_if), ",".join(vpn_if))

    # --- ACLs applied to interfaces ---
    applied = {}
    for h in top:
        m = re.match(r"access-group (\S+) (in|out) interface (\S+)", h)
        if m:
            applied.setdefault(m.group(1), []).append(m.group(3))
        elif re.match(r"access-group (\S+) global", h):
            applied.setdefault(h.split()[1], []).append("global")
    for h in top:
        m = re.match(r"access-list (\S+) extended permit ip any4? any4?(\s|$)", h)
        if m and m.group(1) in applied and any(i in inet or i == "global" for i in applied[m.group(1)]):
            # inside "permit ip any any" is the usual outbound default and is not flagged here
            ifs = applied[m.group(1)]
            found.append(finding("ASA-ANY-ANY", f"{m.group(1)} on {', '.join(ifs)}: {h.split(' ', 2)[2]}",
                                 [h], exposed=any(i in inet or i == "global" for i in ifs),
                                 where=m.group(1)))

    # --- object NAT: object network X / host or subnet / nat (in,out) static ip [service ...] ---
    for h, ch in blocks:
        if not h.startswith("object network "):
            continue
        host = next((c.split()[1] for c in ch if c.startswith(("host ", "subnet ", "range "))), "?")
        for c in ch:
            m = re.match(r"nat \((\S+),(\S+)\) static (\S+)(.*)", c)
            if not m or m.group(2) not in inet:
                continue
            svc = m.group(4).split()
            if "service" not in svc:
                found.append(finding("ASA-NAT-RISKY", f"{h.split()[2]} ({host}) is static-NATed to "
                                     f"{m.group(3)} on all ports", [h, c], exposed=True, where=h.split()[2]))
                continue
            i = svc.index("service")
            ports = {_port(t) for t in svc[i + 2:i + 4]}
            risky = sorted({RISKY_PORTS[p] for p in ports if p in RISKY_PORTS})
            if risky:
                found.append(finding("ASA-NAT-RISKY", f"{h.split()[2]} ({host}) publishes "
                                     f"{', '.join(risky)} on {m.group(3)}", [h, c], exposed=True,
                                     where=h.split()[2]))

    snmp = [h for h in top if re.match(r"snmp-server (host .* community|community) ", h)]
    weak = [h for h in snmp if any(re.search(rf"community {w}(\s|$)", h) for w in WEAK)]
    if weak:
        found.append(finding("ASA-SNMP-COMMUNITY", f"{len(weak)} line(s) with a default community",
                             [re.sub(r"community \S+", "community <hidden>", w) for w in weak],
                             exposed=any(w.split()[2] in inet for w in weak if w.startswith("snmp-server host"))))
    if not any(h.startswith("logging host ") for h in top):
        found.append(finding("ASA-NO-REMOTE-LOG", "No 'logging host' line", [], exposed=False))

    facts["internet_facing"] = bool(inet)
    facts["exposure_reason"] = ("internet-facing: " + ", ".join(sorted(inet))) if inet else \
        "no outside/public interface found"
    return facts, found
