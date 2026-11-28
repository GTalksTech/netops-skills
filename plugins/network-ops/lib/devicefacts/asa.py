# ============================================================
# Script:       asa.py
# Purpose:      Cisco ASA device facts from "show running-config": interfaces (by nameif,
#               which face the internet and the lines that show it) and the features CVE
#               conditions name (ASDM / http server, AnyConnect / WebVPN).
# Author:       G Talks Tech
# Notes:        Read-only text parsing. Single context.
# ============================================================
import re

from .facts import feature, internet_evidence, new_facts
from .net import is_public, looks_internet, mask_to_prefix
from .parsers import ios_blocks

FEATURES = ("mgmt_http", "webvpn")


def mgmt_lines(top, inet):
    """(management access lines 'http|ssh|telnet <source> [<mask>] <nameif>', the ones on an
    internet-facing nameif, http server enabled)."""
    mgmt = [h for h in top if re.match(r"(http|ssh|telnet) \S+( \S+)? \S+$", h)
            and not h.startswith(("http server", "ssh version", "ssh timeout", "ssh key-exchange",
                                  "ssh cipher", "telnet timeout", "ssh stricthostkeycheck"))]
    http_on = "http server enable" in top or any(h.startswith("http server enable") for h in top)
    out_mgmt = [h for h in mgmt if h.split()[-1] in inet and (not h.startswith("http") or http_on)]
    return mgmt, out_mgmt, http_on


def read(text, dev=None):
    blocks = ios_blocks(text)
    top = [h for h, _ in blocks]
    facts = new_facts()
    for h in top:
        if h.startswith("hostname "):
            facts["hostname"] = h.split()[1]

    nameif = {}
    for h, ch in blocks:
        if not h.startswith("interface "):
            continue
        itf = {"name": h.split()[1], "nameif": None, "level": None, "ips": []}
        proof = [h]
        for c in ch:
            if c.startswith("nameif "):
                itf["nameif"] = c.split()[1]
                proof.append(c)
            elif c.startswith("security-level "):
                itf["level"] = int(c.split()[1])
            m = re.match(r"ip address (\S+) (\S+)", c)
            if m and "dhcp" not in c:
                itf["ips"].append(f"{m.group(1)}/{mask_to_prefix(m.group(2))}")
                proof.append(c)
            elif c.startswith("ip address dhcp"):
                itf["ips"].append("dhcp")
                proof.append(c)
        itf["public"] = any(is_public(i) for i in itf["ips"] if i != "dhcp")
        itf["mgmt_only"] = "management-only" in ch
        itf["_proof"] = proof
        if itf["nameif"]:
            nameif[itf["nameif"]] = itf
        facts["interfaces"].append(itf)
    inet = {n for n, i in nameif.items() if (i["public"] or looks_internet(n)) and not i["mgmt_only"]
            and n != "management"}
    for itf in facts["interfaces"]:
        proof = itf.pop("_proof")
        if itf["nameif"] in inet:
            internet_evidence(itf, proof, "public IP" if itf["public"] else "name")
    facts["internet_interfaces"] = sorted(inet)

    _, out_mgmt, http_on = mgmt_lines(top, inet)
    http_out = [h for h in out_mgmt if h.startswith("http ")]
    feature(facts, "mgmt_http", http_on, http_on and bool(http_out), None,
            [h for h in top if h.startswith("http server enable")] + http_out,
            ("http server enable" + (", reachable from an internet-facing interface" if http_out else ""))
            if http_on else "no 'http server enable' line")

    webvpn = next((ch for h, ch in blocks if h == "webvpn"), [])
    vpn_if = [c.split()[1] for c in webvpn if c.startswith("enable ")]
    feature(facts, "webvpn", bool(vpn_if), any(i in inet for i in vpn_if), ",".join(vpn_if),
            ["webvpn"] + [c for c in webvpn if c.startswith("enable ")] if vpn_if else [],
            "webvpn enabled on " + ", ".join(vpn_if) if vpn_if else "no 'enable <nameif>' under webvpn")

    facts["internet_facing"] = bool(inet)
    facts["exposure_reason"] = ("internet-facing: " + ", ".join(sorted(inet))) if inet else \
        "no outside/public interface found"
    return facts
