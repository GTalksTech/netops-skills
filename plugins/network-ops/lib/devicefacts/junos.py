# ============================================================
# Script:       junos.py
# Purpose:      Juniper Junos (EX, MX, SRX) device facts from "show configuration | display
#               set": interfaces and zones (which face the internet and the lines that show
#               it), the services each internet zone lets in, and J-Web.
# Author:       G Talks Tech
# Notes:        Read-only text parsing. apply-groups are expanded (see lines()).
# ============================================================
import re

from .facts import feature, internet_evidence, new_facts
from .net import is_public, looks_internet
from .parsers import junos_set

FEATURES = ("jweb",)


def lines(text):
    """The set lines, with 'set groups G ...' lines of every applied group added as if written
    at the top level."""
    out = junos_set(text)
    applied = {l.split()[2] for l in out if l.startswith("set apply-groups ")}
    return out + ["set " + l.split(" ", 3)[3] for l in out
                  if l.startswith("set groups ") and len(l.split()) > 3 and l.split()[2] in applied]


def read(text, dev=None):
    ls = lines(text)
    facts = new_facts()
    ips, zone_of, zone_svcs, proof = {}, {}, {}, {}
    for l in ls:
        m = re.match(r"set system host-name (\S+)", l)
        if m:
            facts["hostname"] = m.group(1)
        m = re.match(r"set interfaces (\S+) unit (\d+) family inet address (\S+)", l)
        if m:
            name = f"{m.group(1)}.{m.group(2)}"
            ips.setdefault(name, []).append(m.group(3))
            proof.setdefault(name, []).append(l)
        m = re.match(r"set security zones security-zone (\S+) interfaces (\S+)(.*)", l)
        if m:
            zone_of[m.group(2)] = m.group(1)
            proof.setdefault(m.group(2), []).append(l)
            s = re.search(r"host-inbound-traffic system-services (\S+)", m.group(3))
            if s:
                zone_svcs.setdefault(m.group(1), set()).add(s.group(1))
        m = re.match(r"set security zones security-zone (\S+) host-inbound-traffic system-services (\S+)", l)
        if m:
            zone_svcs.setdefault(m.group(1), set()).add(m.group(2))
    inet = set()
    for itf, addrs in ips.items():
        public = any(is_public(a) for a in addrs)
        i = {"name": itf, "ips": addrs, "public": public, "zone": zone_of.get(itf)}
        facts["interfaces"].append(i)
        if public or looks_internet(zone_of.get(itf)):
            inet.add(itf)
            internet_evidence(i, proof.get(itf, []), "public IP" if public else f"zone {zone_of.get(itf)}")
    inet_zones = {zone_of[i] for i in inet if i in zone_of} | {z for z in zone_svcs if looks_internet(z)}
    facts["internet_interfaces"] = sorted(inet)
    facts["has_zones"] = bool(zone_of)
    facts["internet_services"] = sorted(set().union(*[zone_svcs.get(z, set()) for z in inet_zones])
                                        if inet_zones else set())

    jweb = [l for l in ls if l.startswith("set system services web-management")]
    feature(facts, "jweb", bool(jweb), bool(jweb) and (exposed(facts, "http") or exposed(facts, "https")), None,
            jweb, "web-management configured" if jweb else "no 'system services web-management' line")

    facts["internet_facing"] = bool(inet)
    facts["exposure_reason"] = ("internet-facing: " + ", ".join(sorted(inet))) if inet else \
        "no public or untrust interface found"
    return facts


def exposed(facts, svc):
    """Whether a system service is reachable from the internet side. On an SRX, the
    host-inbound-traffic of the internet zones decides; on EX/MX there are no zones, so it falls
    back to 'the device has a public interface'."""
    if facts["has_zones"]:
        return bool({svc, "all"} & set(facts["internet_services"]))
    return bool(facts["internet_interfaces"])
