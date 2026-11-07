# ============================================================
# Script:       vendor_junos.py
# Purpose:      Juniper Junos (EX, MX, SRX): facts and a few management-plane checks from
#               "show configuration | display set".
# Author:       G Talks Tech
# Notes:        Read-only. SRX security policies are not checked yet.
# ============================================================
import re

from common import feature, finding, is_public, looks_internet, new_facts
from parsers import junos_set

WEAK = {"public", "private"}


def analyze(text, dev):
    lines = junos_set(text)
    facts = new_facts()
    found = []
    ips, zone_of, zone_svcs = {}, {}, {}
    for l in lines:
        m = re.match(r"set system host-name (\S+)", l)
        if m:
            facts["hostname"] = m.group(1)
        m = re.match(r"set interfaces (\S+) unit (\d+) family inet address (\S+)", l)
        if m:
            ips.setdefault(f"{m.group(1)}.{m.group(2)}", []).append(m.group(3))
        m = re.match(r"set security zones security-zone (\S+) interfaces (\S+)(.*)", l)
        if m:
            zone_of[m.group(2)] = m.group(1)
            s = re.search(r"host-inbound-traffic system-services (\S+)", m.group(3))
            if s:
                zone_svcs.setdefault(m.group(1), set()).add(s.group(1))
        m = re.match(r"set security zones security-zone (\S+) host-inbound-traffic system-services (\S+)", l)
        if m:
            zone_svcs.setdefault(m.group(1), set()).add(m.group(2))
    inet = set()
    for itf, addrs in ips.items():
        public = any(is_public(a) for a in addrs)
        facts["interfaces"].append({"name": itf, "ips": addrs, "public": public, "zone": zone_of.get(itf)})
        if public or looks_internet(zone_of.get(itf)):
            inet.add(itf)
    inet_zones = {zone_of[i] for i in inet if i in zone_of} | {z for z in zone_svcs if looks_internet(z)}
    facts["internet_interfaces"] = sorted(inet)
    inet_svcs = set().union(*[zone_svcs.get(z, set()) for z in inet_zones]) if inet_zones else set()

    def exposed(svc):
        # On an SRX, host-inbound-traffic on the internet zone decides reachability.
        # On EX/MX there are no zones: fall back to "the device has a public interface".
        if zone_of:
            return bool({svc, "all"} & inet_svcs)
        return bool(inet)

    if "set system services telnet" in lines:
        found.append(finding("JUNOS-TELNET", "system services telnet", ["set system services telnet"],
                             exposed=exposed("telnet")))
    http = [l for l in lines if l.startswith("set system services web-management http")
            and not l.startswith("set system services web-management https")]
    jweb = [l for l in lines if l.startswith("set system services web-management")]
    feature(facts, "jweb", bool(jweb), bool(jweb) and (exposed("http") or exposed("https")))
    if http:
        found.append(finding("JUNOS-HTTP", "J-Web over plain HTTP", http[:2], exposed=exposed("http")))
    bad = []
    for l in lines:
        m = re.match(r"set snmp community (\S+)\s*(.*)", l)
        if m and (m.group(1).strip('"').lower() in WEAK or "authorization read-write" in m.group(2)):
            bad.append(re.sub(r"community \S+", "community <hidden>", l))
    if bad:
        found.append(finding("JUNOS-SNMP-COMMUNITY", "default or read-write SNMP community", bad[:3],
                             exposed=exposed("snmp")))

    facts["internet_facing"] = bool(inet)
    facts["exposure_reason"] = ("internet-facing: " + ", ".join(sorted(inet))) if inet else \
        "no public or untrust interface found"
    return facts, found
