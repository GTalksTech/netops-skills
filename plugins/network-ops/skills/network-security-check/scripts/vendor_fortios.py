# ============================================================
# Script:       vendor_fortios.py
# Purpose:      FortiGate (FortiOS): facts and config checks from the saved "show" output.
# Author:       G Talks Tech
# Notes:        Read-only. Single-VDOM configs. Multi-VDOM ("config vdom / edit root")
#               is flattened: policies of every VDOM are checked together.
# ============================================================
import re

from common import (RISKY_PORTS, feature, finding, is_public, is_segmented, looks_internet,
                    mask_to_prefix, new_facts)
from parsers import fortios_tree

MGMT = {"http", "https", "ssh", "telnet", "snmp"}
ANY_ADDR = {"all", "any", "all6", "any6"}


def _section(tree, name):
    """A config section, wherever it sits (top level or inside 'config vdom / edit X')."""
    out = dict(tree.get(name, {}))
    for vd in tree.get("vdom", {}).values():
        out.update(vd.get(name, {}))
    return out


def _ports(spec):
    """'3389' or '3389-3390' or '' -> set of ints (empty = unknown)."""
    out = set()
    for part in spec:
        m = re.match(r"(\d+)(?:-(\d+))?", part)
        if m:
            a, b = int(m.group(1)), int(m.group(2) or m.group(1))
            out |= set(range(a, min(b, a + 2000) + 1))
    return out


def analyze(text, dev):
    tree = fortios_tree(text)
    facts = new_facts()
    found = []
    facts["hostname"] = (_section(tree, "system global").get("hostname") or [None])[0]

    ifaces = _section(tree, "system interface")
    zones = _section(tree, "system zone")
    internet_if = set()
    for name, cfg in ifaces.items():
        ip = cfg.get("ip", [])
        addr = f"{ip[0]}/{mask_to_prefix(ip[1])}" if len(ip) >= 2 else None
        public = bool(addr and is_public(addr))
        wan = cfg.get("role") == ["wan"] or public or looks_internet(name) or looks_internet(
            (cfg.get("alias") or [""])[0])
        facts["interfaces"].append({"name": name, "ips": [addr] if addr else [], "public": public,
                                    "role": (cfg.get("role") or [None])[0],
                                    "alias": (cfg.get("alias") or [None])[0],
                                    "allowaccess": cfg.get("allowaccess", [])})
        if wan and cfg.get("status") != ["down"]:
            internet_if.add(name)
    for zname, z in zones.items():
        members = set(z.get("interface", []))
        if members & internet_if or looks_internet(zname):
            internet_if.add(zname)
    facts["internet_interfaces"] = sorted(internet_if)

    def is_inet(intfs):
        return any(i in internet_if for i in intfs)

    def segmented(intfs):
        for i in intfs:
            alias = (ifaces.get(i, {}).get("alias") or [""])[0]
            if is_segmented(i, alias):
                return True
        return False

    # --- management on internet-facing interfaces ---
    admin_web_inet = False
    for itf in facts["interfaces"]:
        bad = MGMT & set(itf["allowaccess"])
        if itf["name"] in internet_if and bad:
            admin_web_inet |= bool({"http", "https"} & bad)
            found.append(finding("FGT-MGMT-ON-WAN",
                                 f"{itf['name']} ({itf['ips'][0] if itf['ips'] else 'no IP'}) allows "
                                 + " ".join(sorted(bad)),
                                 [f"set allowaccess {' '.join(itf['allowaccess'])}"], exposed=True,
                                 where=itf["name"]))
    feature(facts, "fgfm", any("fgfm" in i["allowaccess"] for i in facts["interfaces"]),
            any("fgfm" in i["allowaccess"] for i in facts["interfaces"] if i["name"] in internet_if))
    any_admin_web = any({"http", "https"} & set(i["allowaccess"]) for i in facts["interfaces"])
    feature(facts, "admin_web", any_admin_web, admin_web_inet)

    ssl = _section(tree, "vpn ssl settings")
    ssl_on = bool(ssl.get("source-interface")) and ssl.get("status") != ["disable"]
    feature(facts, "sslvpn", ssl_on, ssl_on and is_inet(ssl.get("source-interface", [])),
            ",".join(ssl.get("source-interface", [])))

    # --- admins ---
    wan_admin = any({"https", "http", "ssh", "telnet"} & set(i["allowaccess"])
                    for i in facts["interfaces"] if i["name"] in internet_if)
    for name, cfg in _section(tree, "system admin").items():
        if not any(k.startswith("trusthost") or k.startswith("ip6-trusthost") for k in cfg):
            found.append(finding("FGT-ADMIN-NO-TRUSTHOST", f"admin '{name}' has no trusted hosts",
                                 [f'edit "{name}"'], exposed=wan_admin, where=name))

    # --- policies ---
    vips = _section(tree, "firewall vip")
    for pid, p in _section(tree, "firewall policy").items():
        if p.get("action") != ["accept"] or p.get("status") == ["disable"]:
            continue
        src, dst = p.get("srcintf", []), p.get("dstintf", [])
        sa, da, svc = set(p.get("srcaddr", [])), set(p.get("dstaddr", [])), set(p.get("service", []))
        label = f"policy {pid}" + (f" '{p['name'][0]}'" if p.get("name") else "")
        ev = [f"srcintf {' '.join(src)} -> dstintf {' '.join(dst)}", f"srcaddr {' '.join(sa)}",
              f"dstaddr {' '.join(da)}", f"service {' '.join(svc)}"]
        inbound = is_inet(src) and not is_inet(dst)
        any_svc = "ALL" in svc
        outbound = is_inet(dst) and not is_inet(src) and "any" not in src
        seg = segmented(src) and not is_inet(dst) and not segmented(dst) and any_svc and bool(da & ANY_ADDR)
        if seg:
            found.append(finding("FGT-SEGMENT", f"{label}: {' '.join(src)} -> {' '.join(dst)}, "
                                 "all destinations, service ALL", ev, exposed=False, where=label))
        elif sa <= ANY_ADDR and da <= ANY_ADDR and any_svc and not outbound:
            # Outbound LAN -> internet all/all/ALL is the usual default and is not flagged here.
            found.append(finding("FGT-ANY-ANY", f"{label}: all -> all, service ALL", ev,
                                 exposed=inbound or "any" in src, where=label))
        elif inbound and any_svc:
            found.append(finding("FGT-INBOUND-ANY-SERVICE", f"{label}: from internet, service ALL", ev,
                                 exposed=True, where=label))
        if p.get("logtraffic") == ["disable"]:
            found.append(finding("FGT-NO-LOG", f"{label}: logtraffic disable", ev, exposed=inbound,
                                 where=label))
        if inbound and not p.get("ips-sensor"):
            found.append(finding("FGT-INBOUND-NO-IPS", f"{label}: inbound from internet, no IPS sensor",
                                 ev, exposed=True, where=label))
        if inbound:
            for vname in da & set(vips):
                v = vips[vname]
                ext = v.get("extintf", ["any"])
                if not (is_inet(ext) or ext == ["any"]):
                    continue
                mapped = " ".join(v.get("mappedip", []))
                if v.get("portforward") != ["enable"]:
                    found.append(finding("FGT-VIP-RISKY",
                                         f"VIP '{vname}' maps {v.get('extip', ['?'])[0]} to {mapped} on ALL "
                                         f"ports, used by {label}", ev, exposed=True, where=vname))
                    continue
                ports = _ports(v.get("extport", [])) | _ports(v.get("mappedport", []))
                risky = sorted({RISKY_PORTS[x] for x in ports if x in RISKY_PORTS})
                if risky:
                    found.append(finding("FGT-VIP-RISKY",
                                         f"VIP '{vname}' publishes {', '.join(risky)} ({mapped}) to the "
                                         f"internet, used by {label}", ev, exposed=True, where=vname))

    facts["internet_facing"] = bool(internet_if)
    facts["exposure_reason"] = ("internet-facing: " + ", ".join(sorted(internet_if))) if internet_if \
        else "no WAN-role or public interface found"
    return facts, found
