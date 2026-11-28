# ============================================================
# Script:       panos.py
# Purpose:      Palo Alto PAN-OS device facts from "show config running" (default brace
#               format) on a single firewall: layer 3 interfaces and zones (which face the
#               internet and the lines that show it) and the features CVE conditions name
#               (the management web interface, GlobalProtect).
# Author:       G Talks Tech
# Notes:        Read-only text parsing. Reads every vsys.
# ============================================================
from .facts import feature, internet_evidence, new_facts
from .net import is_public, looks_internet
from .parsers import as_list, get, panos_tree

FEATURES = ("mgmt_web", "globalprotect")
WEB = ("https", "http")


def device(tree):
    devs = get(tree, "config", "devices") or {}
    return next(iter(devs.values()), {}) if devs else {}


def _walk_interfaces(node, out):
    """(name, cfg) for every layer3 interface and subinterface under network > interface."""
    for kind in ("ethernet", "aggregate-ethernet", "vlan", "loopback", "tunnel"):
        for name, cfg in (node.get(kind) or {}).items():
            l3 = cfg.get("layer3", cfg) if isinstance(cfg, dict) else {}
            out.append((name, l3))
            for sub, scfg in (get(l3, "units") or {}).items():
                out.append((sub, scfg))
    return out


def _ips(cfg):
    ip = cfg.get("ip")
    if isinstance(ip, dict):
        return [k for k in ip if k != "_items"] + ip.get("_items", [])
    return as_list(ip)


def read(text, dev=None):
    tree = panos_tree(text)
    facts = new_facts()
    d = device(tree)
    facts["hostname"] = get(d, "deviceconfig", "system", "hostname")
    net = d.get("network", {})
    profiles = get(net, "profiles", "interface-management-profile") or {}

    itfs = {}
    for name, cfg in _walk_interfaces(net.get("interface", {}), []):
        ips = _ips(cfg)
        itfs[name] = {"name": name, "ips": ips, "public": any(is_public(i) for i in ips),
                      "mgmt_profile": cfg.get("interface-management-profile")}

    vsyses = d.get("vsys") or {}
    zone_of, zones_inet = {}, set()
    for vs in vsyses.values():
        for zname, z in (vs.get("zone") or {}).items():
            members = as_list(get(z, "network", "layer3"))
            for m in members:
                zone_of[m] = zname
            if looks_internet(zname) or any(itfs.get(m, {}).get("public") for m in members):
                zones_inet.add(zname)
    facts["zones_inet"] = sorted(zones_inet)

    for i in itfs.values():
        i["zone"] = zone_of.get(i["name"])
        i["internet"] = i["public"] or (i["zone"] in zones_inet)
        facts["interfaces"].append(i)
        if i["internet"]:
            internet_evidence(i, [f"{i['name']} ip [ {' '.join(i['ips'])} ]"] + (
                [f"zone {i['zone']} layer3 [ {i['name']} ]"] if i["zone"] else []),
                "public IP" if i["public"] else f"in zone {i['zone']}")
    facts["internet_interfaces"] = sorted(i["name"] for i in itfs.values() if i["internet"])

    web_inet = [f"{i['name']}: interface-management-profile {i['mgmt_profile']} ("
                + ", ".join(s for s in WEB if profiles.get(i["mgmt_profile"] or "", {}).get(s) == "yes") + ")"
                for i in itfs.values() if i["internet"]
                and any(profiles.get(i["mgmt_profile"] or "", {}).get(s) == "yes" for s in WEB)]
    # The management port always serves the web interface: on, and internet-facing only when an
    # interface management profile opens it on an internet-facing interface.
    feature(facts, "mgmt_web", True, bool(web_inet), "management port or profile", web_inet,
            "the management port always runs the web interface" + (
                "; a management profile opens it on an internet-facing interface" if web_inet else ""))

    gp = []
    for vsname, vs in vsyses.items():
        gpc = vs.get("global-protect") or {}
        gp += [f"vsys {vsname}: global-protect {k}" for k in ("global-protect-portal", "global-protect-gateway")
               if gpc.get(k)]
    feature(facts, "globalprotect", bool(gp), bool(gp) and bool(zones_inet), None, gp,
            "GlobalProtect portal or gateway configured" if gp else "no GlobalProtect portal or gateway")

    facts["internet_facing"] = bool(facts["internet_interfaces"])
    facts["exposure_reason"] = ("internet-facing: " + ", ".join(facts["internet_interfaces"])) \
        if facts["internet_interfaces"] else "no untrust/public interface found"
    return facts
