# ============================================================
# Script:       vendor_panos.py
# Purpose:      Palo Alto PAN-OS: facts and config checks from "show config running"
#               (default brace format) on a single firewall. Reads rulebase plus
#               pre-rulebase / post-rulebase, where Panorama rules sit when present.
# Author:       G Talks Tech
# Notes:        Read-only. Checks every vsys.
# ============================================================
import re

from common import (RISKY_PORTS, feature, fill_passes, finding, is_public, is_segmented, looks_internet,
                    new_facts)
from parsers import as_list, get, panos_tree

MGMT = ("https", "http", "ssh", "telnet", "snmp")
CHECKS = ("PAN-ANY-ANY", "PAN-INBOUND-ANY-SERVICE", "PAN-MGMT-ON-UNTRUST", "PAN-NO-LOG",
          "PAN-INBOUND-NO-PROFILE", "PAN-NAT-RISKY", "PAN-SEGMENT")


def _device(tree):
    devs = get(tree, "config", "devices") or {}
    return next(iter(devs.values()), {}) if devs else {}


def _walk_interfaces(node, out, prefix=None):
    """Yield (name, cfg) for every layer3 interface and subinterface under network > interface."""
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


def _ports(svc_names, services):
    """Resolve service names to ports. None = any port."""
    ports = set()
    for s in svc_names:
        if s in ("any",):
            return None
        if s == "application-default":
            continue
        for proto in ("tcp", "udp"):
            spec = get(services, s, "protocol", proto, "port")
            for part in str(spec or "").split(","):
                m = re.match(r"(\d+)(?:-(\d+))?$", part.strip())
                if m:
                    a, b = int(m.group(1)), int(m.group(2) or m.group(1))
                    ports |= set(range(a, min(b, a + 2000) + 1))
        m = re.search(r"(\d{2,5})$", s)  # service-rdp-3389 style names with no object
        if not get(services, s) and m:
            ports.add(int(m.group(1)))
    return ports


def analyze(text, dev):
    tree = panos_tree(text)
    facts = new_facts()
    found = []
    d = _device(tree)
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

    for i in itfs.values():
        i["zone"] = zone_of.get(i["name"])
        i["internet"] = i["public"] or (i["zone"] in zones_inet)
        facts["interfaces"].append(i)
    facts["internet_interfaces"] = sorted(i["name"] for i in itfs.values() if i["internet"])

    mgmt_inet = False
    for i in itfs.values():
        prof = profiles.get(i["mgmt_profile"] or "", {})
        on = [s for s in MGMT if prof.get(s) == "yes"]
        if i["internet"] and on:
            mgmt_inet |= bool({"https", "http"} & set(on))
            found.append(finding("PAN-MGMT-ON-UNTRUST",
                                 f"{i['name']} (zone {i['zone']}) uses management profile "
                                 f"'{i['mgmt_profile']}' with {', '.join(on)}",
                                 [f"interface-management-profile {i['mgmt_profile']}"], exposed=True,
                                 where=i["name"]))
    feature(facts, "mgmt_web", True, mgmt_inet, "management port or profile")

    gp = False
    for vs in vsyses.values():
        gpc = vs.get("global-protect") or {}
        if gpc.get("global-protect-portal") or gpc.get("global-protect-gateway"):
            gp = True
    feature(facts, "globalprotect", gp, gp and bool(zones_inet))

    def is_inet_zone(zs):
        return any(z in zones_inet for z in zs)

    for vsname, vs in vsyses.items():
        services = vs.get("service") or {}
        rules = {}
        for base in ("pre-rulebase", "rulebase", "post-rulebase"):
            rules.update(get(vs, base, "security", "rules") or {})
        open_inbound_zones = set()
        for rname, r in rules.items():
            if r.get("action") != "allow" or r.get("disabled") == "yes":
                continue
            if r.get("negate-source") == "yes" or r.get("negate-destination") == "yes":
                continue    # negated rules need address math this parser doesn't do
            frm, to = as_list(r.get("from")), as_list(r.get("to"))
            src, dst = as_list(r.get("source")), as_list(r.get("destination"))
            app, svc = as_list(r.get("application")), as_list(r.get("service"))
            label = f"rule '{rname}'"
            ev = [f"from {' '.join(frm)} to {' '.join(to)}", f"source {' '.join(src)}",
                  f"destination {' '.join(dst)}", f"application {' '.join(app)}",
                  f"service {' '.join(svc)}"]
            inbound = (is_inet_zone(frm) or frm == ["any"]) and not is_inet_zone(to)
            any_app = app == ["any"]
            any_svc = svc == ["any"]
            seg_src = any(is_segmented(z) for z in frm)
            reaches_internal = to == ["any"] or any(not is_inet_zone([z]) and not is_segmented(z) for z in to)
            outbound = is_inet_zone(to) and not is_inet_zone(frm) and frm != ["any"]
            if is_inet_zone(frm) and any_app and any_svc:
                open_inbound_zones |= set(to)
            if seg_src and reaches_internal and any_app and dst == ["any"]:
                found.append(finding("PAN-SEGMENT", f"{label}: {', '.join(frm)} -> {', '.join(to)}, "
                                     "any destination, any application", ev, exposed=False, where=label))
            elif src == ["any"] and dst == ["any"] and any_app and not outbound:
                found.append(finding("PAN-ANY-ANY", f"{label}: {', '.join(frm)} -> {', '.join(to)}, any "
                                     "source and destination, application any", ev, exposed=inbound, where=label))
            elif is_inet_zone(frm) and not is_inet_zone(to) and any_app and any_svc:
                found.append(finding("PAN-INBOUND-ANY-SERVICE",
                                     f"{label}: from {', '.join(frm)}, any application, any service", ev,
                                     exposed=True, where=label))
            if r.get("log-end") == "no":
                found.append(finding("PAN-NO-LOG", f"{label}: log at session end is off", ev,
                                     exposed=is_inet_zone(frm), where=label))
            if is_inet_zone(frm) and not is_inet_zone(to) and not r.get("profile-setting"):
                found.append(finding("PAN-INBOUND-NO-PROFILE", f"{label}: from {', '.join(frm)}, no "
                                     "security profiles", ev, exposed=True, where=label))

        nat_rules = {}
        for base in ("pre-rulebase", "rulebase", "post-rulebase"):
            nat_rules.update(get(vs, base, "nat", "rules") or {})
        for rname, r in nat_rules.items():
            if r.get("disabled") == "yes":
                continue
            frm = as_list(r.get("from"))
            dt = r.get("destination-translation")
            if not (is_inet_zone(frm) and isinstance(dt, dict)):
                continue
            svc = as_list(r.get("service") or "any")
            ports = _ports(svc, services)
            tport = dt.get("translated-port")
            if tport and str(tport).isdigit():
                ports = (ports or set()) | {int(tport)}
            target = dt.get("translated-address", "?")
            ev = [f"from {' '.join(frm)}", f"service {' '.join(svc)}", f"translated-address {target}"]
            if ports is None and not open_inbound_zones:
                continue    # all-ports NAT, but no security rule lets everything through
            if ports is None:
                found.append(finding("PAN-NAT-RISKY", f"NAT rule '{rname}' maps to {target} on all "
                                     "ports (service any)", ev, exposed=True, where=rname))
            else:
                risky = sorted({RISKY_PORTS[p] for p in ports if p in RISKY_PORTS})
                if risky:
                    found.append(finding("PAN-NAT-RISKY", f"NAT rule '{rname}' publishes "
                                         f"{', '.join(risky)} on {target} to the internet", ev,
                                         exposed=True, where=rname))

    facts["internet_facing"] = bool(facts["internet_interfaces"])
    facts["exposure_reason"] = ("internet-facing: " + ", ".join(facts["internet_interfaces"])) \
        if facts["internet_interfaces"] else "no untrust/public interface found"
    # Fail-only checks: a pass here means the search found nothing, not a positive check.
    facts["results"] = fill_passes(found, CHECKS)
    return facts, found
