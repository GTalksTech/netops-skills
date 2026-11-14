# ============================================================
# Script:       ios_cp.py
# Purpose:      Cisco IOS / IOS-XE control plane checks: control plane policing (CoPP),
#               ICMP and ARP behaviour on external interfaces, CDP/LLDP on external
#               interfaces, and legacy services that should be off.
# Author:       G Talks Tech
# Notes:        Read-only. Called by vendor_ios.analyze. Sources per check: settings/checks.yaml.
#               Defaults used here (research/sources.md, R4 rows): proxy ARP, ICMP redirects and
#               unreachables are ON unless an interface says "no ...". Directed broadcast, small
#               servers and finger are OFF unless the line is present. IP source routing is OFF
#               from IOS XE 17.1.1 and ON before it. LLDP is off unless "lldp run". CDP state is
#               read from the saved show cdp neighbors output when it is there. IPv6 (Cisco IPv6
#               command reference): redirects and unreachables ON, type 0 routing header
#               processing (ipv6 source-route) OFF since 12.4(15)T; with ipv6 unicast-routing the
#               router sends router advertisements unless "ipv6 nd ra suppress".
# ============================================================
import re
from pathlib import Path

from common import result
from ios_routing import _routing_auth

CHECKS = ("IOS-NO-COPP", "IOS-EDGE-IP-SERVICES", "IOS-EDGE-CDP-LLDP", "IOS-LEGACY-SERVICES")
V6_IGP = r"(ipv6 ospf \d+ area |ospfv3 \d+ (ipv6 )?area |ipv6 eigrp \d+)"

# DISA CISC-ND-000470: services that must not be in the configuration (present-line test).
# ip http server has its own check (IOS-HTTP-SERVER). service call-home is left out: the STIG
# exempts it where Smart Licensing needs it, and IOS XE 17 uses it for that.
LEGACY = [
    (r"service tcp-small-servers\b", True), (r"service udp-small-servers\b", True),
    (r"service finger\b", True), (r"ip finger\b", True), (r"ip identd\b", True),
    (r"ip bootp server\b", True), (r"ip dns server\b", True), (r"ip rcmd rcp-enable\b", True),
    (r"ip rcmd rsh-enable\b", True), (r"service pad\b", False), (r"service config\b", False),
    (r"boot network\b", False), (r"ip boot server\b", False),
]   # (pattern, listens on an IP port)


def external_interfaces(blocks, interfaces):
    """Interfaces that face an outside network: internet-facing (public IP or NAT outside, not in
    a management VRF, not shut), not a loopback or Null, and not running an OSPF or EIGRP
    adjacency. An interface that forms an IGP adjacency talks to one of your own routers (a
    public transit link to the firewall, for example), not to the ISP."""
    igp = set()
    for a in _routing_auth(blocks, interfaces):
        m = re.match(r"(OSPF|EIGRP) \S+ on (\S+)$", a["what"])
        if m:
            igp.add(m.group(2))
    # IPv6 IGPs are enabled on the interface itself (OSPFv3, EIGRP for IPv6)
    for h, ch in blocks:
        if h.startswith("interface ") and any(re.match(V6_IGP, c) for c in ch):
            igp.add(h.split()[1])
    return [i for i in interfaces if i.get("internet") and i["name"] not in igp
            and not re.match(r"(?i)(loopback|null)", i["name"])]


def _itf_cfg(blocks):
    return {h.split()[1]: ch for h, ch in blocks if h.startswith("interface ")}


def _show(dev, name):
    folder = (dev or {}).get("_folder")
    f = Path(folder) / name if folder else None
    return f.read_text(encoding="utf-8", errors="replace") if f and f.exists() else None


def _version(top):
    """(major, minor) from the config's 'version 17.16' line, else None."""
    for h in top:
        m = re.match(r"version (\d+)\.(\d+)", h)
        if m:
            return int(m.group(1)), int(m.group(2))
    return None


def _routes(blocks):
    return any(re.match(r"router (ospf|ospfv3|eigrp|bgp|isis|rip)\b", h) for h, _ in blocks)


def _unfiltered(blocks, external):
    """External interfaces with no inbound ACL, or one that permits ip any any before denying
    the internal ranges."""
    import vendor_ios   # late import: vendor_ios imports this module
    out = []
    for i in external:
        acl = i.get("acl_in")
        if not acl or vendor_ios._acl_is_open(blocks, acl):
            out.append(i["name"])
    return out


def check(blocks, top, interfaces, external, dev):
    res = []
    cfg = _itf_cfg(blocks)
    ext_names = [i["name"] for i in external]

    # --- CoPP ---
    # 'control-plane host' (the subinterface for traffic to the router itself) carries CoPP too
    cp = [ch for h, ch in blocks if h == "control-plane" or h == "control-plane host"]
    pol = [c for ch in cp for c in ch if re.match(r"service-policy input \S+", c)]
    maps = {h.split()[1] for h, _ in blocks if re.match(r"policy-map \S+$", h)}
    if pol:
        name = pol[0].split()[2]
        if name in maps or name.startswith("system-cpp"):
            res.append(result("IOS-NO-COPP", "pass", f"control-plane has service-policy input {name}",
                              ["control-plane"] + pol))
        else:
            res.append(result("IOS-NO-COPP", "fail", f"control-plane points at policy-map {name}, which is not "
                              "defined: nothing is policed", ["control-plane"] + pol, exposed=bool(external)))
    elif external:
        res.append(result("IOS-NO-COPP", "fail", "No 'service-policy input' under control-plane: traffic to the "
                          "router itself is not filtered or rate-limited, and the device faces the internet on "
                          + ", ".join(ext_names), ["control-plane"] if cp else [], exposed=True))
    elif _routes(blocks):
        res.append(result("IOS-NO-COPP", "fail", "No 'service-policy input' under control-plane (internal router: "
                          "only hosts inside can reach it)", ["control-plane"] if cp else []))
    else:
        res.append(result("IOS-NO-COPP", "n/a", "no routing protocol and no internet-facing interface: CoPP is a "
                          "router control (STIG RTR), and here only the management network reaches the device"))

    # --- ICMP and ARP behaviour on external interfaces ---
    rate_limit = [h for h in top if re.match(r"ip icmp rate-limit unreachable\b", h)]
    # Cisco ARP configuration guide, "Globally Disabling Proxy ARP": the global command turns
    # proxy ARP off on every interface.
    proxy_off_global = "ip arp proxy disable" in top
    if not external:
        for c in ("IOS-EDGE-IP-SERVICES", "IOS-EDGE-CDP-LLDP"):
            res.append(result(c, "n/a", "no internet-facing interface"))
    else:
        bad, ok, reach = [], [], False
        v6_routing = "ipv6 unicast-routing" in top
        for i in external:
            n, ch = i["name"], cfg.get(i["name"], [])
            why = []
            # IPv4 items on an interface that faces the internet over IPv4 (or one read before the
            # IPv4/IPv6 split, which has neither flag)
            if i.get("internet4", True) or not i.get("internet6"):
                if "no ip proxy-arp" not in ch and not proxy_off_global:
                    why.append("proxy-arp")
                if "no ip redirects" not in ch:
                    why.append("redirects")
                if "no ip unreachables" not in ch and not rate_limit:
                    why.append("unreachables")
                    reach = True
                if any(re.match(r"ip directed-broadcast\b", c) for c in ch):
                    why.append("directed-broadcast")
                    reach = True
            # IPv6 (Cisco IPv6 command reference: redirects and unreachables on by default; STIG
            # CISC-RT-000391: suppress router advertisements on external IPv6 interfaces). A router
            # sends RAs only with ipv6 unicast-routing.
            if i.get("internet6"):
                if "no ipv6 redirects" not in ch:
                    why.append("ipv6 redirects")
                if "no ipv6 unreachables" not in ch:
                    why.append("ipv6 unreachables")
                    reach = True
                if v6_routing and not any(re.match(r"ipv6 nd (ra suppress( all)?|suppress-ra)$", c) for c in ch):
                    why.append("ipv6 router advertisements")
            (bad if why else ok).append((n, why))
        if bad:
            res.append(result("IOS-EDGE-IP-SERVICES", "fail", "On by default and not turned off: " + "; ".join(
                f"{n} ({', '.join(w)})" for n, w in bad), [f"interface {n}" for n, _ in bad], exposed=reach,
                where=", ".join(n for n, _ in bad)))
        else:
            v6 = [i["name"] for i in external if i.get("internet6")]
            res.append(result("IOS-EDGE-IP-SERVICES", "pass", "proxy-arp, redirects and unreachables off, no "
                              "directed broadcast on " + ", ".join(ext_names)
                              + (f"; IPv6 redirects and unreachables off" + (
                                  ", router advertisements suppressed" if v6_routing else "")
                                 + f" on {', '.join(v6)}" if v6 else ""),
                              [f"interface {n}: {c}" for n in ext_names for c in cfg.get(n, [])
                               if re.match(r"no ipv6 (redirects|unreachables)$|no ip (proxy-arp|redirects|"
                                           r"unreachables)$|ipv6 nd (ra suppress|suppress-ra)", c)] + rate_limit
                              + (["ip arp proxy disable"] if proxy_off_global else [])))

        # --- CDP / LLDP on external interfaces ---
        cdp_show = _show(dev, "show-cdp-neighbors-detail.txt")
        lldp_show = _show(dev, "show-lldp-neighbors-detail.txt")
        if "no cdp run" in top:
            cdp_on, cdp_how = False, "no cdp run"
        elif "cdp run" in top:
            cdp_on, cdp_how = True, "cdp run"
        elif cdp_show is not None and re.search(r"CDP is not enabled", cdp_show):
            cdp_on, cdp_how = False, "show cdp neighbors: CDP is not enabled"
        elif cdp_show is not None:
            cdp_on, cdp_how = True, "show cdp neighbors answers (CDP runs)"
        else:
            cdp_on, cdp_how = True, "assumed on: no 'no cdp run' line and no show cdp output saved"
        if "lldp run" in top:
            lldp_on, lldp_how = True, "lldp run"
        else:
            lldp_on, lldp_how = False, "no 'lldp run' (LLDP is off by default)"
        # IOS writes only non-default lines. A 'cdp enable' line on any interface means the per-interface
        # default on this platform is off (seen on some IOS XE routers), so only those interfaces run it.
        explicit = {h.split()[1] for h, ch in blocks if h.startswith("interface ") and "cdp enable" in ch}
        if explicit and cdp_on:
            cdp_how += "; per-interface default off ('cdp enable' is written on " + ", ".join(sorted(explicit)[:4]) \
                + (" and more" if len(explicit) > 4 else "") + ")"
        hits = []
        for n in ext_names:
            ch = cfg.get(n, [])
            if cdp_on and "no cdp enable" not in ch and (not explicit or n in explicit):
                hits.append(f"{n} (CDP)")
            if lldp_on and "no lldp transmit" not in ch:
                hits.append(f"{n} (LLDP)")
        if hits:
            res.append(result("IOS-EDGE-CDP-LLDP", "fail", "Discovery protocol sent toward the outside: "
                              + ", ".join(hits) + f". CDP: {cdp_how}; LLDP: {lldp_how}",
                              [f"interface {h.split()[0]}" for h in hits], where=", ".join(hits)))
        else:
            res.append(result("IOS-EDGE-CDP-LLDP", "pass", f"no CDP or LLDP toward the outside. CDP: {cdp_how}; "
                              f"LLDP: {lldp_how}",
                              [f"interface {n}: {c}" for n in ext_names for c in cfg.get(n, [])
                               if c in ("no cdp enable", "no lldp transmit", "no lldp receive")]))

    # --- legacy services ---
    found, listening = [], False
    for pat, port in LEGACY:
        for h in top:
            if re.match(pat, h):
                found.append(h)
                listening |= port
    ver = _version(top)
    if "ipv6 source-route" in top:
        # off by default since IOS 12.4(15)T: the router then drops packets with a type 0 routing header
        found.append("ipv6 source-route")
    if any(re.match(r"ip source-route\b", h) for h in top):
        found.append("ip source-route")
    elif ver and ver < (17, 1) and "no ip source-route" not in top:
        found.append(f"no 'no ip source-route' (source routing is on by default before IOS XE 17.1.1; "
                     f"config says version {ver[0]}.{ver[1]})")
    if found:
        open_itf = _unfiltered(blocks, external) if listening else []
        res.append(result("IOS-LEGACY-SERVICES", "fail", "Legacy services on: " + "; ".join(found)
                          + (f". Reachable through {', '.join(open_itf)} (no inbound ACL or one that permits "
                             "ip any any)" if open_itf else ""), [f for f in found if not f.startswith("no '")],
                          exposed=bool(open_itf)))
    else:
        res.append(result("IOS-LEGACY-SERVICES", "pass", "no small servers, finger, identd, BOOTP or DNS server, "
                          "rcmd, PAD, service config, boot network or source routing in the config"
                          + (f" (version {ver[0]}.{ver[1]}: source routing off by default)" if ver and ver >= (17, 1)
                             else ""),
                          [h for h in top if re.match(r"no (service|ip) (tcp-small|udp-small|pad|finger|bootp|"
                                                      r"source-route|identd|dns server)", h)]))
    return res
