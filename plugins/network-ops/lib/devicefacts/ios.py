# ============================================================
# Script:       ios.py
# Purpose:      Cisco IOS / IOS-XE device facts from a saved running config: interfaces
#               (IPv4 and IPv6, which face the internet and the lines that show it) and the
#               features CVE conditions name, each on, off or unknown with its proof lines.
# Author:       G Talks Tech
# Notes:        Read-only text parsing. The feature conditions follow the "vulnerable products"
#               config checks in Cisco's advisories (network-vuln-scan research/sources.md,
#               cisco-sa-feature-conditions).
# ============================================================
import ipaddress
import re

from .facts import feature, internet_evidence, new_facts, unknown
from .ios_bgp import bgp_sessions
from .net import is_public, looks_internet, mask_to_prefix
from .parsers import ios_blocks

FEATURES = ("http_server", "snmp", "dhcp_snooping", "iox", "ike", "sdwan", "ssl_vpn", "webauth", "nbar_capwap",
            "beep", "xmcp", "meraki", "smart_install")
SPARSE = 5      # a config with fewer top-level lines than this is not trusted


def general_prefixes(blocks):
    """{name: prefix} for IPv6 general prefixes: 'ipv6 general-prefix NAME X/len' as written, and
    'ipv6 dhcp client pd NAME' (delegated by the upstream, so global unicast: stored as None)."""
    out = {}
    for h, ch in blocks:
        m = re.match(r"ipv6 general-prefix (\S+) ([0-9A-Fa-f:]+/\d+)", h)
        if m:
            out[m.group(1)] = m.group(2)
        for c in ch:
            m = re.match(r"ipv6 dhcp client pd (\S+)", c)
            if m and not m.group(1).startswith("hint"):
                out.setdefault(m.group(1), None)
    return out


def _ipv6_line(itf, c, gen_prefixes):
    """Read one interface 'ipv6 ...' line into itf: ips6 (address/len), v6_learned (SLAAC or
    DHCPv6 address), v6_pd_client, acl6_in (ipv6 traffic-filter X in). Address and prefix
    delegation lines are kept in _v6_lines as proof."""
    m = re.match(r"ipv6 address ([0-9A-Fa-f:]+/\d+)", c)
    if m:
        itf.setdefault("ips6", []).append(m.group(1))
        itf["_v6_lines"].append(c)
        return
    m = re.match(r"ipv6 address (\S+) ([0-9A-Fa-f:]+/\d+)", c)
    if m and m.group(1) in gen_prefixes:          # general prefix + host part
        pfx = gen_prefixes[m.group(1)]
        if pfx:
            itf.setdefault("ips6", []).append(pfx)
        else:
            itf["v6_delegated"] = True      # from a delegated prefix: global unicast, subnet unknown
        itf["_v6_lines"].append(c)
        return
    if re.match(r"ipv6 address (autoconfig|dhcp)\b", c):
        itf["v6_learned"] = True
        itf["_v6_lines"].append(c)
    elif c.startswith("ipv6 dhcp client pd "):
        itf["v6_pd_client"] = True
        itf["_v6_lines"].append(c)
    elif re.match(r"ipv6 traffic-filter \S+ in$", c):
        itf["acl6_in"] = c.split()[2]


def _mark_internet6(blocks, interfaces):
    """Set itf['internet6']: the interface has a global unicast IPv6 address (net.is_public:
    2000::/3, not fe80::/10 or fc00::/7) AND something shows it is the outside. IPv6 LANs use global
    addresses too, so the address alone cannot tell an inside interface from the ISP link the way a
    public IPv4 address does. Outside signs: the interface also faces the internet over IPv4; an
    IPv6 default route leaves through it; an eBGP neighbor with a public address sits in its subnet;
    it asks the upstream for a delegated prefix (ipv6 dhcp client pd, which also makes a SLAAC or
    DHCPv6 address on it count); or its name or description reads like an internet link
    (naming.yaml internet_names). The sign is kept in _v6_proof."""
    ebgp6 = [(ipaddress.ip_address(s["neighbor"]), f"neighbor {s['neighbor']} remote-as {s['remote_as']}")
             for s in bgp_sessions(blocks, per_neighbor=True)
             if s["ebgp"] and ":" in s["neighbor"] and is_public(s["neighbor"])]
    defaults = []       # (interface or None, next hop or None, line) of 'ipv6 route ::/0 ...'
    for h, _ in blocks:
        m = re.match(r"ipv6 route (?:vrf \S+ )?::/0 (\S+)(?: (\S+))?", h)
        if m:
            a, b = m.groups()
            if ":" in a:
                defaults.append((None, a, h))
            else:
                defaults.append((a, b if b and ":" in b else None, h))
    for itf in interfaces:
        nets = []
        for ip in itf.get("ips6", []):
            try:
                nets.append(ipaddress.ip_interface(ip).network)
            except ValueError:
                pass
        pub6 = any(is_public(ip) for ip in itf.get("ips6", [])) or bool(itf.get("v6_delegated"))
        pd = bool(itf.get("v6_pd_client"))
        itf["public"] = itf["public"] or pub6
        if not itf["up"] or not (pub6 or (pd and itf.get("v6_learned"))):
            itf["internet6"] = False
            continue

        def _in(addr):
            try:
                a = ipaddress.ip_address(addr.split("%")[0])
            except ValueError:
                return False
            return any(a in n for n in nets if n.prefixlen < 128)
        route = next((l for i, nh, l in defaults if i == itf["name"] or (i is None and nh and _in(nh))), None)
        peer = next((l for a, l in ebgp6 if any(n.prefixlen < 128 and a in n for n in nets)), None)
        named = looks_internet(itf["name"]) or looks_internet(itf.get("description"))
        why = ("IPv4 internet link" if itf["internet4"] else
               "ipv6 dhcp client pd" if pd else
               "IPv6 default route" if route else
               "eBGP neighbor" if peer else
               "name" if named else None)
        itf["internet6"] = bool(why)
        if why:
            itf["internet6_why"] = why
            itf["_v6_proof"] = [l for l in (route, peer) if l and why in ("IPv6 default route", "eBGP neighbor")] + (
                [f"description {itf['description']}"] if why == "name" and itf.get("description") else [])


def snmp_communities(top):
    """Each 'snmp-server community' line: {line, name, rw, acl (list of ACL words)}."""
    out = []
    for h in top:
        m = re.match(r"snmp-server community (\S+)(.*)", h)
        if not m:
            continue
        name, rest = m.group(1), m.group(2).split()
        acl = [r for r in rest if r not in ("RO", "RW", "ro", "rw", "view") and not r.startswith("view")]
        if "view" in rest:
            acl = [a for a in rest[rest.index("view") + 2:] if a not in ("RO", "RW")]
        out.append({"line": h, "name": name, "rw": "RW" in rest or "rw" in rest, "acl": acl})
    return out


def http_lines(top):
    """('ip http server' / 'ip http secure-server' lines, 'ip http access-class' lines)."""
    return ([h for h in top if re.match(r"ip http (secure-)?server$", h)],
            [h for h in top if re.match(r"ip http access-class (ipv4 )?\S+", h)])


def read(text, dev):
    """Facts from one IOS / IOS-XE running config. dev: the inventory entry; '_is_switch'
    (from the model) decides what a missing Smart Install line means."""
    blocks = ios_blocks(text)
    facts = new_facts()
    top = [h for h, _ in blocks]

    for h in top:
        if h.startswith("hostname "):
            facts["hostname"] = h.split()[1]

    vlan_names = {}
    for h, ch in blocks:
        m = re.match(r"vlan (\d+)$", h)
        if m:
            for c in ch:
                if c.startswith("name "):
                    vlan_names[m.group(1)] = c[5:].strip()

    gen_prefixes = general_prefixes(blocks)
    for h, ch in blocks:
        m = re.match(r"interface (\S+)", h)
        if not m:
            continue
        name = m.group(1)
        itf = {"name": name, "ips": [], "acl_in": None, "vrf": "global", "shutdown": False,
               "description": None, "_v4_lines": [], "_v6_lines": []}
        for c in ch:
            ma = re.match(r"ip address (\S+) (\S+)", c)
            if ma:
                itf["ips"].append(f"{ma.group(1)}/{mask_to_prefix(ma.group(2))}")
                if is_public(itf["ips"][-1]):
                    itf["_v4_lines"].append(c)
            elif c.startswith("ip access-group ") and c.endswith(" in"):
                itf["acl_in"] = c.split()[2]
            elif re.match(r"(ip )?vrf forwarding ", c):
                itf["vrf"] = c.split()[-1]
            elif c == "shutdown":
                itf["shutdown"] = True
            elif c == "ip nat outside":
                itf["nat_outside"] = True
                itf["_v4_lines"].append(c)
            elif c.startswith("ip address dhcp"):
                itf["ips"].append("dhcp")
                itf["_v4_lines"].append(c)
            elif c.startswith("description "):
                itf["description"] = c[12:]
            elif c.startswith("ipv6 "):
                _ipv6_line(itf, c, gen_prefixes)
        vm = re.match(r"[Vv]lan(\d+)$", name)
        itf["vlan_name"] = vlan_names.get(vm.group(1)) if vm else None
        pub4 = any(is_public(ip) for ip in itf["ips"] if ip != "dhcp")
        itf["public"], itf["_pub4"] = pub4, pub4
        mgmt = bool(re.search(r"mgmt|management|oob", itf["vrf"], re.I))
        itf["up"] = not mgmt and not itf["shutdown"]
        # a public IP, or a NAT outside interface (also covers a DHCP address from the ISP)
        itf["internet4"] = (pub4 or itf.get("nat_outside", False)) and itf["up"]
        facts["interfaces"].append(itf)
    _mark_internet6(blocks, facts["interfaces"])
    for itf in facts["interfaces"]:
        itf["internet"] = itf["internet4"] or itf["internet6"]
        itf.pop("up", None)
        v4, v6, v6p = itf.pop("_v4_lines"), itf.pop("_v6_lines"), itf.pop("_v6_proof", [])
        pub4 = itf.pop("_pub4")
        if itf["internet"]:
            facts["internet_interfaces"].append(itf["name"])
            why = " and ".join(w for w in (
                ("public IPv4 address" if pub4 else "ip nat outside")
                if itf["internet4"] else None,
                f"IPv6 ({itf['internet6_why']})" if itf["internet6"] else None) if w)
            internet_evidence(itf, [f"interface {itf['name']}"] + (v4 if itf["internet4"] else [])
                              + (v6 + v6p if itf["internet6"] else []), why)

    internet = bool(facts["internet_interfaces"])
    facts["internet_facing"] = internet
    facts["exposure_reason"] = ("public IP on " + ", ".join(facts["internet_interfaces"])) if internet else \
        "no interface with a public IP"
    if len(top) < SPARSE:
        facts["notes"].append("config is nearly empty: feature conditions not read")
        facts["exposure_reason"] = "config not readable"
        for f in FEATURES:
            unknown(facts, f, "config is nearly empty")
        return facts

    # --- features named in CVE conditions ---
    http, acl = http_lines(top)
    http_acl = bool(acl)
    feature(facts, "http_server", bool(http), internet and not http_acl, "ip http server" if http else None,
            http + acl if http else [h for h in top if re.match(r"no ip http (secure-)?server$", h)],
            ("web UI on" + ("" if http_acl else ", no ip http access-class")) if http else
            "no 'ip http server' or 'ip http secure-server' line")
    communities = snmp_communities(top)
    snmp_lines = [h for h in top if h.startswith("snmp-server")]
    open_comm = [c["line"] for c in communities if not c["acl"]]
    feature(facts, "snmp", bool(communities) or bool(snmp_lines), internet and bool(open_comm), None,
            (open_comm or [c["line"] for c in communities] or snmp_lines),
            ("SNMP configured" + (f", {len(open_comm)} community line(s) with no ACL" if open_comm else ""))
            if snmp_lines else "no 'snmp-server' line")
    _line(facts, "dhcp_snooping", top, lambda h: h == "ip dhcp snooping", False, "ip dhcp snooping")   # an access-layer feature
    _line(facts, "iox", top, lambda h: h == "iox", internet, "iox")
    _line(facts, "ike", top, lambda h: re.match(r"crypto (isakmp|ikev2) ", h), internet, "crypto isakmp / crypto ikev2")
    _line(facts, "sdwan", top, lambda h: h == "sdwan" or h.startswith("sdwan "), internet, "sdwan")
    ssl_policies = [(h, ch) for h, ch in blocks if h.startswith("crypto ssl policy ")]
    ssl_vpn = [h for h, ch in ssl_policies if "shutdown" not in ch]
    feature(facts, "ssl_vpn", bool(ssl_vpn), internet, ssl_vpn[0] if ssl_vpn else None,
            ssl_vpn or [f"{h}: shutdown" for h, _ in ssl_policies],
            "crypto ssl policy without shutdown" if ssl_vpn else
            "every crypto ssl policy is shut down" if ssl_policies else "no 'crypto ssl policy' line")
    webauth = [h for h in top if re.match(r"ip admission name \S+ proxy http", h)
               or h.startswith("parameter-map type webauth")]
    feature(facts, "webauth", bool(http and webauth), internet and not http_acl, webauth[0] if webauth else None,
            webauth + http if webauth else [],
            "web authentication with the HTTP server on" if http and webauth else
            "web authentication configured, but the HTTP server is off" if webauth else
            "no 'ip admission name ... proxy http' or 'parameter-map type webauth' line")
    _line(facts, "nbar_capwap", top, lambda h: h == "ip nbar classification tunneled-traffic capwap", internet,
          "ip nbar classification tunneled-traffic capwap")
    _line(facts, "beep", top, lambda h: "beep listener" in h, internet, "netconf beep listener", where=True)
    _line(facts, "xmcp", top, lambda h: h.startswith("service-routing xmcp listen"), internet,
          "service-routing xmcp listen")
    _line(facts, "meraki", top, lambda h: re.match(r"(service )?meraki\b", h), internet, "service meraki")
    if "vstack" in top:
        feature(facts, "smart_install", True, internet, None, ["vstack"], "vstack is configured")
    elif "no vstack" in top:
        feature(facts, "smart_install", False, False, None, ["no vstack"], "Smart Install is turned off")
    elif dev.get("_is_switch"):
        facts["notes"].append("Smart Install state is not in the config. Run 'show vstack config' "
                              "on switches to confirm it is disabled.")
        unknown(facts, "smart_install", "not in the config: needs 'show vstack config'")
    else:
        unknown(facts, "smart_install", "not in the config, and the model is not a known Catalyst switch")
    return facts


def _line(facts, name, top, match, internet, label, where=False):
    """A feature that one top-level line turns on: on with that line, else off by absence."""
    hits = [h for h in top if match(h)]
    feature(facts, name, bool(hits), internet, hits[0] if hits and where else None, hits,
            f"'{label}' is configured" if hits else f"no '{label}' line in the config")
