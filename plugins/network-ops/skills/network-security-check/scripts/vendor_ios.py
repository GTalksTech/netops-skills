# ============================================================
# Script:       vendor_ios.py
# Purpose:      Cisco IOS / IOS-XE: facts (interfaces, internet exposure, features) and
#               config checks from a saved running config.
# Author:       G Talks Tech
# Notes:        Read-only. Check IDs and sources live in settings/checks.yaml.
# ============================================================
import ipaddress
import re
from pathlib import Path

from common import feature, finding, is_public, is_segmented, mask_to_prefix, new_facts
from parsers import ios_blocks

WEAK_COMMUNITIES = {"public", "private", "cisco", "community", "snmp", "admin", "secret"}


PRIVATE_DENY = re.compile(r"^deny\s+ip\s+\S+(\s+\S+)?\s+(any|10\.0\.0\.0 0\.255\.255\.255|"
                          r"172\.16\.0\.0 0\.15\.255\.255|192\.168\.0\.0 0\.0\.255\.255)(\s|$)")


def _acl_is_open(blocks, name):
    """True when an ACL reaches a permit ip any any without first denying the internal ranges
    (deny ip ... any, or a deny to 10/8, 172.16/12 or 192.168/16)."""
    lines = []
    for h, ch in blocks:
        if h == f"ip access-list extended {name}" or h == f"ip access-list standard {name}":
            lines = ch
        elif h.startswith(f"access-list {name} "):
            lines.append(h.split(" ", 2)[2])
    for l in lines:
        l = re.sub(r"^\d+\s+", "", l)
        if PRIVATE_DENY.match(l):
            return False
        if re.match(r"permit\s+ip\s+any\s+any\b", l) or l == "permit any":
            return True
    return not lines  # ACL referenced but not defined: IOS permits all


def _in_network(ip, net, wild):
    """IOS 'network <net> <wildcard>' match for one interface address."""
    try:
        a, n, w = (int(ipaddress.IPv4Address(x)) for x in (ip, net, wild))
    except ValueError:
        return False
    return (a & ~w) == (n & ~w)


def _classful_wild(net):
    first = int(net.split(".")[0])
    return "0.255.255.255" if first < 128 else "0.0.255.255" if first < 192 else "0.0.0.255"


STRONG_MAC = re.compile(r"^(hmac-sha-?(1|256|384|512)|aes-(128|256)-cmac)", re.I)


def _chain_grade(chains, name):
    """Grade a key chain by its cryptographic-algorithm lines: strong, md5 or unset."""
    algs = chains.get(name)
    if not algs:
        return "unset", f"key chain {name}: no cryptographic-algorithm"
    if not all(STRONG_MAC.match(a) for a in algs):
        return "md5", f"key chain {name}: {', '.join(sorted(algs))}"
    return "strong", f"key chain {name}: {', '.join(sorted(algs))}"


def _routing_auth(blocks, interfaces):
    """Every routing adjacency and how it is authenticated, as dicts {what, grade, how, public}.
    grade: none, clear (clear-text key), md5, unset (key chain with no algorithm), strong
    (HMAC-SHA or AES-CMAC).
    OSPF: 'ip ospf authentication [message-digest|key-chain K|null]' on the interface, else
    'area X authentication [message-digest]'. EIGRP: 'ip authentication mode eigrp N md5', or
    'authentication mode md5|hmac-sha-256' under a named-mode af-interface (or default). BGP:
    'neighbor X password' (TCP MD5) or 'neighbor X ao K' (TCP-AO), on the neighbor or its
    peer-group. Loopbacks and passive interfaces form no adjacency: skipped."""
    itf_cfg = {h.split()[1]: ch for h, ch in blocks if h.startswith("interface ")}
    chains = {}
    for h, ch in blocks:
        mk = re.match(r"key chain (\S+)", h)
        if mk:
            chains[mk.group(1)] = {c.split()[1] for c in ch if c.startswith("cryptographic-algorithm ")}
    addrs = {i["name"]: [ip.split("/")[0] for ip in i["ips"] if ip != "dhcp"]
             for i in interfaces if not i["shutdown"] and not i["name"].lower().startswith("loopback")}
    out = []
    for h, ch in blocks:
        m = re.match(r"router (ospf|eigrp) (\S+)", h)
        if m:
            proto, pid = m.groups()
            passive_default = "passive-interface default" in ch
            passive = {c.split()[1] for c in ch if c.startswith("passive-interface ") and c != "passive-interface default"}
            active = {c.split()[2] for c in ch if c.startswith("no passive-interface ")}
            nets = []
            for c in ch:
                mn = re.match(r"network (\S+)(?: (\d+\.\d+\.\d+\.\d+))?(?: area (\S+))?", c)
                if mn:
                    nets.append((mn.group(1), mn.group(2) or _classful_wild(mn.group(1)), mn.group(3)))
            area_auth = {}
            for c in ch:
                ma = re.match(r"area (\S+) authentication( message-digest)?$", c)
                if ma:
                    area_auth[ma.group(1)] = ("md5", "area message-digest") if ma.group(2) else \
                        ("clear", "area clear-text key")
            asn, named, af_itf = pid, {}, None
            for c in ch:   # named EIGRP: address-family ... autonomous-system N / af-interface X
                mas = re.search(r"autonomous-system (\d+)", c)
                if mas:
                    asn = mas.group(1)
                if c.startswith("af-interface "):
                    af_itf = c.split()[1]
                elif c == "exit-af-interface":
                    af_itf = None
                elif af_itf and c.startswith("authentication mode "):
                    mode = c.split()[2]
                    named[af_itf] = ("md5", "md5") if mode == "md5" else ("strong", mode)
            for name, ips in addrs.items():
                icfg = itf_cfg.get(name, [])
                area = None
                if proto == "ospf":
                    ia = [c for c in icfg if re.match(rf"ip ospf {re.escape(pid)} area (\S+)", c)]
                    if ia:
                        area = ia[0].split()[-1]
                runs = bool(area) or any(_in_network(ip, n, w) for ip in ips for n, w, _ in nets)
                if not runs or (passive_default and name not in active) or name in passive:
                    continue
                if proto == "ospf":
                    area = area or next((a for ip in ips for n, w, a in nets if _in_network(ip, n, w)), None)
                    iauth = [c for c in icfg if c.startswith("ip ospf authentication")
                             and not c.startswith("ip ospf authentication-key")]
                    if not iauth:
                        grade, how = area_auth.get(area, ("none", ""))
                    elif iauth[0] == "ip ospf authentication null":
                        grade, how = "none", "null"
                    elif iauth[0] == "ip ospf authentication message-digest":
                        grade, how = "md5", "message-digest"
                    elif iauth[0].startswith("ip ospf authentication key-chain "):
                        grade, how = _chain_grade(chains, iauth[0].split()[-1])
                    else:
                        grade, how = "clear", "clear-text key"
                else:
                    if any(c.startswith(f"ip authentication mode eigrp {asn} ") for c in icfg):
                        grade, how = "md5", "md5"
                    else:
                        grade, how = named.get(name) or named.get("default") or ("none", "")
                out.append({"what": f"{proto.upper()} {pid} on {name}", "grade": grade, "how": how,
                            "public": False})
        mb = re.match(r"router bgp (\S+)", h)
        if mb:
            peers = {c.split()[1]: c.split()[3] for c in ch if re.match(r"neighbor \S+ remote-as \S+", c)}
            group = {c.split()[1]: c.split()[3] for c in ch if re.match(r"neighbor \S+ peer-group \S+$", c)}
            auth = {}
            for c in ch:
                ma = re.match(r"neighbor (\S+) (password|ao) (\S+)", c)
                if ma:
                    auth[ma.group(1)] = ("md5", "TCP MD5 password") if ma.group(2) == "password" else \
                        _chain_grade(chains, ma.group(3))
            for n, ras in peers.items():
                if not re.match(r"[\d.:a-fA-F]+$", n):
                    continue
                grade, how = auth.get(n) or auth.get(group.get(n)) or ("none", "")
                out.append({"what": f"BGP neighbor {n} (AS {ras})", "grade": grade, "how": how,
                            "public": is_public(n)})
    return out


def _ssh_version(dev):
    """'2.0', '1.99' or '1.5' from the snapshot's show ip ssh output, else None."""
    folder = dev.get("_folder")
    f = Path(folder) / "show-ip-ssh.txt" if folder else None
    if not f or not f.exists():
        return None
    m = re.search(r"SSH Enabled - version (\d+\.\d+)", f.read_text(encoding="utf-8", errors="replace"))
    return m.group(1) if m else None


def analyze(text, dev):
    blocks = ios_blocks(text)
    facts = new_facts()
    found = []
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

    for h, ch in blocks:
        m = re.match(r"interface (\S+)", h)
        if not m:
            continue
        name = m.group(1)
        itf = {"name": name, "ips": [], "acl_in": None, "vrf": "global", "shutdown": False,
               "description": None}
        for c in ch:
            ma = re.match(r"ip address (\S+) (\S+)", c)
            if ma:
                itf["ips"].append(f"{ma.group(1)}/{mask_to_prefix(ma.group(2))}")
            elif c.startswith("ip access-group ") and c.endswith(" in"):
                itf["acl_in"] = c.split()[2]
            elif re.match(r"(ip )?vrf forwarding ", c):
                itf["vrf"] = c.split()[-1]
            elif c == "shutdown":
                itf["shutdown"] = True
            elif c == "ip nat outside":
                itf["nat_outside"] = True
            elif c.startswith("ip address dhcp"):
                itf["ips"].append("dhcp")
            elif c.startswith("description "):
                itf["description"] = c[12:]
        vm = re.match(r"[Vv]lan(\d+)$", name)
        itf["vlan_name"] = vlan_names.get(vm.group(1)) if vm else None
        itf["public"] = any(is_public(ip) for ip in itf["ips"] if ip != "dhcp")
        mgmt = bool(re.search(r"mgmt|management|oob", itf["vrf"], re.I))
        # a public IP, or a NAT outside interface (also covers a DHCP address from the ISP)
        itf["internet"] = (itf["public"] or itf.get("nat_outside", False)) and not mgmt and not itf["shutdown"]
        facts["interfaces"].append(itf)
        if itf["internet"]:
            facts["internet_interfaces"].append(name)

    internet = bool(facts["internet_interfaces"])
    if len(top) < 5:
        facts["notes"].append("config is nearly empty: config checks skipped")
        facts["internet_facing"], facts["exposure_reason"] = internet, "config not readable"
        return facts, []

    # --- management plane ---
    http_lines = [h for h in top if re.match(r"ip http (secure-)?server$", h)]
    http_acl = any(h.startswith("ip http access-class") for h in top)
    feature(facts, "http_server", bool(http_lines), internet and not http_acl,
            "ip http server" if http_lines else None)
    if http_lines:
        found.append(finding("IOS-HTTP-SERVER",
                             "Web UI is on" + (" and the device has an internet-facing interface with no "
                                               "ip http access-class" if internet and not http_acl else ""),
                             http_lines, exposed=internet and not http_acl))

    vty = [(h, ch) for h, ch in blocks if h.startswith("line vty")
           and "transport input none" not in ch]
    no_acl = [h for h, ch in vty if not any(c.startswith("access-class") for c in ch)]
    no_tin = [h for h, ch in vty if not any(c.startswith("transport input") for c in ch)]
    if no_tin:
        facts["notes"].append(f"{', '.join(no_tin)}: no 'transport input' line. The default (and whether "
                              "telnet is allowed) depends on the release: set 'transport input ssh'.")
    for h, ch in vty:
        tin = [c for c in ch if c.startswith("transport input")]
        if any(re.search(r"\b(telnet|all)\b", c) for c in tin):
            found.append(finding("IOS-TELNET", f"{h}: {tin[0]}", [h] + tin,
                                 exposed=internet and h in no_acl, where=h))
    if no_acl:
        found.append(finding("IOS-VTY-ACL", "No access-class on: " + ", ".join(no_acl), no_acl,
                             exposed=internet))
    # IOS-XE 17.x runs SSH v2 only and writes no "ip ssh version 2" line, so the saved
    # "show ip ssh" output decides when it is there ("version 2.0" = v2 only, "1.99" = both).
    ssh_shown = _ssh_version(dev)
    if vty and "ip ssh version 2" not in top and ssh_shown != "2.0" and not all(
            any(re.search(r"transport input (none|telnet)$", c) for c in ch) for _, ch in vty):
        found.append(finding("IOS-SSH-V1", "No 'ip ssh version 2' line" + (
            f" and 'show ip ssh' reports version {ssh_shown}" if ssh_shown else
            " (no 'show ip ssh' output saved to confirm)"), [], exposed=False))

    snmp_bad = []
    for h in top:
        m = re.match(r"snmp-server community (\S+)(.*)", h)
        if not m:
            continue
        name, rest = m.group(1), m.group(2).split()
        rw = "RW" in rest or "rw" in rest
        acl = [r for r in rest if r not in ("RO", "RW", "ro", "rw", "view") and not r.startswith("view")]
        if "view" in rest:
            acl = rest[rest.index("view") + 2:]
            acl = [a for a in acl if a not in ("RO", "RW")]
        why = []
        if name.lower() in WEAK_COMMUNITIES:
            why.append("default/guessable name")
        if rw:
            why.append("read-write")
        if not acl:
            why.append("no ACL")
        if why:
            snmp_bad.append((re.sub(r"community \S+", "community <hidden>", h), why, not acl))
    communities = [h for h in top if h.startswith("snmp-server community ")]
    feature(facts, "snmp", bool(communities) or any(h.startswith("snmp-server") for h in top),
            internet and any(x[2] for x in snmp_bad))
    feature(facts, "dhcp_snooping", "ip dhcp snooping" in top, False)   # an access-layer feature
    feature(facts, "iox", "iox" in top, internet)
    ike = [h for h in top if re.match(r"crypto (isakmp|ikev2) ", h)]
    feature(facts, "ike", bool(ike), internet and bool(ike))
    feature(facts, "sdwan", any(h == "sdwan" or h.startswith("sdwan ") for h in top), internet)
    # Conditions below are the "vulnerable products" config checks in Cisco's advisories
    # (research/sources.md, cisco-sa-feature-conditions).
    ssl_vpn = [h for h, ch in blocks if h.startswith("crypto ssl policy ") and "shutdown" not in ch]
    feature(facts, "ssl_vpn", bool(ssl_vpn), internet, ssl_vpn[0] if ssl_vpn else None)
    webauth = [h for h in top if re.match(r"ip admission name \S+ proxy http", h)
               or h.startswith("parameter-map type webauth")]
    feature(facts, "webauth", bool(http_lines and webauth), internet and not http_acl,
            webauth[0] if webauth else None)
    feature(facts, "nbar_capwap", "ip nbar classification tunneled-traffic capwap" in top, internet)
    beep = [h for h in top if "beep listener" in h]
    feature(facts, "beep", bool(beep), internet, beep[0] if beep else None)
    feature(facts, "xmcp", any(h.startswith("service-routing xmcp listen") for h in top), internet)
    feature(facts, "meraki", any(re.match(r"(service )?meraki\b", h) for h in top), internet)
    if snmp_bad:
        found.append(finding("IOS-SNMP-COMMUNITY",
                             "; ".join(f"community {n + 1}: {', '.join(w)}" for n, (_, w, _) in enumerate(snmp_bad)),
                             [l for l, _, _ in snmp_bad], exposed=internet and any(x[2] for x in snmp_bad)))

    weak = []
    for h in top:
        if re.match(r"enable password ", h):
            weak.append("enable password (type 0/7)")
        elif re.match(r"enable secret 5 ", h):
            weak.append("enable secret type 5 (MD5)")
        m = re.match(r"username (\S+) .*?(password|secret) (\d) ", h)
        if m and (m.group(2) == "password" or m.group(3) == "5"):
            weak.append(f"username {m.group(1)}: {m.group(2)} type {m.group(3)}")
        elif re.match(r"username \S+ .*password (?!\d )\S", h):
            weak.append(f"username {h.split()[1]}: clear-text password")
    if weak:
        found.append(finding("IOS-PASSWORD-STORAGE", "; ".join(weak), [], exposed=False))

    if "vstack" in top:
        feature(facts, "smart_install", True, internet)
        found.append(finding("IOS-SMART-INSTALL", "vstack is configured", ["vstack"], exposed=internet))
    elif "no vstack" not in top and dev.get("_is_switch"):
        facts["notes"].append("Smart Install state is not in the config. Run 'show vstack config' "
                              "on switches to confirm it is disabled.")

    # --- routing protocol authentication ---
    # OSPF and EIGRP use link-local packets (TTL 1): only a device on the link can inject
    # routes, so they are never internet-exposed. BGP is TCP to the neighbor's address, so an
    # unauthenticated session to a public address is.
    adj = _routing_auth(blocks, facts["interfaces"])
    no_auth = [a for a in adj if a["grade"] in ("none", "clear")]
    weak_auth = [a for a in adj if a["grade"] in ("md5", "unset")]

    def _adj_list(items):
        parts = [a["what"] + (f" ({a['how']})" if a["how"] else "") for a in items]
        return "; ".join(parts[:8]) + (f"; and {len(parts) - 8} more" if len(parts) > 8 else "")
    if no_auth:
        found.append(finding("IOS-ROUTING-NO-AUTH", "No authentication: " + _adj_list(no_auth), [],
                             exposed=any(a["public"] for a in no_auth)))
    if weak_auth:
        found.append(finding("IOS-ROUTING-WEAK-AUTH", "MD5 or no algorithm set: " + _adj_list(weak_auth),
                             [], exposed=any(a["public"] for a in weak_auth)))

    if not any(re.match(r"logging (host \S|\d)", h) for h in top):
        found.append(finding("IOS-NO-REMOTE-LOG", "No 'logging host' line", [], exposed=False))

    # --- segmentation: a segmented SVI routing to other SVIs in the same VRF with no ACL ---
    svis = [i for i in facts["interfaces"] if re.match(r"[Vv]lan\d+$", i["name"]) and i["ips"]
            and not i["shutdown"]]
    for s in svis:
        if not is_segmented(s["vlan_name"], s["description"]):
            continue
        if s["acl_in"] and not _acl_is_open(blocks, s["acl_in"]):
            continue
        peers = [p for p in svis if p is not s and p["vrf"] == s["vrf"]
                 and not is_segmented(p["vlan_name"], p["description"])]
        if not peers:
            continue
        label = s["vlan_name"] or s["description"]
        acl_txt = f"ACL {s['acl_in']} permits ip any any" if s["acl_in"] else "no inbound ACL"
        found.append(finding(
            "IOS-SEGMENT-ROUTED",
            f"{s['name']} ({label}, {s['ips'][0]}) has {acl_txt} and shares VRF '{s['vrf']}' with "
            + ", ".join(f"{p['name']} ({p['vlan_name'] or p['description'] or 'no name'})" for p in peers[:6]),
            [f"interface {s['name']}"], exposed=False, where=s["name"]))

    facts["internet_facing"] = internet
    facts["exposure_reason"] = ("public IP on " + ", ".join(facts["internet_interfaces"])) if internet else \
        "no interface with a public IP"
    return facts, found
