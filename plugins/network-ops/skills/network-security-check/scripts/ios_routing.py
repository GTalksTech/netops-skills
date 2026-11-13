# ============================================================
# Script:       ios_routing.py
# Purpose:      Cisco IOS / IOS-XE routing protocol authentication: every OSPF, EIGRP and
#               BGP adjacency and how it authenticates, and the two checks built on it
#               (IOS-ROUTING-NO-AUTH, IOS-ROUTING-WEAK-AUTH).
# Author:       G Talks Tech
# Notes:        Read-only. Called by vendor_ios.analyze.
# ============================================================
import ipaddress
import re

from common import is_public, result


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


def _adj_list(items):
    parts = [a["what"] + (f" ({a['how']})" if a["how"] else "") for a in items]
    return "; ".join(parts[:8]) + (f"; and {len(parts) - 8} more" if len(parts) > 8 else "")


def check(blocks, interfaces):
    """Results for IOS-ROUTING-NO-AUTH and IOS-ROUTING-WEAK-AUTH.
    OSPF and EIGRP use link-local packets (TTL 1): only a device on the link can inject
    routes, so they are never internet-exposed. BGP is TCP to the neighbor's address, so an
    unauthenticated session to a public address is."""
    adj = _routing_auth(blocks, interfaces)
    if not adj:
        why = "no OSPF, EIGRP or BGP adjacency in the config"
        return [result("IOS-ROUTING-NO-AUTH", "n/a", why), result("IOS-ROUTING-WEAK-AUTH", "n/a", why)]
    no_auth = [a for a in adj if a["grade"] in ("none", "clear")]
    weak = [a for a in adj if a["grade"] in ("md5", "unset")]
    strong = [a for a in adj if a["grade"] == "strong"]
    out = []
    if no_auth:
        out.append(result("IOS-ROUTING-NO-AUTH", "fail", "No authentication: " + _adj_list(no_auth),
                          exposed=any(a["public"] for a in no_auth)))
    else:
        out.append(result("IOS-ROUTING-NO-AUTH", "pass", f"all {len(adj)} adjacencies authenticate: "
                          + _adj_list(adj)))
    if weak:
        out.append(result("IOS-ROUTING-WEAK-AUTH", "fail", "MD5 or no algorithm set: " + _adj_list(weak),
                          exposed=any(a["public"] for a in weak)))
    elif strong:
        out.append(result("IOS-ROUTING-WEAK-AUTH", "pass", "HMAC-SHA or AES-CMAC: " + _adj_list(strong)))
    else:
        out.append(result("IOS-ROUTING-WEAK-AUTH", "n/a", "no authenticated adjacency to grade"))
    return out
