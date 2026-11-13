# ============================================================
# Script:       ios_edge.py
# Purpose:      Cisco IOS / IOS-XE edge checks: anti-spoofing on external interfaces (uRPF or
#               an inbound ACL that drops private sources, BCP 38/84) and eBGP session hygiene
#               (import and export policy, maximum-prefix, GTSM, what the inbound prefix-list
#               lets in). eBGP neighbors are resolved through peer-groups and peer templates.
# Author:       G Talks Tech
# Notes:        Read-only. Called by vendor_ios.analyze. Sources per check: settings/checks.yaml.
#               IOS XE has no default maximum-prefix, GTSM or uRPF. Whether it applies RFC 8212
#               (no policy = no routes) by default was not verified, so a missing policy is a
#               finding on every release. iBGP and confederation peers are not graded.
# ============================================================
import ipaddress
import re

from common import NOT_PUBLIC, is_public, result
from parsers import ios_acl_lines

CHECKS = ("IOS-EDGE-NO-ANTISPOOF", "IOS-BGP-NO-POLICY", "IOS-BGP-MAX-PREFIX", "IOS-BGP-NO-GTSM",
          "IOS-BGP-INBOUND-PERMISSIVE")

RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
TOO_SPECIFIC_V4 = 24    # DISA CISC-RT-000570: reject prefixes longer than /24
UNICAST_AF = re.compile(r"(ipv4|ipv6)( vrf \S+)?$")
SESSION = re.compile(r"(remote-as|ttl-security|ebgp-multihop|disable-connected-check|password|"
                     r"inherit peer-session|peer-group)\b")


# ---------- anti-spoofing ----------

def _src(tokens):
    """Source network of an ACL entry's address tokens and how many tokens it used.
    None for an object-group or anything unreadable."""
    if not tokens:
        return None, 0
    if tokens[0] == "any":
        return ipaddress.ip_network("0.0.0.0/0"), 1
    if tokens[0] == "host" and len(tokens) > 1:
        return ipaddress.ip_network(f"{tokens[1]}/32"), 2
    if re.match(r"\d+\.\d+\.\d+\.\d+$", tokens[0]):
        if len(tokens) > 1 and re.match(r"\d+\.\d+\.\d+\.\d+$", tokens[1]):
            try:
                return ipaddress.ip_network(f"{tokens[0]}/{tokens[1]}", strict=False), 2
            except ValueError:
                return None, 2
        return ipaddress.ip_network(f"{tokens[0]}/32"), 1
    return None, 0


def acl_antispoof(blocks, name):
    """How an inbound ACL treats private (RFC 1918) source addresses: ('ok', why),
    ('open', why) or ('unknown', why). ok = every RFC 1918 source is denied by an 'ip' deny
    before any permit that could match it, or the ACL never permits such a source (implicit
    deny). Undefined ACL = IOS permits all."""
    lines = ios_acl_lines(blocks, name)
    if lines is None:
        return "open", f"ACL {name} is applied but not defined (IOS then permits all)"
    covered = set()
    for l in lines:
        t = l.split()
        if not t or t[0] not in ("permit", "deny"):
            continue
        extended = len(t) > 1 and not re.match(r"(any|host|\d+\.\d+\.\d+\.\d+)$", t[1])
        proto = t[1] if extended else "ip"
        src, _ = _src(t[2:] if extended else t[1:])
        if src is None:
            return "unknown", f"ACL {name}: '{l}' uses a source the check cannot read"
        if t[0] == "deny":
            if proto == "ip":
                covered |= {str(p) for p in RFC1918 if p.subnet_of(src)}
            continue
        missing = [p for p in RFC1918 if str(p) not in covered and p.overlaps(src)]
        if missing:
            return "open", f"ACL {name}: '{l}' comes before any deny of {', '.join(map(str, missing))} as a source"
    if covered:
        return "ok", f"ACL {name} denies {', '.join(sorted(covered))} as sources first"
    return "ok", f"ACL {name} permits only listed sources (implicit deny for the rest)"


def _antispoof(blocks, external):
    cfg = {h.split()[1]: ch for h, ch in blocks if h.startswith("interface ")}
    if not external:
        return result("IOS-EDGE-NO-ANTISPOOF", "n/a", "no internet-facing interface")
    bad, good, unknown = [], [], []
    for i in external:
        n, ch = i["name"], cfg.get(i["name"], [])
        urpf = [c for c in ch if re.match(r"ip verify unicast (source reachable-via|reverse-path)", c)]
        strict = [c for c in urpf if re.search(r"reachable-via rx|reverse-path", c)]
        loose = [c for c in urpf if "reachable-via any" in c and "allow-default" not in c]
        acl = i.get("acl_in")
        verdict, why = acl_antispoof(blocks, acl) if acl else ("open", "no inbound ACL")
        if strict or loose:
            good.append((n, f"{n}: {(strict or loose)[0]}" + ("" if strict else " (loose mode: drops sources "
                                                                    "with no route only)")))
        elif verdict == "ok":
            good.append((n, f"{n}: {why}"))
        elif verdict == "unknown":
            unknown.append((n, f"{n}: {why}"))
        else:
            extra = " and no uRPF" + (" ('allow-default' makes uRPF accept any source)" if urpf else "")
            bad.append((n, f"{n}: {why}{extra}"))
    if bad:
        return result("IOS-EDGE-NO-ANTISPOOF", "fail", "Spoofed private sources can enter: "
                      + "; ".join(w for _, w in bad), [f"interface {n}" for n, _ in bad]
                      + [f"interface {n}: ip access-group {i['acl_in']} in" for i in external for n, _ in bad
                         if i["name"] == n and i.get("acl_in")], exposed=True, where=", ".join(n for n, _ in bad))
    if unknown:
        return result("IOS-EDGE-NO-ANTISPOOF", "not-visible", "; ".join(w for _, w in unknown + good))
    return result("IOS-EDGE-NO-ANTISPOOF", "pass", "; ".join(w for _, w in good), [w for _, w in good])


# ---------- BGP ----------

def _af_name(line):
    m = re.match(r"address-family (\S+)(?: (unicast|multicast))?(?: vrf (\S+))?", line)
    if not m:
        return line
    if m.group(2) == "multicast" or m.group(1) not in ("ipv4", "ipv6"):
        return line[len("address-family "):]
    return m.group(1) + (f" vrf {m.group(3)}" if m.group(3) else "")


def _templates(ch):
    """{('session'|'policy', name): [lines]} from 'template peer-session/peer-policy' blocks."""
    out, cur = {}, None
    for c in ch:
        m = re.match(r"template peer-(session|policy) (\S+)$", c)
        if m:
            cur = (m.group(1), m.group(2))
            out[cur] = []
        elif c in ("exit-peer-session", "exit-peer-policy"):
            cur = None
        elif cur:
            out[cur].append(c)
    return out


def _tpl_lines(tpls, kind, name, depth=0):
    """A template's lines plus every template it inherits (its own lines win by coming first)."""
    if depth > 8 or (kind, name) not in tpls:
        return []
    lines = list(tpls[(kind, name)])
    for l in list(lines):
        m = re.match(rf"inherit peer-{kind} (\S+)", l)
        if m:
            lines += _tpl_lines(tpls, kind, m.group(1), depth + 1)
    return lines


def bgp_sessions(blocks):
    """Every BGP neighbor (by address) in every unicast address family it is active in, with
    peer-group and template settings folded in. A list of dicts: neighbor, remote_as, local_as,
    ebgp, af, session (lines that apply to the TCP session) and policy (lines for this AF)."""
    out = []
    for h, ch in blocks:
        mb = re.match(r"router bgp (\S+)", h)
        if not mb:
            continue
        local_as = mb.group(1)
        tpls = _templates(ch)
        no_default_v4 = "no bgp default ipv4-unicast" in ch
        confed = {a for c in ch if c.startswith("bgp confederation peers ") for a in c.split()[3:]}
        sess, pol, top_def, af_def = {}, {}, set(), {}
        af, in_tpl, in_af = "ipv4", False, False
        for c in ch:
            if re.match(r"template peer-(session|policy) ", c):
                in_tpl = True
                continue
            if c in ("exit-peer-session", "exit-peer-policy"):
                in_tpl = False
                continue
            if in_tpl:
                continue
            if c.startswith("address-family "):
                af, in_af = _af_name(c), True
                continue
            if c == "exit-address-family":
                af, in_af = "ipv4", False
                continue
            m = re.match(r"neighbor (\S+) (.+)", c)
            if not m:
                continue
            n, rest = m.groups()
            if SESSION.match(rest):
                sess.setdefault(n, []).append(rest)
                if rest.startswith("remote-as ") or re.match(r"peer-group \S+$", rest):
                    if in_af:
                        af_def.setdefault(n, set()).add(af)
                    else:
                        top_def.add(n)
            else:
                pol.setdefault((n, af), []).append(rest)
        for n in sess:
            if not re.match(r"[\d.:a-fA-F]+$", n) or ":" not in n and "." not in n:
                continue        # a peer-group or template name, not a neighbor address
            own = sess[n]
            pg = next((l.split()[1] for l in own if re.match(r"peer-group \S+$", l)), None)
            s_lines = own + (sess.get(pg, []) if pg else [])
            for l in list(s_lines):
                mt = re.match(r"inherit peer-session (\S+)", l)
                if mt:
                    s_lines += _tpl_lines(tpls, "session", mt.group(1))
            ras = next((l.split()[1] for l in s_lines if l.startswith("remote-as ")), None)
            if ras is None:
                continue
            afs = {a for (x, a) in pol if x in (n, pg) and "activate" in pol[(x, a)]}
            afs |= af_def.get(n, set())
            if n in top_def and not no_default_v4:
                afs.add("ipv4")
            for a in sorted(afs):
                if not UNICAST_AF.match(a):
                    continue
                p_lines = pol.get((n, a), []) + (pol.get((pg, a), []) if pg else [])
                for l in list(p_lines):
                    mt = re.match(r"inherit peer-policy (\S+)", l)
                    if mt:
                        p_lines += _tpl_lines(tpls, "policy", mt.group(1))
                out.append({"neighbor": n, "remote_as": ras, "local_as": local_as, "af": a, "peer_group": pg,
                            "ebgp": ras != local_as and ras not in confed and ras != "internal",
                            "session": s_lines, "policy": p_lines, "public": is_public(n)})
    return out


def _filters(lines, direction):
    return [l for l in lines if re.match(rf"(prefix-list|route-map|filter-list|distribute-list) \S+ {direction}$", l)]


def prefix_lists(top):
    """{(family, name): [(action, network, ge, le, line)]} in sequence order."""
    raw = {}
    for h in top:
        m = re.match(r"(ip|ipv6) prefix-list (\S+) (?:seq (\d+) )?(permit|deny) (\S+)(.*)", h)
        if not m:
            continue
        fam, name, seq, action, net, rest = m.groups()
        try:
            network = ipaddress.ip_network(net, strict=False)
        except ValueError:
            continue
        ge = re.search(r"\bge (\d+)", rest)
        le = re.search(r"\ble (\d+)", rest)
        raw.setdefault((fam, name), []).append((int(seq) if seq else 10 ** 6 + len(raw.get((fam, name), [])),
                                                action, network, int(ge.group(1)) if ge else None,
                                                int(le.group(1)) if le else None, h))
    return {k: [e[1:] for e in sorted(v, key=lambda e: e[0])] for k, v in raw.items()}


def _range(net, ge, le):
    full = net.max_prefixlen
    if ge is None and le is None:
        return net.prefixlen, net.prefixlen
    if ge is not None and le is not None:
        return ge, le
    if ge is not None:
        return ge, full
    return net.prefixlen, le


def pl_permits(entries, probe):
    """First-match evaluation of a prefix-list for one route. Implicit deny at the end."""
    for action, net, ge, le, _ in entries:
        if net.version != probe.version or not probe.subnet_of(net):
            continue
        lo, hi = _range(net, ge, le)
        if lo <= probe.prefixlen <= hi:
            return action == "permit"
    return False


def pl_leaks(entries):
    """Routes a prefix-list provably accepts that it should not: bogon space (the private,
    loopback, link-local, CGNAT, multicast and reserved ranges in common.NOT_PUBLIC) and IPv4
    prefixes longer than /24. Only entries with ge/le are graded for length: an exact entry for
    one long prefix is a deliberate exception. [(route, why, line)]."""
    out, seen = [], set()
    for action, net, ge, le, line in entries:
        if action != "permit":
            continue
        lo, hi = _range(net, ge, le)
        for b in NOT_PUBLIC:
            if b.version != net.version or not net.overlaps(b):
                continue
            base = net if net.subnet_of(b) else b
            length = max(lo, base.prefixlen)
            if length > hi:
                continue
            probe = ipaddress.ip_network(f"{base.network_address}/{length}")
            if pl_permits(entries, probe) and ("bogon", str(b)) not in seen:
                seen.add(("bogon", str(b)))
                out.append((probe, f"bogon {b}", line))
        if net.version == 4 and (ge is not None or le is not None) and hi > TOO_SPECIFIC_V4:
            probe = ipaddress.ip_network(f"{net.network_address}/{max(lo, TOO_SPECIFIC_V4 + 1)}")
            if pl_permits(entries, probe) and ("long", line) not in seen:
                seen.add(("long", line))
                out.append((probe, f"longer than /{TOO_SPECIFIC_V4}", line))
    return out


def _label(s):
    return f"{s['neighbor']} (AS {s['remote_as']}" + (f", {s['af']}" if s["af"] != "ipv4" else "") + ")"


def _bgp(blocks, top):
    sessions = [s for s in bgp_sessions(blocks) if s["ebgp"]]
    if not sessions:
        why = "no eBGP neighbor in the config"
        return [result(c, "n/a", why) for c in CHECKS[1:]]
    res = []

    # import and export policy (RFC 8212)
    bad, good = [], []
    for s in sessions:
        fin, fout = _filters(s["policy"], "in"), _filters(s["policy"], "out")
        miss = [w for w, f in (("no inbound filter", fin), ("no outbound filter", fout)) if not f]
        (bad if miss else good).append((s, miss, fin + fout))
    if bad:
        res.append(result("IOS-BGP-NO-POLICY", "fail", "eBGP without import/export policy: " + "; ".join(
            f"{_label(s)}: {', '.join(m)}" for s, m, _ in bad),
            [f"neighbor {s['neighbor']} remote-as {s['remote_as']}" for s, _, _ in bad],
            exposed=any(s["public"] for s, _, _ in bad), where=", ".join(s["neighbor"] for s, _, _ in bad)))
    else:
        res.append(result("IOS-BGP-NO-POLICY", "pass", f"all {len(sessions)} eBGP session(s) filter both ways",
                          [f"neighbor {s['neighbor']} {f}" for s, _, fl in good for f in fl]))

    # maximum-prefix
    bad = [s for s in sessions if not any(l.startswith("maximum-prefix ") for l in s["policy"])]
    if bad:
        res.append(result("IOS-BGP-MAX-PREFIX", "fail", "No maximum-prefix: " + "; ".join(map(_label, bad)),
                          [f"neighbor {s['neighbor']} remote-as {s['remote_as']}" for s in bad],
                          exposed=any(s["public"] for s in bad), where=", ".join(s["neighbor"] for s in bad)))
    else:
        res.append(result("IOS-BGP-MAX-PREFIX", "pass", "every eBGP session has a maximum-prefix limit",
                          [f"neighbor {s['neighbor']} {l}" for s in sessions for l in s["policy"]
                           if l.startswith("maximum-prefix ")]))

    # GTSM on single-hop eBGP (per session, not per AF)
    by_n = {}
    for s in sessions:
        by_n.setdefault(s["neighbor"], s)
    single = [s for s in by_n.values()
              if not any(re.match(r"(ebgp-multihop|disable-connected-check)\b", l) for l in s["session"])]
    bad = [s for s in single if not any(l.startswith("ttl-security hops") for l in s["session"])]
    if not single:
        res.append(result("IOS-BGP-NO-GTSM", "n/a", "every eBGP session is multihop (GTSM is for directly "
                          "connected peers)"))
    elif bad:
        res.append(result("IOS-BGP-NO-GTSM", "fail", "No ttl-security hops on directly connected eBGP: "
                          + "; ".join(map(_label, bad)),
                          [f"neighbor {s['neighbor']} remote-as {s['remote_as']}" for s in bad],
                          exposed=any(s["public"] for s in bad), where=", ".join(s["neighbor"] for s in bad)))
    else:
        res.append(result("IOS-BGP-NO-GTSM", "pass", "every directly connected eBGP session uses GTSM",
                          [f"neighbor {s['neighbor']} {l}" for s in single for l in s["session"]
                           if l.startswith("ttl-security")]))

    # what the inbound prefix-list lets in (public neighbors only: private eBGP, an MPLS VPN for
    # example, carries private and long prefixes on purpose)
    pls = prefix_lists(top)
    graded, leaks, skipped = [], [], []
    for s in sessions:
        if not s["public"]:
            continue
        names = [l.split()[1] for l in s["policy"] if re.match(r"prefix-list \S+ in$", l)]
        fam = "ipv6" if s["af"].startswith("ipv6") else "ip"
        if not names or (fam, names[0]) not in pls:
            skipped.append(s)
            continue
        graded.append((s, names[0]))
        for probe, why, line in pl_leaks(pls[(fam, names[0])]):
            leaks.append((s, names[0], probe, why, line))
    if leaks:
        res.append(result("IOS-BGP-INBOUND-PERMISSIVE", "fail", "Inbound prefix-list accepts routes it should "
                          "not: " + "; ".join(f"{n} from {s['neighbor']} accepts {p} ({w})"
                                              for s, n, p, w, _ in leaks),
                          sorted({l for *_, l in leaks}), exposed=True,
                          where=", ".join(sorted({s["neighbor"] for s, *_ in leaks}))))
    elif graded:
        res.append(result("IOS-BGP-INBOUND-PERMISSIVE", "pass", "inbound prefix-lists reject bogons and "
                          f"prefixes longer than /{TOO_SPECIFIC_V4}: "
                          + ", ".join(f"{n} from {s['neighbor']}" for s, n in graded),
                          [l for _, n in graded for k in pls if k[1] == n for *_, l in pls[k]]))
    else:
        res.append(result("IOS-BGP-INBOUND-PERMISSIVE", "n/a", "no public eBGP neighbor with an inbound "
                          "prefix-list the check can read" + (" (route-map or no filter: "
                                                             + ", ".join(s["neighbor"] for s in skipped) + ")"
                                                             if skipped else "")))
    return res


def check(blocks, external):
    top = [h for h, _ in blocks]
    return [_antispoof(blocks, external)] + _bgp(blocks, top)
