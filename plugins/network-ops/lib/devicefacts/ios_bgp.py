# ============================================================
# Script:       ios_bgp.py
# Purpose:      Cisco IOS / IOS-XE BGP neighbors from a saved config, with peer-groups and
#               peer templates folded in. A device fact (which neighbors are eBGP, which
#               address families they carry) used to find the internet side and by the eBGP
#               config checks.
# Author:       G Talks Tech
# ============================================================
import re

from .net import is_public

UNICAST_AF = re.compile(r"(ipv4|ipv6)( vrf \S+)?$")
SESSION = re.compile(r"(remote-as|ttl-security|ebgp-multihop|disable-connected-check|password|ao|"
                     r"inherit peer-session|peer-group)\b")


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


def bgp_sessions(blocks, per_neighbor=False):
    """Every BGP neighbor (by address) in every unicast address family it is active in, with
    peer-group and template settings folded in. A list of dicts: neighbor, remote_as, local_as,
    ebgp, af, session (lines that apply to the TCP session) and policy (lines for this AF).
    per_neighbor=True: one entry per neighbor (af None, no policy), any address family; used for
    the TCP session itself (ios_routing.py authentication)."""
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
            if per_neighbor:    # one entry per neighbor, whatever address families it carries
                out.append({"neighbor": n, "remote_as": ras, "local_as": local_as, "af": None, "peer_group": pg,
                            "ebgp": ras != local_as and ras not in confed and ras != "internal",
                            "session": s_lines, "policy": [], "public": is_public(n)})
                continue
            afs = {a for (x, a) in pol if x in (n, pg) and "activate" in pol[(x, a)]}
            afs |= af_def.get(n, set())
            # 'bgp default ipv4-unicast' activates IPv4 neighbors only; an IPv6 neighbor needs an
            # explicit activate in each address family
            if n in top_def and not no_default_v4 and ":" not in n:
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
