# ============================================================
# Script:       ios_l2.py
# Purpose:      Cisco IOS / IOS-XE layer 2 and first-hop checks: BPDU guard, DHCP snooping and
#               Dynamic ARP Inspection on access VLANs, port security / 802.1X / MAB, unused
#               ports, DTP, trunk native and allowed VLANs, VTP password, and HSRP / VRRP / GLBP
#               authentication.
# Author:       G Talks Tech
# Notes:        Read-only. Called by vendor_ios.analyze. Sources per check: settings/checks.yaml.
#               When the snapshot has 'show interfaces switchport', 'show interfaces status',
#               'show vlan brief' and 'show vtp status', those are the truth for mode, DTP
#               negotiation, VLANs and port state; otherwise the config and the STIG defaults
#               are used (DTP on, access and native VLAN 1). Layer 2 weaknesses need a host on
#               the same segment, so no result here is ever internet-exposed.
# ============================================================
import re
from pathlib import Path

from common import result

CHECKS = ("IOS-L2-BPDUGUARD", "IOS-L2-DHCP-SNOOPING", "IOS-L2-DAI", "IOS-L2-PORT-AUTH", "IOS-L2-UNUSED-PORTS",
          "IOS-L2-DTP", "IOS-L2-TRUNK-VLANS", "IOS-L2-VTP-AUTH", "IOS-FHRP-NO-AUTH")
L2_CHECKS = CHECKS[:-1]

ALL_VLANS = frozenset(range(1, 4095))
# DHCP snooping and DAI are asked for on user VLANs (STIG CISC-L2-000130 / -000150): VLANs whose
# name marks them as server, DMZ or printer VLANs are left out and named in the detail.
SERVER_VLAN = re.compile(r"serv|srv|dmz|print", re.I)
NOT_PORT = re.compile(r"(Vlan|Loopback|Tunnel|BDI|Null|Virtual|Dialer|Serial|Multilink|nve|Cellular|Async|NVI|"
                      r"LISP|Embedded|Wlan)", re.I)
SHORT = (("TwentyFiveGigE", "Twe"), ("TenGigabitEthernet", "Te"), ("FortyGigabitEthernet", "Fo"),
         ("HundredGigE", "Hu"), ("AppGigabitEthernet", "Ap"), ("GigabitEthernet", "Gi"),
         ("FastEthernet", "Fa"), ("Ethernet", "Et"), ("Port-channel", "Po"))


def short(name):
    """Ethernet0/1 -> Et0/1, the form the show commands print."""
    for long_, s in SHORT:
        if name.startswith(long_):
            return s + name[len(long_):]
    return name


def vlan_set(text):
    """'10,20-22' -> {10, 20, 21, 22}; 'ALL' / 'all' -> every VLAN; 'none' -> empty."""
    text = text.strip()
    if text.lower() == "all":
        return set(ALL_VLANS)
    if text.lower() in ("none", ""):
        return set()
    out = set()
    for part in text.split(","):
        part = part.strip()
        m = re.match(r"(\d+)(?:-(\d+))?$", part)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
            out |= set(range(lo, hi + 1))
    return out


def vlan_text(vlans):
    """{10, 20, 21, 22} -> '10,20-22'."""
    if set(vlans) == ALL_VLANS:
        return "ALL"
    out, run = [], []
    for v in sorted(vlans):
        if run and v == run[-1] + 1:
            run.append(v)
            continue
        if run:
            out.append(f"{run[0]}-{run[-1]}" if len(run) > 1 else str(run[0]))
        run = [v]
    if run:
        out.append(f"{run[0]}-{run[-1]}" if len(run) > 1 else str(run[0]))
    return ",".join(out)


# ---------- saved show output ----------

def _show(dev, name):
    folder = (dev or {}).get("_folder")
    f = Path(folder) / name if folder else None
    if not f or not f.exists():
        return None
    text = f.read_text(encoding="utf-8", errors="replace")
    return None if text.strip() in ("", "(no output)") else text


def parse_switchport(text):
    """'show interfaces switchport' -> {short name: {field: value}}."""
    out, cur = {}, None
    for line in (text or "").splitlines():
        m = re.match(r"Name:\s*(\S+)", line)
        if m:
            cur = out.setdefault(m.group(1), {})
            continue
        if cur is not None and ":" in line:
            k, v = line.split(":", 1)
            cur[k.strip()] = v.strip()
    return out


def parse_status(text):
    """'show interfaces status' -> {short name: status}. Columns are read by the header position,
    because the Name column can hold spaces."""
    lines = (text or "").splitlines()
    head = next((l for l in lines if l.startswith("Port") and "Status" in l and "Vlan" in l), None)
    if not head:
        return {}
    s, v = head.index("Status"), head.index("Vlan")
    out = {}
    for l in lines[lines.index(head) + 1:]:
        if not l.strip():
            continue
        out[l.split()[0]] = l[s:v].strip().split()[0] if l[s:v].strip() else ""
    return out


def parse_vlan_names(text):
    out = {}
    for l in (text or "").splitlines():
        m = re.match(r"(\d+)\s+(\S+)\s+(active|act/\S+|suspended)", l)
        if m:
            out[int(m.group(1))] = m.group(2)
    return out


def parse_vtp_mode(text):
    m = re.search(r"VTP Operating Mode\s*:\s*(\S+)", text or "")
    return m.group(1).lower() if m else None


# ---------- port model ----------

def _trunk_allowed(lines):
    allowed = None
    for c in lines:
        m = re.match(r"switchport trunk allowed vlan (add |remove |except )?(.+)", c)
        if not m:
            continue
        op, vl = (m.group(1) or "").strip(), vlan_set(m.group(2))
        if op == "add":
            allowed = (allowed if allowed is not None else set()) | vl
        elif op == "remove":
            allowed = (allowed if allowed is not None else set(ALL_VLANS)) - vl
        elif op == "except":
            allowed = set(ALL_VLANS) - vl
        else:
            allowed = vl
    return set(ALL_VLANS) if allowed is None else allowed


def ports(blocks, dev):
    """Every switchport on the device with its mode, VLANs and settings. Show output wins over
    the config where both say something. [] when the device has no switchport."""
    sw = parse_switchport(_show(dev, "show-interfaces-switchport.txt"))
    status = parse_status(_show(dev, "show-interfaces-status.txt"))
    is_l2 = any(v.get("Switchport") == "Enabled" for v in sw.values()) or bool((dev or {}).get("_is_switch")) or any(
        c.startswith("switchport") for h, ch in blocks if h.startswith("interface ") for c in ch)
    if not is_l2:
        return []
    out = []
    for h, ch in blocks:
        m = re.match(r"interface (\S+)$", h)
        if not m or NOT_PORT.match(m.group(1)):
            continue
        name = m.group(1)
        s = sw.get(short(name), {})
        if s.get("Switchport") == "Disabled" or (not s and ("no switchport" in ch
                                                             or any(c.startswith("ip address") for c in ch))):
            continue
        p = {"name": name, "lines": ch, "shutdown": "shutdown" in ch, "status": status.get(short(name)),
             "from_show": bool(s), "default_mode": False}
        mode = next((c.split(None, 2)[2] for c in ch if c.startswith("switchport mode ")), None)
        admin = s.get("Administrative Mode", "").lower()
        if admin:
            p["mode"] = ("access" if "access" in admin else "trunk" if admin == "trunk"
                         else "dynamic" if admin.startswith("dynamic") else admin)
            p["mode_text"] = admin
        else:
            p["mode"] = ("access" if mode == "access" else "trunk" if mode == "trunk"
                         else "dynamic" if mode is None or mode.startswith("dynamic") else mode)
            p["mode_text"] = mode or "dynamic (no switchport mode line)"
            p["default_mode"] = mode is None
        oper = s.get("Operational Mode", "").lower()
        p["trunking"] = p["mode"] == "trunk" or (p["mode"] == "dynamic" and oper == "trunk")
        neg = s.get("Negotiation of Trunking")
        if neg:
            p["dtp"] = neg.lower() == "on"
        else:
            p["dtp"] = p["mode"] == "dynamic" or (p["mode"] == "trunk" and "switchport nonegotiate" not in ch)
        av = re.match(r"(\d+)", s.get("Access Mode VLAN", ""))
        cfg_av = next((c.split()[-1] for c in ch if c.startswith("switchport access vlan ")), None)
        p["access_vlan"] = int(av.group(1)) if av else int(cfg_av) if cfg_av and cfg_av.isdigit() else 1
        nv = re.match(r"(\d+)", s.get("Trunking Native Mode VLAN", ""))
        cfg_nv = next((c.split()[-1] for c in ch if c.startswith("switchport trunk native vlan ")
                       and c.split()[-1].isdigit()), None)
        p["native_vlan"] = int(nv.group(1)) if nv else int(cfg_nv) if cfg_nv else 1
        p["native_tagged"] = (s.get("Administrative Native VLAN tagging", "").lower() == "enabled"
                              or "switchport trunk native vlan tag" in ch)
        en = s.get("Trunking VLANs Enabled")
        p["allowed"] = vlan_set(en) if en and p["trunking"] else _trunk_allowed(ch)
        out.append(p)
    return out


def _portfast(p, top):
    ch = p["lines"]
    if any(re.match(r"spanning-tree portfast( edge)?( trunk)? disable$", c) or c == "no spanning-tree portfast"
           for c in ch):
        return False
    if any(re.match(r"spanning-tree portfast( edge)?$", c) for c in ch):
        return True
    return any(re.match(r"spanning-tree portfast( edge)? default$", h) for h in top)


# ---------- checks ----------

def _bpduguard(access, top):
    glob = [h for h in top if re.match(r"spanning-tree portfast( edge)? bpduguard default$", h)]
    bad, good = [], []
    for p in access:
        ch = p["lines"]
        if "spanning-tree bpduguard disable" in ch:
            bad.append((p, "spanning-tree bpduguard disable"))
        elif "spanning-tree bpduguard enable" in ch:
            good.append(f"{p['name']}: spanning-tree bpduguard enable")
        elif glob and _portfast(p, top):
            good.append(f"{p['name']}: portfast with {glob[0]}")
        else:
            bad.append((p, "no portfast" if glob else "no bpduguard"))
    if bad:
        return result("IOS-L2-BPDUGUARD", "fail", "Access ports without BPDU guard: " + "; ".join(
            f"{p['name']} ({w})" for p, w in bad), [f"interface {p['name']}" for p, _ in bad] + glob,
            where=", ".join(p["name"] for p, _ in bad))
    return result("IOS-L2-BPDUGUARD", "pass", f"BPDU guard covers all {len(access)} active access port(s)", good)


def _vlan_feature(cid, label, cmd, top, user_vlans, skipped):
    on = re.compile(rf"{cmd} vlan (.+)")
    covered = set()
    for h in top:
        m = on.match(h)
        if m:
            covered |= vlan_set(m.group(1))
    glob_ok = cmd != "ip dhcp snooping" or "ip dhcp snooping" in top
    missing = set(user_vlans) - covered if glob_ok else set(user_vlans)
    skip = f" (server VLANs not graded: {vlan_text(skipped)})" if skipped else ""
    lines = [h for h in top if h == cmd or on.match(h)]
    if missing:
        why = "" if glob_ok else f"no global '{cmd}'; "
        return result(cid, "fail", f"No {label} on access VLAN(s) {vlan_text(missing)}: {why}"
                      f"{len(covered & set(user_vlans))} of {len(user_vlans)} covered{skip}", lines,
                      where="VLAN " + vlan_text(missing))
    return result(cid, "pass", f"{label} on every user access VLAN ({vlan_text(user_vlans)}){skip}", lines)


def _port_auth(access):
    pat = re.compile(r"(switchport port-security$|switchport port-security maximum|authentication port-control auto|"
                     r"access-session port-control auto|dot1x pae authenticator|mab$|service-policy type control)")
    bad, good = [], []
    for p in access:
        hit = [c for c in p["lines"] if pat.match(c)]
        if hit:
            good.append(f"{p['name']}: {hit[0]}")
        else:
            bad.append(p)
    if bad:
        return result("IOS-L2-PORT-AUTH", "fail", "Access ports with no port security, 802.1X or MAB: "
                      + ", ".join(p["name"] for p in bad) + ". If a NAC system controls these ports another way, "
                      "record it as accepted risk.", [f"interface {p['name']}" for p in bad],
                      where=", ".join(p["name"] for p in bad))
    return result("IOS-L2-PORT-AUTH", "pass", "every active access port has port security, 802.1X or MAB", good)


def _unused(swports, trunk_vlans, have_status):
    unused = [p for p in swports if not p["trunking"] and (p["shutdown"] or p["status"] in ("notconnect", "disabled"))]
    if not unused:
        return result("IOS-L2-UNUSED-PORTS", "n/a", "no unused access port" + (
            "" if have_status else " shut down in the config (no 'show interfaces status' to find idle ports)"))
    bad, good = [], []
    for p in unused:
        why = []
        if not p["shutdown"]:
            why.append(f"not shut down (status {p['status']})")
        if p["access_vlan"] == 1:
            why.append("in VLAN 1")
        elif p["access_vlan"] in trunk_vlans:
            why.append(f"VLAN {p['access_vlan']} is carried on a trunk")
        if why:
            bad.append((p, why))
        else:
            good.append(f"{p['name']}: shutdown, VLAN {p['access_vlan']}")
    if bad:
        return result("IOS-L2-UNUSED-PORTS", "fail", "Unused ports left usable: " + "; ".join(
            f"{p['name']} ({', '.join(w)})" for p, w in bad), [f"interface {p['name']}" for p, _ in bad],
            where=", ".join(p["name"] for p, _ in bad))
    return result("IOS-L2-UNUSED-PORTS", "pass", f"all {len(unused)} unused port(s) are shut down in a VLAN "
                  "that no trunk carries", good)


def _dtp(live):
    bad = [p for p in live if p["dtp"]]
    if not live:
        return result("IOS-L2-DTP", "n/a", "no switchport that is not shut down")
    if bad:
        def why(p):
            if p["mode"] == "trunk":
                return f"{p['name']} (trunk without switchport nonegotiate)"
            return f"{p['name']} ({p['mode_text']})"
        default = [p["name"] for p in bad if p["default_mode"]]
        return result("IOS-L2-DTP", "fail", "DTP negotiation is on: " + "; ".join(map(why, bad)) + (
            f". No 'switchport mode' line on {', '.join(default)}: DTP is on by default." if default else ""),
            [f"interface {p['name']}" for p in bad], where=", ".join(p["name"] for p in bad))
    return result("IOS-L2-DTP", "pass", f"no DTP on any of {len(live)} live switchport(s)",
                  [f"{p['name']}: {p['mode_text']}, negotiation off" for p in live])


def _trunk_vlans(trunks, user_vlans, top):
    if not trunks:
        return result("IOS-L2-TRUNK-VLANS", "n/a", "no active trunk")
    tag_all = "vlan dot1q tag native" in top
    bad, good = [], []
    for p in trunks:
        why = []
        tagged = tag_all or p["native_tagged"]
        if p["native_vlan"] == 1 and not tagged:
            why.append("native VLAN 1 untagged" + ("" if 1 in p["allowed"] else ", though VLAN 1 is not allowed"))
        elif p["native_vlan"] in user_vlans and not tagged:
            why.append(f"native VLAN {p['native_vlan']} is also an access VLAN")
        if p["allowed"] == set(ALL_VLANS):
            why.append("all VLANs allowed")
        if why:
            bad.append((p, why))
        else:
            good.append(f"{p['name']}: native {p['native_vlan']}{' tagged' if tagged else ''}, "
                        f"allowed {vlan_text(p['allowed'])}")
    if bad:
        return result("IOS-L2-TRUNK-VLANS", "fail", "Trunk VLAN settings: " + "; ".join(
            f"{p['name']} ({', '.join(w)})" for p, w in bad), [f"interface {p['name']}" for p, _ in bad],
            where=", ".join(p["name"] for p, _ in bad))
    return result("IOS-L2-TRUNK-VLANS", "pass", "trunks use a native VLAN other than 1 (or tag it) and list "
                  "their VLANs", good)


def _vtp(swports, top, dev):
    show = _show(dev, "show-vtp-status.txt")
    mode = parse_vtp_mode(show)
    src = "show vtp status"
    if not mode:
        line = next((h for h in top if h.startswith("vtp mode ")), None)
        mode, src = (line.split()[2].lower(), line) if line else ("server", "no 'vtp mode' line (default server)")
    if mode in ("transparent", "off"):
        return result("IOS-L2-VTP-AUTH", "pass", f"VTP mode {mode}: the switch does not take VLANs from VTP "
                      "updates (STIG CISC-L2-000030 also asks for a password in transparent mode)",
                      [f"VTP Operating Mode: {mode} ({src})"])
    links = [p for p in swports if not p["shutdown"] and (p["trunking"] or p["mode"] == "dynamic")]
    if not links:
        return result("IOS-L2-VTP-AUTH", "n/a", f"VTP mode {mode}, but no trunk or DTP port: VTP messages "
                      "only travel on trunks", [f"VTP Operating Mode: {mode} ({src})"])
    if any(h.startswith("vtp password ") for h in top):
        return result("IOS-L2-VTP-AUTH", "pass", f"VTP mode {mode} with a password", ["vtp password <hidden>"])
    pw = _show(dev, "show-vtp-password.txt")
    if pw and re.search(r"not configured", pw, re.I):
        return result("IOS-L2-VTP-AUTH", "fail", f"VTP mode {mode} with no password on a switch with trunks "
                      f"({', '.join(p['name'] for p in links[:6])})", [f"VTP Operating Mode: {mode} ({src})"],
                      where="VTP")
    if pw and re.search(r"VTP Password", pw, re.I):
        return result("IOS-L2-VTP-AUTH", "pass", f"VTP mode {mode} with a password", ["VTP Password: <hidden>"])
    return result("IOS-L2-VTP-AUTH", "not-visible", f"VTP mode {mode} on a switch with trunks and no 'vtp password' "
                  "line; VTP settings are not always in the running config, so this needs 'show vtp password'")


def _safe_auth(line):
    """An FHRP authentication line with its key or string removed (common.mask does not cover
    'authentication text <string>' or 'md5 key-string <type> <key>')."""
    m = re.match(r"(.*?\bauthentication)\s+(.*)", line)
    if not m:
        return line
    head, rest = m.groups()
    if re.match(r"md5 key-chain \S+$", rest):
        return line
    for kw in ("md5 key-string", "md5", "text"):
        if rest.startswith(kw):
            return f"{head} {kw} <hidden>"
    return f"{head} <hidden>"


FHRP = (("HSRP", r"standby(?: (\d+))? ip\b", r"standby(?: (\d+))? authentication (.+)"),
        ("VRRP", r"vrrp (\d+) ip\b", r"vrrp (\d+) authentication (.+)"),
        ("GLBP", r"glbp (\d+) ip\b", r"glbp (\d+) authentication (.+)"))


def fhrp_groups(blocks):
    """[(interface, protocol, group, auth kind, safe auth line)] for every FHRP group on an
    interface that is not shut down. auth kind: md5, text or none."""
    out, v3 = [], []
    for h, ch in blocks:
        m = re.match(r"interface (\S+)$", h)
        if not m or "shutdown" in ch:
            continue
        for c in ch:
            mv = re.match(r"vrrp (\d+) address-family", c)
            if mv:
                v3.append(f"{m.group(1)} VRRPv3 {mv.group(1)}")
        for proto, grp, auth in FHRP:
            groups = {(mg.group(1) or "0") for c in ch for mg in [re.match(grp, c)] if mg}
            auths = {(ma.group(1) or "0"): ma.group(2) for c in ch for ma in [re.match(auth, c)] if ma}
            for g in sorted(groups, key=int):
                a = auths.get(g)
                kind = "none" if a is None else "md5" if a.startswith("md5") else "text"
                line = None if a is None else _safe_auth(
                    next(c for c in ch if re.match(auth, c) and (re.match(auth, c).group(1) or "0") == g))
                out.append((m.group(1), proto, g, kind, line))
    return out, v3


def _fhrp(blocks):
    groups, v3 = fhrp_groups(blocks)
    note = (f" VRRPv3 groups are not graded ({', '.join(v3)}): protect them with an ACL." if v3 else "")
    if not groups:
        return result("IOS-FHRP-NO-AUTH", "n/a", "no HSRP, VRRP or GLBP group" + (f".{note}" if v3 else ""))
    bad = [g for g in groups if g[3] != "md5"]
    if bad:
        return result("IOS-FHRP-NO-AUTH", "fail", "First-hop redundancy groups without MD5 authentication: "
                      + "; ".join(f"{i} {p} {g} ({'clear text' if k == 'text' else 'no authentication'})"
                                  for i, p, g, k, _ in bad) + "." + note,
                      [f"interface {i}: {l}" if l else f"interface {i}: {p} group {g}" for i, p, g, _, l in bad],
                      where=", ".join(sorted({i for i, *_ in bad})))
    return result("IOS-FHRP-NO-AUTH", "pass", f"all {len(groups)} FHRP group(s) use MD5 authentication." + note,
                  [f"interface {i}: {l}" for i, _, _, _, l in groups])


def check(blocks, top, dev):
    res = []
    swports = ports(blocks, dev)
    if not swports:
        res += [result(c, "n/a", "no switchport on this device") for c in L2_CHECKS[:-1]]
        res.append(_vtp(swports, top, dev) if _show(dev, "show-vtp-status.txt")
                   else result("IOS-L2-VTP-AUTH", "n/a", "no switchport on this device"))
        res.append(_fhrp(blocks))
        return res
    names = parse_vlan_names(_show(dev, "show-vlan-brief.txt"))
    for h, ch in blocks:
        m = re.match(r"vlan (\d+)$", h)
        if m:
            nm = next((c[5:].strip() for c in ch if c.startswith("name ")), None)
            if nm:
                names.setdefault(int(m.group(1)), nm)
    live = [p for p in swports if not p["shutdown"]]
    access = [p for p in live if not p["trunking"]]
    trunks = [p for p in live if p["trunking"]]
    acc_vlans = {p["access_vlan"] for p in access}
    skipped = {v for v in acc_vlans if SERVER_VLAN.search(names.get(v, ""))}
    user_vlans = acc_vlans - skipped
    trunk_vlans = set().union(*[p["allowed"] for p in trunks]) if trunks else set()

    if access:
        res.append(_bpduguard(access, top))
        res.append(_port_auth(access))
    else:
        res += [result(c, "n/a", "no active access port") for c in ("IOS-L2-BPDUGUARD", "IOS-L2-PORT-AUTH")]
    for cid, label, cmd in (("IOS-L2-DHCP-SNOOPING", "DHCP snooping", "ip dhcp snooping"),
                            ("IOS-L2-DAI", "Dynamic ARP Inspection", "ip arp inspection")):
        if user_vlans:
            res.append(_vlan_feature(cid, label, cmd, top, user_vlans, skipped))
        else:
            res.append(result(cid, "n/a", "no active access port in a user VLAN" + (
                f" (server VLANs not graded: {vlan_text(skipped)})" if skipped else "")))
    res.append(_unused(swports, trunk_vlans, any(p["status"] for p in swports)))
    res.append(_dtp(live))
    res.append(_trunk_vlans(trunks, acc_vlans, top))
    res.append(_vtp(swports, top, dev))
    res.append(_fhrp(blocks))
    return sorted(({**r, "exposed": False} for r in res), key=lambda r: CHECKS.index(r["check"]))
