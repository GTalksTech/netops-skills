# ============================================================
# Script:       vendor_ios.py
# Purpose:      Cisco IOS / IOS-XE: facts (interfaces, internet exposure, features) and
#               config checks from a saved running config.
# Author:       G Talks Tech
# Notes:        Read-only. Check IDs and sources live in settings/checks.yaml.
# ============================================================
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
