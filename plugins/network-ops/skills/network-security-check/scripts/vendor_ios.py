# ============================================================
# Script:       vendor_ios.py
# Purpose:      Cisco IOS / IOS-XE: facts (interfaces, internet exposure, features) and
#               config checks from a saved running config. Every check returns a result
#               (pass, fail, n/a, not-visible); routing authentication is in ios_routing.py,
#               AAA, timeouts, banner, NTP, syslog depth and SNMP version in ios_mgmt.py,
#               CoPP and edge interface services in ios_cp.py, anti-spoofing and eBGP in ios_edge.py,
#               layer 2 and HSRP/VRRP/GLBP in ios_l2.py.
# Author:       G Talks Tech
# Notes:        Read-only. Check IDs and sources live in settings/checks.yaml.
# ============================================================
import re
from pathlib import Path

import ios_cp
import ios_edge
import ios_l2
import ios_mgmt
import ios_routing
from common import feature, fails, is_public, is_segmented, mask_to_prefix, new_facts, result
from ios_routing import _routing_auth  # noqa: F401  (kept importable here for the tests)
from parsers import ios_acl_lines, ios_blocks

CHECKS = ("IOS-HTTP-SERVER", "IOS-TELNET", "IOS-SSH-V1", "IOS-VTY-ACL", "IOS-SNMP-COMMUNITY",
          "IOS-PASSWORD-STORAGE", "IOS-SMART-INSTALL", "IOS-NO-REMOTE-LOG", "IOS-ROUTING-NO-AUTH",
          "IOS-ROUTING-WEAK-AUTH", "IOS-SEGMENT-ROUTED") + ios_mgmt.CHECKS + ios_cp.CHECKS + ios_edge.CHECKS \
    + ios_l2.CHECKS
WEAK_COMMUNITIES = {"public", "private", "cisco", "community", "snmp", "admin", "secret"}


PRIVATE_DENY = re.compile(r"^deny\s+ip\s+\S+(\s+\S+)?\s+(any|10\.0\.0\.0 0\.255\.255\.255|"
                          r"172\.16\.0\.0 0\.15\.255\.255|192\.168\.0\.0 0\.0\.255\.255)(\s|$)")


def _acl_is_open(blocks, name):
    """True when an ACL reaches a permit ip any any without first denying the internal ranges
    (deny ip ... any, or a deny to 10/8, 172.16/12 or 192.168/16)."""
    lines = ios_acl_lines(blocks, name) or []
    for l in lines:
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
        facts["results"] = [result(c, "not-visible", "config is nearly empty") for c in CHECKS]
        return facts, []
    res = []

    # --- management plane ---
    http_lines = [h for h in top if re.match(r"ip http (secure-)?server$", h)]
    http_acl = any(h.startswith("ip http access-class") for h in top)
    feature(facts, "http_server", bool(http_lines), internet and not http_acl,
            "ip http server" if http_lines else None)
    if http_lines:
        res.append(result("IOS-HTTP-SERVER",
                          "fail", "Web UI is on" + (" and the device has an internet-facing interface with no "
                                                    "ip http access-class" if internet and not http_acl else ""),
                          http_lines, exposed=internet and not http_acl))
    else:
        res.append(result("IOS-HTTP-SERVER", "pass", "web UI is off",
                          [h for h in top if re.match(r"no ip http (secure-)?server$", h)]))

    vty = [(h, ch) for h, ch in blocks if h.startswith("line vty")
           and "transport input none" not in ch]
    no_acl = [h for h, ch in vty if not any(c.startswith("access-class") for c in ch)]
    no_tin = [h for h, ch in vty if not any(c.startswith("transport input") for c in ch)]
    if no_tin:
        facts["notes"].append(f"{', '.join(no_tin)}: no 'transport input' line. The default (and whether "
                              "telnet is allowed) depends on the release: set 'transport input ssh'.")
    telnet = []
    for h, ch in vty:
        tin = [c for c in ch if c.startswith("transport input")]
        if any(re.search(r"\b(telnet|all)\b", c) for c in tin):
            telnet.append(h)
            res.append(result("IOS-TELNET", "fail", f"{h}: {tin[0]}", [h] + tin,
                              exposed=internet and h in no_acl, where=h))
    if not vty:
        for c in ("IOS-TELNET", "IOS-VTY-ACL", "IOS-SSH-V1"):
            res.append(result(c, "n/a", "no vty line accepts remote logins"))
    else:
        if not telnet:
            res.append(result("IOS-TELNET", "pass", "no vty line allows telnet",
                              [f"{h}: {c}" for h, ch in vty for c in ch if c.startswith("transport input")]))
        if no_acl:
            res.append(result("IOS-VTY-ACL", "fail", "No access-class on: " + ", ".join(no_acl), no_acl,
                              exposed=internet))
        else:
            res.append(result("IOS-VTY-ACL", "pass", "every vty line has an access-class",
                              [f"{h}: {c}" for h, ch in vty for c in ch if c.startswith("access-class")]))
    # IOS-XE 17.x runs SSH v2 only and writes no "ip ssh version 2" line, so the saved
    # "show ip ssh" output decides when it is there ("version 2.0" = v2 only, "1.99" = both).
    ssh_shown = _ssh_version(dev)
    if vty:
        ssh_used = not all(any(re.search(r"transport input (none|telnet)$", c) for c in ch) for _, ch in vty)
        if not ssh_used:
            res.append(result("IOS-SSH-V1", "n/a", "no vty line accepts SSH"))
        elif "ip ssh version 2" in top or ssh_shown == "2.0":
            res.append(result("IOS-SSH-V1", "pass", "SSH version 2 only",
                              ["ip ssh version 2"] if "ip ssh version 2" in top else
                              ["show ip ssh: SSH Enabled - version 2.0"]))
        else:
            res.append(result("IOS-SSH-V1", "fail", "No 'ip ssh version 2' line" + (
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
        res.append(result("IOS-SNMP-COMMUNITY", "fail",
                          "; ".join(f"community {n + 1}: {', '.join(w)}" for n, (_, w, _) in enumerate(snmp_bad)),
                          [l for l, _, _ in snmp_bad], exposed=internet and any(x[2] for x in snmp_bad)))
    elif communities:
        res.append(result("IOS-SNMP-COMMUNITY", "pass",
                          f"{len(communities)} community line(s), read-only, bound to an ACL, not a default name",
                          communities))
    else:
        res.append(result("IOS-SNMP-COMMUNITY", "n/a", "no SNMP v1/v2c community configured"))

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
    creds = [h for h in top if re.match(r"(enable (password|secret)|username \S+ .*(password|secret)) ", h)]
    if weak:
        res.append(result("IOS-PASSWORD-STORAGE", "fail", "; ".join(weak), [], exposed=False))
    elif creds:
        res.append(result("IOS-PASSWORD-STORAGE", "pass",
                          f"{len(creds)} enable/user secret(s), none type 0, 5 or 7", creds))
    else:
        res.append(result("IOS-PASSWORD-STORAGE", "n/a", "no enable secret or local user password in the config"))

    if "vstack" in top:
        feature(facts, "smart_install", True, internet)
        res.append(result("IOS-SMART-INSTALL", "fail", "vstack is configured", ["vstack"], exposed=internet))
    elif "no vstack" in top:
        res.append(result("IOS-SMART-INSTALL", "pass", "Smart Install is off", ["no vstack"]))
    elif dev.get("_is_switch"):
        facts["notes"].append("Smart Install state is not in the config. Run 'show vstack config' "
                              "on switches to confirm it is disabled.")
        res.append(result("IOS-SMART-INSTALL", "not-visible", "Smart Install state is not in the config: "
                          "needs 'show vstack config'"))
    else:
        res.append(result("IOS-SMART-INSTALL", "n/a", "model is not a known Catalyst switch (Smart Install is a switch feature)"))

    # --- routing protocol authentication (ios_routing.py) ---
    res += ios_routing.check(blocks, facts["interfaces"])

    log_hosts = [h for h in top if re.match(r"logging (host \S|\d)", h)]
    if log_hosts:
        res.append(result("IOS-NO-REMOTE-LOG", "pass", "remote syslog configured", log_hosts))
    else:
        res.append(result("IOS-NO-REMOTE-LOG", "fail", "No 'logging host' line", [], exposed=False))

    # --- AAA, timeouts, banner, NTP, syslog depth, SNMP version (ios_mgmt.py) ---
    res += ios_mgmt.check(blocks, top, internet)

    # --- control plane: CoPP, edge interface services, CDP/LLDP, legacy services (ios_cp.py) ---
    external = ios_cp.external_interfaces(blocks, facts["interfaces"])
    res += ios_cp.check(blocks, top, facts["interfaces"], external, dev)

    # --- edge anti-spoofing and eBGP session hygiene (ios_edge.py) ---
    res += ios_edge.check(blocks, external)

    # --- layer 2 and first-hop redundancy (ios_l2.py) ---
    res += ios_l2.check(blocks, top, dev)

    # --- segmentation: a segmented SVI routing to other SVIs in the same VRF with no ACL ---
    svis = [i for i in facts["interfaces"] if re.match(r"[Vv]lan\d+$", i["name"]) and i["ips"]
            and not i["shutdown"]]
    seg = [s for s in svis if is_segmented(s["vlan_name"], s["description"])]
    for s in seg:
        if s["acl_in"] and not _acl_is_open(blocks, s["acl_in"]):
            continue
        peers = [p for p in svis if p is not s and p["vrf"] == s["vrf"]
                 and not is_segmented(p["vlan_name"], p["description"])]
        if not peers:
            continue
        label = s["vlan_name"] or s["description"]
        acl_txt = f"ACL {s['acl_in']} permits ip any any" if s["acl_in"] else "no inbound ACL"
        res.append(result(
            "IOS-SEGMENT-ROUTED", "fail",
            f"{s['name']} ({label}, {s['ips'][0]}) has {acl_txt} and shares VRF '{s['vrf']}' with "
            + ", ".join(f"{p['name']} ({p['vlan_name'] or p['description'] or 'no name'})" for p in peers[:6]),
            [f"interface {s['name']}"], exposed=False, where=s["name"]))
    if not seg:
        res.append(result("IOS-SEGMENT-ROUTED", "n/a", "no routed SVI with an IoT, guest or OT name"))
    elif not any(r["check"] == "IOS-SEGMENT-ROUTED" for r in res):
        res.append(result("IOS-SEGMENT-ROUTED", "pass", "segmented SVIs are filtered or in their own VRF",
                          [f"interface {s['name']}" for s in seg]))

    facts["internet_facing"] = internet
    facts["exposure_reason"] = ("public IP on " + ", ".join(facts["internet_interfaces"])) if internet else \
        "no interface with a public IP"
    facts["results"] = res
    return facts, fails(res)
