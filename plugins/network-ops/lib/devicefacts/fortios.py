# ============================================================
# Script:       fortios.py
# Purpose:      FortiGate (FortiOS) device facts from the saved "show" output: interfaces and
#               zones (which face the internet and the lines that show it) and the features
#               CVE conditions name (FortiManager access, the admin web UI, SSL VPN, OSPF, iBGP
#               neighbors; GCP OS Login is never in the config, so always unknown).
# Author:       G Talks Tech
# Notes:        Read-only text parsing. Multi-VDOM configs ("config global" + "config vdom /
#               edit X") are flattened: see section().
# ============================================================
from .facts import feature, internet_evidence, new_facts, unknown
from .net import is_public, looks_internet, mask_to_prefix
from .parsers import fortios_tree

FEATURES = ("fgfm", "admin_web", "sslvpn", "ospf", "ibgp", "gcp_os_login")


def _scopes(tree):
    """Where a config section can sit: top level, 'config global' (multi-VDOM: interfaces, admins)
    or inside 'config vdom / edit X' (policies, VIPs, routing)."""
    return [tree, tree.get("global", {})] + list(tree.get("vdom", {}).values())


def section(tree, name):
    """A config section, wherever it sits (_scopes), merged."""
    out = {}
    for scope in _scopes(tree):
        out.update(scope.get(name, {}))
    return out


def has_section(tree, name):
    """Whether the saved output has this config section at all."""
    return any(name in scope for scope in _scopes(tree))


def _hidden(facts, name, sect, what):
    """A feature whose section is not in the saved output: unknown, never off ('show' prints only
    what the snapshot account can see)."""
    unknown(facts, name, f"no 'config {sect}' in the saved output: the snapshot account may not see {what}")


def _access(itf):
    return f"{itf['name']}: set allowaccess {' '.join(itf['allowaccess']) or '(none)'}"


def _routing(facts, tree):
    """OSPF (ospfd) and iBGP neighbors (bgpd). 'show' prints a router section only when the account
    can see it: no section is unknown, never off."""
    if not has_section(tree, "router ospf"):
        _hidden(facts, "ospf", "router ospf", "routing")
    else:
        ospf = section(tree, "router ospf")
        parts = [k for k in ("area", "network", "ospf-interface") if ospf.get(k)]
        prefixes = [_set("prefix", n["prefix"]) for n in (ospf.get("network") or {}).values() if n.get("prefix")]
        feature(facts, "ospf", bool(parts), False, None,
                ["config router ospf"] + ([_set("router-id", ospf["router-id"])] if ospf.get("router-id") else [])
                + prefixes,
                "OSPF configured: " + ", ".join(parts) if parts else
                "no area, network or ospf-interface under 'config router ospf'")
    if not has_section(tree, "router bgp"):
        _hidden(facts, "ibgp", "router bgp", "routing")
    else:
        bgp = section(tree, "router bgp")
        local = (bgp.get("as") or [""])[0]
        peers = [(name, cfg) for k in ("neighbor", "neighbor-group") for name, cfg in (bgp.get(k) or {}).items()
                 if isinstance(cfg, dict)]
        internal = [(n, c) for n, c in peers if local not in ("", "0") and (c.get("remote-as") or [""])[0] == local]
        head = ["config router bgp"] + ([_set("as", bgp["as"])] if bgp.get("as") else [])
        shown = [ln for n, c in (internal or peers)
                 for ln in (f'edit "{n}"', _set("remote-as", c.get("remote-as") or []))]
        feature(facts, "ibgp", bool(internal), False, None, head + shown,
                f"iBGP neighbor in the local AS {local}: " + ", ".join(n for n, _ in internal) if internal else
                f"no BGP neighbor or neighbor-group in the local AS {local or '(no set as)'}")


def _set(key, values):
    """A 'set' line as the config shows it: empty and spaced values quoted again."""
    shown = ["''" if v == "" else f'"{v}"' if " " in v else v for v in values]
    return " ".join(["set", key] + shown)


def read(text, dev=None):
    tree = fortios_tree(text)
    facts = new_facts()
    facts["hostname"] = (section(tree, "system global").get("hostname") or [None])[0]

    ifaces = section(tree, "system interface")
    zones = section(tree, "system zone")
    internet_if = set()
    for name, cfg in ifaces.items():
        ip = cfg.get("ip", [])
        addr = f"{ip[0]}/{mask_to_prefix(ip[1])}" if len(ip) >= 2 else None
        public = bool(addr and is_public(addr))
        alias = (cfg.get("alias") or [""])[0]
        why = ("set role wan" if cfg.get("role") == ["wan"] else "public IP" if public else
               "name" if looks_internet(name) or looks_internet(alias) else None)
        itf = {"name": name, "ips": [addr] if addr else [], "public": public,
               "role": (cfg.get("role") or [None])[0], "alias": (cfg.get("alias") or [None])[0],
               "allowaccess": cfg.get("allowaccess", [])}
        facts["interfaces"].append(itf)
        if why and cfg.get("status") != ["down"]:
            internet_if.add(name)
            internet_evidence(itf, [f'edit "{name}"'] + [f"set {k} {' '.join(cfg[k])}" for k in ("role", "ip", "alias")
                                                         if k in cfg], why)
    zone_proof = []
    for zname, z in zones.items():
        members = set(z.get("interface", []))
        if members & internet_if or looks_internet(zname):
            internet_if.add(zname)
            zone = {"name": zname}
            internet_evidence(zone, [f'edit "{zname}"', f"set interface {' '.join(z.get('interface', []))}"],
                              "zone with an internet-facing member" if members & internet_if else "name")
            zone_proof.append(zone)
    facts["internet_interfaces"] = sorted(internet_if)
    facts["zones"] = zone_proof

    # allowaccess features: on = the interfaces that allow it; off = proven by every allowaccess
    # line in the config, none of which names it ('show' omits defaults: no line, no access).
    allowing = [i for i in facts["interfaces"] if i["allowaccess"]]
    checked = f"allowaccess on {', '.join(i['name'] for i in allowing)}"

    def access_feature(name, protocols, label):
        hit = [i for i in facts["interfaces"] if set(protocols) & set(i["allowaccess"])]
        feature(facts, name, bool(hit), any(i["name"] in internet_if for i in hit), None,
                [_access(i) for i in (hit or allowing)],
                f"{label} in an interface's allowaccess" if hit else
                f"no interface allows {label} ({checked})" if allowing else "no interface has set allowaccess")

    access_feature("fgfm", ("fgfm",), "fgfm")
    access_feature("admin_web", ("http", "https"), "http or https")

    if not has_section(tree, "vpn ssl settings"):
        _hidden(facts, "sslvpn", "vpn ssl settings", "VPN settings")
    else:
        ssl = section(tree, "vpn ssl settings")
        src = ssl.get("source-interface", [])
        ssl_on = bool(src) and ssl.get("status") != ["disable"]
        decisive = ("status", "source-interface") if ssl_on or src else tuple(ssl)
        feature(facts, "sslvpn", ssl_on, ssl_on and any(i in internet_if for i in src), ",".join(src),
                ["config vpn ssl settings"] + [_set(k, ssl[k]) for k in decisive
                                               if k in ssl and isinstance(ssl[k], list)],
                "SSL VPN listens on " + ", ".join(src) if ssl_on else
                "SSL VPN status disable" if ssl.get("status") == ["disable"] else
                "no source-interface under 'config vpn ssl settings'")

    _routing(facts, tree)
    unknown(facts, "gcp_os_login", "GCP OS Login is set in the Google Cloud instance metadata (enable-oslogin), "
                                   "not in the FortiGate config")

    facts["internet_facing"] = bool(internet_if)
    facts["exposure_reason"] = ("internet-facing: " + ", ".join(sorted(internet_if))) if internet_if \
        else "no WAN-role or public interface found"
    return facts
