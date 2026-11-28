# ============================================================
# Package:      topology
# Purpose:      The network's topology from saved show output: devices (with site, device role,
#               interfaces, VLANs, port-channels) and links between them. Neighbor links come
#               from CDP and LLDP; subnet links from two interfaces sharing a /30 or /31 (finds
#               firewalls and tunnels that discovery can't see); spreadsheet links from a CSV.
#               Read-only: works from files, never connects to a device.
# Usage:        import topology
#               topo = topology.read_snapshot(repo, inventory)      # inventory may be None
#               topology.read_csv(topo, Path("links.csv"))
#               topology.build_links(topo)
#               topo["devices"], topo["links"], topo["gaps"]
# Author:       G Talks Tech
# Notes:        Terms (CONTEXT.md): neighbor link, subnet link, unlinked device, unknown
#               neighbor, device role. A device's role comes from devicetags (ADR 0002).
# ============================================================
import csv
import re
from collections import defaultdict
from pathlib import Path

import devicetags
import snapshotfiles

from . import parsers as p
from .parsers import norm_intf, short_host, short_intf  # noqa: F401  (public names)

NEIGHBOR, SUBNET, TUNNEL, SPREADSHEET = "neighbor", "subnet", "tunnel", "spreadsheet"
SKIP_VRFS = ("MGMT", "Mgmt-vrf", "management", "mgmt")

# Commands read per device (network-snapshot file = snapshotfiles.slug(command)).
CMD = {
    "cdp": "show cdp neighbors detail",
    "lldp": ("show lldp neighbors detail", "show lldp neighbor-info detail"),
    "config": ("show running-config view full", "show running-config"),
    "fortios": "show",
    "descriptions": "show interfaces description",
    "trunks": "show interfaces trunk",
    "vlans": "show vlan brief",
    "etherchannel": "show etherchannel summary",
}


def _read(folder, cmds):
    for c in (cmds if isinstance(cmds, tuple) else (cmds,)):
        f = folder / snapshotfiles.slug(c)
        if f.exists():
            return f.read_text(encoding="utf-8", errors="replace")
    return None


def new():
    """An empty topology."""
    return {"devices": {}, "links": [], "gaps": [], "unknown_neighbors": []}


def _device(name, site="", platform="", entry=None):
    entry = dict(entry or {}, name=name)
    role, role_source = devicetags.role_of(entry)
    return {"name": name, "site": site, "platform": platform, "role": role, "role_source": role_source,
            "in_inventory": entry is not None and bool(entry.get("_inventory")),
            "neighbors": [], "lldp": None, "ips": {}, "descriptions": {}, "trunks": {}, "vlans": {},
            "portchannels": {}, "seen_files": [], "notes": []}


def read_snapshot(repo, inventory=None, site=None):
    """Topology from a network-snapshot repo (<repo>/<site>/<name>/<command>.txt).
    inventory: the parsed inventory.yaml ({defaults, devices}) or None; with it, each listed
    device's site, device_type and tags come from the inventory and devices not listed are
    still read from their folders. site: read only that site."""
    repo = Path(repo)
    topo = new()
    entries = {}
    if inventory:
        defaults = inventory.get("defaults") or {}
        for e in inventory.get("devices") or []:
            if isinstance(e, dict) and e.get("name"):
                entries[e["name"]] = {**defaults, **e, "_inventory": True}
    folders = {}
    for d in sorted(x for x in repo.glob("*/*") if x.is_dir() and not x.parts[-2].startswith(".")):
        folders[d.name] = d
    names = sorted(set(entries) | set(folders))
    for name in names:
        e = entries.get(name)
        dsite = (e or {}).get("site") or (folders[name].parent.name if name in folders else "unassigned")
        if site and dsite != site:
            continue
        dev = _device(name, dsite, (e or {}).get("device_type", ""), e)
        folder = repo / dsite / name if e else folders.get(name)
        if not folder or not folder.exists():
            folder = folders.get(name)
        if not folder:
            dev["notes"].append("no snapshot folder: run network-snapshot first")
            topo["gaps"].append({"device": name, "gap": "no snapshot", "fix": "run network-snapshot"})
        else:
            _read_device(dev, folder, topo)
        topo["devices"][name] = dev
    return topo


def _read_device(dev, folder, topo):
    text = _read(folder, CMD["cdp"])
    if text is not None:
        dev["neighbors"] += [dict(n, source="cdp") for n in p.cdp(text)]
        dev["seen_files"].append("cdp")
    text = _read(folder, CMD["lldp"])
    if text is not None:
        dev["lldp"] = p.lldp_enabled(text)
        dev["neighbors"] += [dict(n, source="lldp") for n in p.lldp(text)]
        dev["seen_files"].append("lldp")
    forti = _read(folder, CMD["fortios"])
    if forti and "config system interface" in forti:
        dev["ips"] = p.fortios_ips(forti)
        dev["descriptions"] = {k: {"status": "", "protocol": "", "description": v}
                               for k, v in p.fortios_descriptions(forti).items()}
        if not dev["role"]:
            dev["role"], dev["role_source"] = "firewall", "FortiOS config (a FortiGate is a firewall)"
    else:
        cfg = _read(folder, CMD["config"])
        if cfg:
            dev["ips"] = p.cisco_ips(cfg)
    for key, fn in (("descriptions", p.descriptions), ("trunks", p.trunks), ("vlans", p.vlans),
                    ("portchannels", p.etherchannels)):
        text = _read(folder, CMD[key if key != "portchannels" else "etherchannel"])
        if text is not None:
            dev[key] = fn(text)
            dev["seen_files"].append(key)
    if "cdp" not in dev["seen_files"] and "lldp" not in dev["seen_files"]:
        topo["gaps"].append({"device": dev["name"], "gap": "no CDP or LLDP output saved",
                             "fix": "its links can only come from shared subnets or your spreadsheet"})
    elif dev["lldp"] is False and not any(n["source"] == "cdp" for n in dev["neighbors"]):
        topo["gaps"].append({"device": dev["name"], "gap": "LLDP is off and no CDP neighbors",
                             "fix": "turn on LLDP (lldp run) so neighbors can be read"})


# ---------- links ----------
def _add(topo, index, a, ai, b, bi, source, note=""):
    """One link per pair of interfaces; a link two sources both see keeps both sources."""
    key = tuple(sorted([(a, ai), (b, bi)]))
    if key in index:
        index[key]["sources"].add(source)
        return index[key]
    if "" in (ai, bi):     # a spreadsheet row without ports joins any link already between the two
        for (x, _xi), (y, _yi) in list(index):
            if {x, y} == {a, b}:
                index[((x, _xi), (y, _yi))]["sources"].add(source)
                return index[((x, _xi), (y, _yi))]
    (x, xi), (y, yi) = key
    link = {"a": x, "a_intf": xi, "b": y, "b_intf": yi, "sources": {source}, "note": note, "members": []}
    index[key] = link
    return link


def build_links(topo, subnets=True, skip_vrfs=SKIP_VRFS):
    """Neighbor links, then subnet links for interfaces no neighbor link covers, then port-channel
    members folded into one link per channel. Spreadsheet links read by read_csv are kept."""
    devs = topo["devices"]
    index = {tuple(sorted([(l["a"], l["a_intf"]), (l["b"], l["b_intf"])])): l for l in topo["links"]}
    for name, d in list(devs.items()):
        for n in d["neighbors"]:
            if n["remote"] not in devs:
                devs[n["remote"]] = _device(n["remote"], "", "", None)
                devs[n["remote"]]["platform_seen"] = n.get("platform", "")
                if n["remote"] not in topo["unknown_neighbors"]:
                    topo["unknown_neighbors"].append(n["remote"])
            _add(topo, index, name, n["local_intf"], n["remote"], n["remote_intf"], NEIGHBOR)
    if subnets:
        used = {(e, i) for k in index for e, i in k}
        by_net = defaultdict(list)
        for name, d in devs.items():
            for intf, addrs in d["ips"].items():
                for ipi, vrf in addrs:
                    if vrf in skip_vrfs or ipi.network.prefixlen < 30:
                        continue
                    by_net[ipi.network].append((name, intf))
        for net, members in by_net.items():
            if len(members) != 2 or members[0][0] == members[1][0]:
                continue
            (a, ai), (b, bi) = members
            if (a, ai) in used and (b, bi) in used:
                continue     # a neighbor link already covers it
            tunnel = ai.startswith("Tunnel") or bi.startswith("Tunnel")
            _add(topo, index, a, ai, b, bi, TUNNEL if tunnel else SUBNET, note=str(net))
    topo["links"] = _fold_portchannels(devs, list(index.values()))
    for l in topo["links"]:
        l["kind"] = link_kind(l)
    return topo


def _fold_portchannels(devs, links):
    """Links whose both ends are members of the same port-channel pair become one link between
    the port-channels, listing its members."""
    def channel(dev, intf):
        for po, info in devs.get(dev, {}).get("portchannels", {}).items():
            if intf in info["members"]:
                return po
        return None
    out, groups = [], {}
    for l in links:
        pa, pb = channel(l["a"], l["a_intf"]), channel(l["b"], l["b_intf"])
        if pa and pb:
            key = (l["a"], pa, l["b"], pb)
            g = groups.get(key)
            if not g:
                g = groups[key] = {**l, "a_intf": pa, "b_intf": pb, "members": [], "sources": set()}
                out.append(g)
            g["members"].append((l["a_intf"], l["b_intf"]))
            g["sources"] |= l["sources"]
        else:
            out.append(l)
    return out


def link_kind(link):
    """neighbor | spreadsheet | tunnel | subnet: how the drawing shows it (a link any neighbor
    protocol saw is a neighbor link, whatever else also found it)."""
    s = link["sources"]
    for k in (NEIGHBOR, SPREADSHEET, TUNNEL, SUBNET):
        if k in s:
            return k
    return NEIGHBOR


CSV_COLS = {"a": ("device_a", "device a", "a", "from", "source", "local device", "device"),
            "a_intf": ("port_a", "port a", "interface_a", "local port", "local interface", "a port"),
            "b": ("device_b", "device b", "b", "to", "target", "remote device", "neighbor"),
            "b_intf": ("port_b", "port b", "interface_b", "remote port", "remote interface", "b port"),
            "description": ("description", "note", "notes", "label"),
            "vlan": ("vlan", "vlans"), "speed": ("speed",), "site": ("site",)}


def read_csv(topo, path):
    """Spreadsheet links: device, port, port, device (header row optional), plus any of the
    columns description, vlan, speed and site, found by header name. Returns rows read."""
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = [r for r in csv.reader(f) if any(c.strip() for c in r)]
    if not rows:
        return 0
    header = [h.strip().lower() for h in rows[0]]
    col = {k: next((header.index(n) for n in names if n in header), None) for k, names in CSV_COLS.items()}
    if col["a"] is None or col["b"] is None:     # no header: device, port, port, device
        col = {k: None for k in CSV_COLS}
        col.update({"a": 0, "a_intf": 1, "b_intf": 2, "b": 3})
        data = rows
    else:
        data = rows[1:]
    index = {tuple(sorted([(l["a"], l["a_intf"]), (l["b"], l["b_intf"])])): l for l in topo["links"]}
    count = 0
    for r in data:
        def get(k):
            return r[col[k]].strip() if col[k] is not None and col[k] < len(r) else ""
        a, b = short_host(get("a")), short_host(get("b"))
        if not a or not b:
            continue
        for name in (a, b):
            if name not in topo["devices"]:
                topo["devices"][name] = _device(name, get("site"), "", {"name": name})
        note = " | ".join(x for x in (get("description"), get("vlan") and f"VLAN {get('vlan')}",
                                      get("speed")) if x)
        _add(topo, index, a, norm_intf(get("a_intf")), b, norm_intf(get("b_intf")), SPREADSHEET, note)
        count += 1
    topo["links"] = list(index.values())
    return count


def unlinked(topo):
    """Devices with no link of any kind (CONTEXT.md: unlinked device)."""
    linked = {l[k] for l in topo["links"] for k in ("a", "b")}
    return sorted(n for n in topo["devices"] if n not in linked)
