# ============================================================
# Package:      hosttable
# Purpose:      The host table: one row per end host (or address) a snapshot saw, joined
#               from every device's ARP, MAC address table, trunk list, CDP/LLDP neighbors
#               and DHCP bindings, each row naming the tables that showed it. A row exists
#               only when some device table showed it; nothing is guessed.
# Usage:        import hosttable
#               rows = hosttable.build([{"name": "acc-01", "platform": "cisco_ios",
#                                        "outputs": [{"cmd": "show ip arp", "vrf": None,
#                                                     "text": "..."}]}])
#               hosttable.write_csv(rows, path); hosttable.read_csv(path)
#               hosttable.compare(previous_rows, rows)   # {new: [...], gone: [...]} or None
# Author:       G Talks Tech
# Notes:        See lib/README.md. Pure joins over saved text; no device access.
#               Columns: ip, mac, vrf, vlan, device, port, kind, sources, note.
#               kind: host | network-device (an address of a device in the run or a CDP/LLDP
#               neighbor) | virtual (an FHRP virtual MAC). device/port: the edge port the MAC
#               was learned on (hosts), or the device and interface that owns the address.
#               VRFs are matched across devices by name.
# ============================================================
import csv
import ipaddress
import re

from devicefacts import tables

COLUMNS = ["ip", "mac", "vrf", "vlan", "device", "port", "kind", "sources", "note"]
# FHRP virtual MACs: HSRPv1, HSRPv2, VRRP, GLBP
VIRTUAL_MAC = re.compile(r"^(0000\.0c07\.ac|0000\.0c9f\.f|0000\.5e00\.01|0007\.b4)")

# which saved command feeds which table, per platform (commands as the profile lists them)
SOURCES = {
    "cisco_ios": {
        "arp": (tables.ios_arp, lambda c: c == "show ip arp" or c.startswith("show ip arp vrf ")),
        "mac": (tables.ios_mac_table, lambda c: c == "show mac address-table"),
        "trunk": (tables.ios_trunks, lambda c: c == "show interfaces trunk"),
        "cdp": (tables.ios_cdp, lambda c: c == "show cdp neighbors detail"),
        "lldp": (tables.ios_lldp, lambda c: c == "show lldp neighbors detail"),
        "snoop": (tables.ios_snooping, lambda c: c == "show ip dhcp snooping binding"),
        "dhcp": (tables.ios_dhcp_binding, lambda c: c == "show ip dhcp binding"),
    },
    "fortinet": {
        "arp": (tables.fortios_arp, lambda c: c == "get system arp"),
        "ifaddr": (tables.fortios_interfaces, lambda c: c == "get system interface"),
    },
}


def _parse(dev):
    """{table: [(vrf, rows)]} for one device, from whichever outputs its platform knows."""
    found = {}
    for o in dev.get("outputs", []):
        for table, (fn, match) in SOURCES.get(dev.get("platform"), {}).items():
            if match(o["cmd"]):
                found.setdefault(table, []).append((o.get("vrf") or "default", fn(o.get("text") or "")))
    return found


def _ip_key(ip):
    try:
        return (0, ipaddress.ip_address(ip))
    except ValueError:
        return (1, ip)


def _join(values):
    return "; ".join(sorted(set(values)))


def build(devices):
    """Host table rows for the devices of one run (see module header)."""
    parsed = {d["name"]: _parse(d) for d in devices}
    owners = {}      # mac -> (device, interface): an address a device in the run owns
    neighbors = {}   # mac -> (neighbor name, its port): seen in CDP/LLDP
    uplinks = {}     # device -> ports that lead to another network device
    for name, p in parsed.items():
        ups = set()
        for _, ports in p.get("trunk", []):
            ups |= ports
        for table in ("cdp", "lldp"):
            for _, rows in p.get(table, []):
                for n in rows:
                    if n["network"]:  # a phone or AP neighbor does not make a port an uplink
                        ups.add(n["local_port"])
                    # a neighbor that is in this run goes by its inventory name (CDP adds the domain)
                    nname = n["name"] or ""
                    nname = nname if nname in parsed or nname.split(".")[0] not in parsed else nname.split(".")[0]
                    for m in n["macs"] if n["network"] else []:  # a phone or AP stays a host
                        neighbors.setdefault(m, (nname, n["remote_port"]))
        uplinks[name] = ups
        for _, rows in p.get("arp", []):
            for a in rows:
                if a["own"]:
                    owners.setdefault(a["mac"], (name, a["interface"]))

    sightings = {}   # mac -> [(device, port, vlan, edge)]
    for name, p in parsed.items():
        for _, rows in p.get("mac", []):
            for m in rows:
                sightings.setdefault(m["mac"], []).append((name, m["port"], m["vlan"], m["port"] not in uplinks[name]))

    hosts = {}       # (vrf, ip, mac) -> row under construction
    def row(vrf, ip, mac):
        return hosts.setdefault((vrf, ip, mac), {"ip": ip, "mac": mac, "vrf": vrf, "sources": [],
                                                 "arp_on": [], "self": None, "vlans": set(), "edges": []})

    for name, p in parsed.items():  # ARP from every device first: the other tables attach to it
        for vrf, rows in p.get("arp", []):
            for a in rows:
                r = row(vrf, a["ip"], a["mac"])
                if a["own"]:
                    r["self"] = (name, a["interface"])
                    r["sources"].append(f"arp-self:{name}")
                else:
                    r["sources"].append(f"arp:{name}")
                    r["arp_on"].append(f"{name} {a['interface']}")
    for name, p in parsed.items():
        for vrf, rows in p.get("ifaddr", []):  # addresses a device lists but does not ARP for itself
            for i in rows:
                match = [k for k in hosts if k[1] == i["ip"] and k[0] == vrf]
                for r in [hosts[k] for k in match] or [row(vrf, i["ip"], "")]:
                    r["self"] = (name, i["name"])
                    r["sources"].append(f"if-self:{name}")
        for _, rows in p.get("snoop", []):
            for s in rows:
                match = [k for k in hosts if k[1] == s["ip"] and k[2] == s["mac"]]
                r = hosts[match[0]] if match else row("default", s["ip"], s["mac"])
                r["sources"].append(f"dhcp-snoop:{name}:{s['port']}")
                r["vlans"].add(s["vlan"])
        for vrf, rows in p.get("dhcp", []):
            for b in rows:
                match = [k for k in hosts if k[1] == b["ip"] and (k[2] == b["mac"] if b["mac"] else k[0] == vrf)]
                r = hosts[match[0]] if match else row(vrf, b["ip"], b["mac"] or "")
                r["sources"].append(f"dhcp-server:{name}")

    ip_macs = {k[2] for k in hosts}
    for mac in sightings:
        if mac not in ip_macs:
            row("", "", mac)

    out = []
    for (vrf, ip, mac), r in hosts.items():
        seen = sightings.get(mac, [])
        svi = re.match(r"^Vl(\d+)$", (r["self"] or ("", ""))[1] or "")
        for dev, port, vlan, edge in seen:
            r["sources"].append(f"mac:{dev}:{port}")
            if not svi:  # a device's own MAC is shared by its VLAN interfaces: the interface says which
                r["vlans"].add(vlan)
        if svi:
            r["vlans"].add(svi.group(1))
        edges = sorted({(d, p) for d, p, _, e in seen if e})
        notes, device, port = [], "", ""
        if VIRTUAL_MAC.match(mac or ""):
            kind = "virtual"
            device, port = r["self"] or ("", "")
        elif r["self"] or mac in owners or mac in neighbors:
            kind = "network-device"
            device, port = r["self"] or owners.get(mac) or neighbors.get(mac) or ("", "")
            if not r["self"] and mac not in owners:
                notes.append("neighbor from CDP/LLDP")
        else:
            kind = "host"
            if edges:
                device, port = edges[0]
                if len(edges) > 1:
                    device = ";".join(d for d, _ in edges)
                    port = ";".join(p for _, p in edges)
                    notes.append("seen on more than one edge port")
            elif seen:
                notes.append("seen only on uplinks: " + ", ".join(sorted({f"{d} {p}" for d, p, _, _ in seen})))
            elif r["arp_on"]:
                notes.append("no MAC table entry; ARP on " + ", ".join(sorted(set(r["arp_on"]))))
        out.append({"ip": ip, "mac": mac or "", "vrf": vrf, "vlan": ";".join(sorted(r["vlans"], key=int)),
                    "device": device or "", "port": port or "", "kind": kind,
                    "sources": _join(r["sources"]), "note": "; ".join(notes)})

    out.sort(key=lambda r: (r["ip"] == "", r["vrf"] != "default", r["vrf"], _ip_key(r["ip"]), r["mac"]))
    return out


def _cell(v):
    # names come from device output (CDP/LLDP): never let one start a spreadsheet formula
    v = str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@") else v


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        w.writeheader()
        w.writerows({k: _cell(r[k]) for k in COLUMNS} for r in rows)


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return [{k: (v[1:] if v[:2] in ("'=", "'+", "'-", "'@") else v) for k, v in r.items()}
                for r in csv.DictReader(f)]


def _label(r):
    return f"{r['ip'] or '-'} {r['mac'] or '-'}" + (f" vrf {r['vrf']}" if r["vrf"] else "")


def compare(previous, rows):
    """{new, gone}: rows (by ip, mac, vrf) that appeared or disappeared since the previous
    table; None when there is no previous table."""
    if previous is None:
        return None
    key = lambda r: (r["vrf"], r["ip"], r["mac"])  # noqa: E731
    before, now = {key(r): r for r in previous}, {key(r): r for r in rows}
    return {"new": [_label(now[k]) for k in now if k not in before],
            "gone": [_label(before[k]) for k in before if k not in now]}
