# ============================================================
# Script:       tables.py
# Purpose:      Read the host and link tables a snapshot saves (ARP, MAC address table,
#               trunk ports, CDP and LLDP neighbors, DHCP snooping and server bindings,
#               FortiGate ARP) into plain rows. Used by the host table join (lib/hosttable)
#               and open to any skill that needs the same rows.
# Usage:        from devicefacts import tables
#               rows = tables.ios_arp(text)        # [{ip, mac, age, interface, own}]
#               tables.norm_mac("00:50:56:B3:A2:C7")   # "0050.56b3.a2c7"
# Author:       G Talks Tech
# Notes:        Read-only text parsing, no device access. Each parser returns [] (or an
#               empty set) for empty, rejected or unrecognized output, never raises.
#               Written for this project after reading how SuzieQ, Genie, NAPALM and
#               ntc-templates model the same tables; no code or templates copied.
# ============================================================
import re

_HEX = re.compile(r"[0-9a-fA-F]")
_IFNAMES = (  # long name prefix -> the short form Cisco prints in the MAC and trunk tables
    ("TwentyFiveGigE", "Twe"), ("HundredGigE", "Hu"), ("FortyGigabitEthernet", "Fo"),
    ("TenGigabitEthernet", "Te"), ("FiveGigabitEthernet", "Fi"), ("TwoGigabitEthernet", "Tw"),
    ("AppGigabitEthernet", "Ap"), ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"),
    ("Ethernet", "Et"), ("Port-channel", "Po"), ("Vlan", "Vl"), ("Loopback", "Lo"),
    ("Tunnel", "Tu"),
)
_MAC_DOTTED = r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
_MAC_COLON = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"


def norm_mac(text):
    """Any MAC form (aa:bb.., aa-bb.., aabb.ccdd.eeff) as 'aabb.ccdd.eeff'; None if not a MAC."""
    if not text:
        return None
    digits = "".join(_HEX.findall(text))
    if len(digits) != 12 or not re.fullmatch(r"[0-9a-fA-F.:\-]+", text.strip()):
        return None
    d = digits.lower()
    return f"{d[0:4]}.{d[4:8]}.{d[8:12]}"


def short_if(name):
    """An interface name in the short form ('Ethernet0/1' -> 'Et0/1'), so tables that print
    long and short names can be joined. Names with no known prefix come back unchanged."""
    if not name:
        return name
    for long, short in _IFNAMES:
        if name.startswith(long):
            return short + name[len(long):]
    return name


def _lines(text):
    return (text or "").replace("\r", "").split("\n")


def ios_arp(text):
    """`show ip arp [vrf X]`: [{ip, mac, age, interface, own}]. own: the device's own address
    (age '-'). Incomplete entries have no MAC and are left out."""
    rows = []
    for l in _lines(text):
        m = re.match(rf"^Internet\s+(\S+)\s+(\S+)\s+({_MAC_DOTTED})\s+\S+\s+(\S+)", l)
        if m:
            rows.append({"ip": m.group(1), "mac": norm_mac(m.group(3)), "age": m.group(2),
                         "interface": short_if(m.group(4)), "own": m.group(2) == "-"})
    return rows


def ios_mac_table(text):
    """`show mac address-table`: [{vlan, mac, type, port}]. Entries on CPU or with no port
    (the switch's own addresses) are left out."""
    rows = []
    for l in _lines(text):
        m = re.match(rf"^\s*(\d+)\s+({_MAC_DOTTED})\s+(\S+)\s+(\S+)", l)
        if m and m.group(4).upper() not in ("CPU", "DROP", "ROUTER"):
            rows.append({"vlan": m.group(1), "mac": norm_mac(m.group(2)), "type": m.group(3),
                         "port": short_if(m.group(4).split(",")[0])})
    return rows


def ios_trunks(text):
    """`show interfaces trunk`: the set of trunking ports, from its first section."""
    ports, section = set(), 0
    for l in _lines(text):
        if l.startswith("Port"):
            section += 1
            continue
        if section == 1 and l.strip():
            ports.add(short_if(l.split()[0]))
    return ports


def _blocks(text, start):
    out, cur = [], None
    for l in _lines(text):
        if re.match(start, l):
            cur = [l]
            out.append(cur)
        elif cur is not None:
            cur.append(l)
    return out


def _is_network(found, rx):
    """True when a neighbor's capabilities say switch or router, or when none are printed
    (unknown is treated as a network device, so a host port is never claimed without proof)."""
    return True if not found or not found.group(1).strip() else bool(re.search(rx, found.group(1)))


def ios_cdp(text):
    """`show cdp neighbors detail`: [{local_port, name, remote_port, macs, network}]. network:
    the neighbor is a switch or router (a phone or AP is not)."""
    rows = []
    for b in _blocks(text, r"^Device ID:"):
        body = "\n".join(b)
        name = re.search(r"^Device ID:\s*(\S+)", body, re.M)
        intf = re.search(r"^Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(\S+)", body, re.M)
        if name and intf:
            rows.append({"local_port": short_if(intf.group(1).strip()), "name": name.group(1),
                         "remote_port": short_if(intf.group(2)),
                         "macs": sorted({norm_mac(x) for x in re.findall(rf"Peer Source MAC:\s*({_MAC_DOTTED})", body)}),
                         "network": _is_network(re.search(r"Capabilities:\s*(.*)$", body, re.M), r"\b(Router|Switch|Trans-Bridge|Source-Route-Bridge)\b")})
    return rows


def ios_lldp(text):
    """`show lldp neighbors detail`: [{local_port, name, remote_port, macs}] (chassis id and
    peer source MAC when they are MAC addresses)."""
    rows = []
    for b in _blocks(text, r"^Local Intf:"):
        body = "\n".join(b)
        local = re.search(r"^Local Intf:\s*(\S+)", body, re.M)
        name = re.search(r"^System Name:\s*(\S+)", body, re.M)
        port = re.search(r"^Port id:\s*(\S+)", body, re.M)
        macs = {norm_mac(x) for x in re.findall(rf"(?:Chassis id|Peer Source MAC):\s*({_MAC_DOTTED})", body)}
        if local:
            rows.append({"local_port": short_if(local.group(1)), "name": name.group(1) if name else None,
                         "remote_port": short_if(port.group(1)) if port else None, "macs": sorted(macs - {None}),
                         "network": _is_network(re.search(r"^Enabled Capabilities:\s*(.*)$", body, re.M), r"\b[BR]\b")})
    return rows


def ios_snooping(text):
    """`show ip dhcp snooping binding`: [{mac, ip, vlan, port}]."""
    rows = []
    for l in _lines(text):
        m = re.match(rf"^({_MAC_COLON})\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\S+\s+(\d+)\s+(\S+)", l)
        if m:
            rows.append({"mac": norm_mac(m.group(1)), "ip": m.group(2), "vlan": m.group(3),
                         "port": short_if(m.group(4))})
    return rows


def ios_dhcp_binding(text):
    """`show ip dhcp binding`: [{ip, mac, interface}]. mac only when the client id is a
    hardware address (type 01 plus a MAC, or a bare MAC); otherwise None."""
    rows = []
    for l in _lines(text):
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(.*)$", l)
        if not m:
            continue
        digits = "".join(_HEX.findall(m.group(2)))
        mac = None
        if len(digits) == 14 and digits.startswith("01"):
            mac = norm_mac(digits[2:])
        elif len(digits) == 12:
            mac = norm_mac(digits)
        tail = m.group(3).split()
        iface = tail[-1] if tail and re.match(r"^[A-Za-z]", tail[-1]) and tail[-1] not in ("Active", "Selecting") else None
        rows.append({"ip": m.group(1), "mac": mac, "interface": short_if(iface)})
    return rows


def fortios_interfaces(text):
    """`get system interface`: [{name, ip}] for every interface with an address (0.0.0.0 left out)."""
    rows = []
    for l in _lines(text):
        m = re.match(r"^name:\s*(\S+)\s.*?\bip:\s*(\d+\.\d+\.\d+\.\d+)\s", l + " ")
        if m and m.group(2) != "0.0.0.0":
            rows.append({"name": m.group(1), "ip": m.group(2)})
    return rows


def fortios_arp(text):
    """`get system arp`: [{ip, mac, age, interface, own}] (FortiOS lists no own addresses)."""
    rows = []
    for l in _lines(text):
        m = re.match(rf"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+({_MAC_COLON})\s+(\S+)", l)
        if m:
            rows.append({"ip": m.group(1), "mac": norm_mac(m.group(3)), "age": m.group(2),
                         "interface": m.group(4), "own": False})
    return rows
