# ============================================================
# Module:       topology.parsers
# Purpose:      Text parsers for the saved show output a topology is built from: CDP and LLDP
#               neighbors, interface addresses (Cisco config, FortiOS config), interface
#               descriptions, trunks, VLANs and port-channels. Each takes raw text and returns
#               plain data; interface names come back in their long form (Ethernet0/1).
# Author:       G Talks Tech
# ============================================================
import ipaddress
import re
from collections import defaultdict

ABBREV = [
    (r"^(Et|Eth)(?=\d)", "Ethernet"),
    (r"^Gi(?=\d)", "GigabitEthernet"),
    (r"^Fa(?=\d)", "FastEthernet"),
    (r"^Te(?=\d)", "TenGigabitEthernet"),
    (r"^Twe(?=\d)", "TwentyFiveGigE"),
    (r"^Fo(?=\d)", "FortyGigabitEthernet"),
    (r"^Hu(?=\d)", "HundredGigE"),
    (r"^Po(?=\d)", "Port-channel"),
    (r"^Lo(?=\d)", "Loopback"),
    (r"^Tu(?=\d)", "Tunnel"),
    (r"^Vl(?=\d)", "Vlan"),
]
SHORT = [("TwentyFiveGigE", "Twe"), ("TenGigabitEthernet", "Te"), ("GigabitEthernet", "Gi"),
         ("FastEthernet", "Fa"), ("FortyGigabitEthernet", "Fo"), ("HundredGigE", "Hu"),
         ("Port-channel", "Po"), ("Ethernet", "Et"), ("Tunnel", "Tu"), ("Loopback", "Lo"), ("Vlan", "Vl")]


def norm_intf(name):
    """Long interface name: Gi1/0/1 -> GigabitEthernet1/0/1. Unknown names are left as they are."""
    name = str(name).strip().strip('"')
    for pat, full in ABBREV:
        if re.match(pat, name):
            return re.sub(pat, full, name)
    return name


def short_intf(name):
    """Short interface name for labels: GigabitEthernet1/0/1 -> Gi1/0/1."""
    for full, short in SHORT:
        if name.startswith(full):
            return short + name[len(full):]
    return name


def short_host(name):
    """Drop the domain: hq-core-sw-01.gtt.lab -> hq-core-sw-01. IP addresses are left alone."""
    name = str(name).strip().strip('"')
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        return name.split(".")[0]


# ---------- neighbors ----------
def cdp(text):
    """show cdp neighbors detail (IOS, IOS-XE, NX-OS): [{remote, local_intf, remote_intf, platform}].
    Splits on "Device ID:", not on dashed lines: network-snapshot sorts the entries, which can
    leave one without its dashes."""
    out = []
    for entry in re.split(r"(?=^Device ID:)", text, flags=re.M):
        dev = re.search(r"Device ID:\s*(\S+)", entry)
        intf = re.search(r"Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(\S+)", entry)
        plat = re.search(r"Platform:\s*([^,\r\n]+)", entry)
        if dev and intf:
            out.append({"remote": short_host(re.sub(r"\(.*\)$", "", dev.group(1))),
                        "local_intf": norm_intf(intf.group(1)), "remote_intf": norm_intf(intf.group(2)),
                        "platform": plat.group(1).strip() if plat else ""})
    return out


def lldp_enabled(text):
    """False when the output says LLDP is off, else True."""
    return not re.search(r"LLDP is not enabled|LLDP is disabled", text, re.I)


def lldp(text):
    """show lldp neighbors detail: IOS/IOS-XE/NX-OS style ("Local Intf:") and Arista style
    ("Interface X detected"): [{remote, local_intf, remote_intf}]. Other vendors: not read yet."""
    out = []
    if not lldp_enabled(text):
        return out
    for b in re.split(r"(?=^Local Intf:|^Interface \S+ detected)", text, flags=re.M):
        local = (re.search(r"^Local Intf:\s*(\S+)", b, re.M)
                 or re.search(r"^Interface (\S+) detected", b, re.M))
        name = re.search(r"System Name:\s*\"?([^\"\r\n]+)\"?", b)
        port = (re.search(r"^Port id:\s*(\S+)", b, re.M | re.I)
                or re.search(r"Port ID\s*:\s*\"?([^\"\r\n]+)\"?", b))
        if local and name and port:
            out.append({"remote": short_host(name.group(1)), "local_intf": norm_intf(local.group(1)),
                        "remote_intf": norm_intf(port.group(1)), "platform": ""})
    return out


# ---------- addresses ----------
def cisco_ips(config):
    """interface + ip address lines from a Cisco running config (IOS, IOS-XE, NX-OS):
    {intf: [(ipv4_interface, vrf)]}, secondary addresses included."""
    ips, intf, vrf = defaultdict(list), None, ""
    for line in config.splitlines():
        m = re.match(r"^interface (\S+)", line)
        if m:
            intf, vrf = norm_intf(m.group(1)), ""
            continue
        if not line.startswith(" "):
            intf = None
            continue
        if intf is None:
            continue
        m = re.match(r"^\s+(?:ip )?vrf forwarding (\S+)|^\s+vrf member (\S+)", line)
        if m:
            vrf = m.group(1) or m.group(2)
        m = re.match(r"^\s+ip address (\d+\.\d+\.\d+\.\d+)[ /](\S+)", line)
        if m:
            try:
                ips[intf].append((ipaddress.ip_interface(f"{m.group(1)}/{m.group(2)}"), vrf))
            except ValueError:
                pass
    return dict(ips)


def fortios_ips(show):
    """config system interface -> edit "portN" -> set ip <ip> <mask> (FortiOS `show`):
    {intf: [(ipv4_interface, vdom-less vrf "")]}."""
    ips, intf, depth = defaultdict(list), None, 0
    for line in show.splitlines():
        s = line.strip()
        if s == "config system interface" and depth == 0:
            depth = 1
            continue
        if not depth:
            continue
        if s.startswith("config "):
            depth += 1
        elif s == "end":
            depth -= 1
        elif depth == 1:
            m = re.match(r'edit "(.+)"', s)
            if m:
                intf = m.group(1)
            m = re.match(r"set ip (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)", s)
            if m and intf:
                ips[intf].append((ipaddress.ip_interface(f"{m.group(1)}/{m.group(2)}"), ""))
    return dict(ips)


def fortios_descriptions(show):
    """FortiOS interface descriptions and aliases: {intf: text}."""
    out, intf, depth = {}, None, 0
    for line in show.splitlines():
        s = line.strip()
        if s == "config system interface" and depth == 0:
            depth = 1
            continue
        if not depth:
            continue
        if s.startswith("config "):
            depth += 1
        elif s == "end":
            depth -= 1
        elif depth == 1:
            m = re.match(r'edit "(.+)"', s)
            if m:
                intf = m.group(1)
            m = re.match(r'set (?:description|alias) "(.*)"', s)
            if m and intf and m.group(1):
                out.setdefault(intf, m.group(1))
    return out


# ---------- interfaces and layer 2 (Cisco IOS / IOS-XE) ----------
def descriptions(text):
    """show interfaces description: {intf: {status, protocol, description}}."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+(admin down|up|down|deleted)\s+(up|down)\s*(.*)$", line)
        if m and m.group(1) != "Interface":
            out[norm_intf(m.group(1))] = {"status": m.group(2), "protocol": m.group(3),
                                          "description": m.group(4).strip()}
    return out


def trunks(text):
    """show interfaces trunk: {intf: {native, allowed}} from the "Vlans allowed on trunk" table."""
    out, section = {}, None
    for line in text.splitlines():
        if line.startswith("Port"):
            section = "mode" if "Native vlan" in line else ("allowed" if "allowed on trunk" in line else "other")
            continue
        m = re.match(r"^(\S+)\s+(.*\S)\s*$", line)
        if not m or section in (None, "other"):
            continue
        intf = norm_intf(m.group(1))
        if section == "mode":
            native = re.search(r"(\d+)\s*$", m.group(2))
            out.setdefault(intf, {"native": None, "allowed": ""})["native"] = native.group(1) if native else None
        else:
            out.setdefault(intf, {"native": None, "allowed": ""})["allowed"] = m.group(2).strip()
    return out


def vlans(text):
    """show vlan brief: {vlan_id: {name, status, ports: [intf]}}, the reserved 1002-1005 left out.
    Port lists wrap onto continuation lines that start with spaces."""
    out, last = {}, None
    for line in text.splitlines():
        m = re.match(r"^(\d+)\s+(\S+)\s+(active|act/unsup|suspended|act/lshut|sus/lshut)\s*(.*)$", line)
        if m:
            vid = int(m.group(1))
            last = None if 1002 <= vid <= 1005 else vid
            if last is not None:
                out[last] = {"name": m.group(2), "status": m.group(3),
                             "ports": [norm_intf(p) for p in re.split(r",\s*", m.group(4).strip()) if p]}
        elif last is not None and line.startswith(" ") and line.strip():
            out[last]["ports"] += [norm_intf(p) for p in re.split(r",\s*", line.strip()) if p]
    return out


def etherchannels(text):
    """show etherchannel summary: {Port-channelN: {protocol, flags, members: [intf]}}."""
    out, last = {}, None
    for line in text.splitlines():
        m = re.match(r"^(\d+)\s+(Po\d+)\((\w+)\)\s+(\S+)\s*(.*)$", line)
        if m:
            last = norm_intf(m.group(2))
            out[last] = {"protocol": m.group(4), "flags": m.group(3), "members": []}
            rest = m.group(5)
        elif last and line.startswith(" ") and re.search(r"\(\w+\)", line):
            rest = line
        else:
            continue
        out[last]["members"] += [norm_intf(p) for p in re.findall(r"(\S+?)\(\w+\)", rest)]
    return out
