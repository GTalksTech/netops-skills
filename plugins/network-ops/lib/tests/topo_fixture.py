"""A small snapshot repo for topology and diagram tests (network-snapshot layout:
<repo>/<site>/<device>/<command>.txt). Built in a temp folder; addresses are RFC 5737 / RFC 1918.

    hq:   edge-rtr-01 --(subnet only)-- fw-01 --(subnet only)-- core-sw-01
          core-sw-01 Po1 (Et0/1, Et0/2) == dist-sw-01 Po1   (CDP on both members)
          dist-sw-01 Et1/0 -- acc-sw-01 Et0/1 (LLDP, trunk 10,20)
          core-sw-01 Et0/3 -- mystery-ap (CDP, not in the inventory)
    br1:  br1-rtr-01 Tunnel0 -- edge-rtr-01 Tunnel0 (tunnel subnet)
          lonely-sw-01 (no links)
"""
import textwrap

CDP_ENTRY = """Device ID: {dev}
Entry address(es):
  IP address: 10.0.0.1
Platform: {plat},  Capabilities: Switch IGMP
Interface: {local},  Port ID (outgoing port): {remote}
Holdtime : 150 sec
"""

FILES = {
    ("hq", "edge-rtr-01"): {
        "show-running-config-view-full.txt": """
            interface Ethernet0/0
             vrf forwarding MGMT
             ip address 192.168.1.231 255.255.255.0
            !
            interface Ethernet0/1
             description TO fw-01 port2
             ip address 198.51.100.9 255.255.255.252
            !
            interface Tunnel0
             ip address 10.0.1.1 255.255.255.252
            !
            """,
        "show-cdp-neighbors-detail.txt": "",
        "show-lldp-neighbors-detail.txt": "% LLDP is not enabled\n",
    },
    ("hq", "fw-01"): {
        "show.txt": """
            config system interface
                edit "port1"
                    set vdom "root"
                    set ip 192.168.1.242 255.255.255.0
                next
                edit "port2"
                    set ip 198.51.100.10 255.255.255.252
                    set alias "outside"
                    config ipv6
                        set ip6-address ::/0
                    end
                next
                edit "port3"
                    set ip 10.0.0.13 255.255.255.252
                next
            end
            """,
    },
    ("hq", "core-sw-01"): {
        "show-running-config-view-full.txt": """
            interface Ethernet0/0
             ip address 10.0.0.14 255.255.255.252
            !
            """,
        "show-cdp-neighbors-detail.txt": (
            CDP_ENTRY.format(dev="dist-sw-01.lab.example", plat="Linux Unix", local="Ethernet0/1", remote="Ethernet0/1")
            + "-------------------------\n"
            + CDP_ENTRY.format(dev="dist-sw-01.lab.example", plat="Linux Unix", local="Ethernet0/2", remote="Ethernet0/2")
            + "-------------------------\n"
            + CDP_ENTRY.format(dev="mystery-ap", plat="cisco AIR-AP", local="Ethernet0/3", remote="GigabitEthernet0")),
        "show-etherchannel-summary.txt": """
            Group  Port-channel  Protocol    Ports
            ------+-------------+-----------+-----------------------------------------------
            1      Po1(SU)         LACP      Et0/1(P)    Et0/2(P)
            """,
        "show-interfaces-description.txt": """
            Interface                      Status         Protocol Description
            Et0/0                          up             up       TO fw-01 port3
            Et0/1                          up             up       TO dist-sw-01 | Po1 member
            Et0/3                          admin down     down
            """,
    },
    ("hq", "dist-sw-01"): {
        "show-cdp-neighbors-detail.txt": (
            CDP_ENTRY.format(dev="core-sw-01", plat="Linux Unix", local="Ethernet0/1", remote="Ethernet0/1")
            + CDP_ENTRY.format(dev="core-sw-01", plat="Linux Unix", local="Ethernet0/2", remote="Ethernet0/2")),
        "show-lldp-neighbors-detail.txt": """
            Local Intf: Et1/0
            Chassis id: aabb.cc00.0100
            Port id: Et0/1
            System Name: acc-sw-01.lab.example

            Total entries displayed: 1
            """,
        "show-etherchannel-summary.txt": """
            Group  Port-channel  Protocol    Ports
            ------+-------------+-----------+-----------------------------------------------
            1      Po1(SU)         LACP      Et0/1(P)    Et0/2(P)
            """,
        "show-interfaces-trunk.txt": """
            Port        Mode             Encapsulation  Status        Native vlan
            Et1/0       on               802.1q         trunking      99

            Port        Vlans allowed on trunk
            Et1/0       10,20

            Port        Vlans allowed and active in management domain
            Et1/0       10,20
            """,
        "show-vlan-brief.txt": """
            VLAN Name                             Status    Ports
            ---- -------------------------------- --------- -------------------------------
            1    default                          active
            10   USERS                            active    Et2/0, Et2/1, Et2/2, Et2/3,
                                                            Et3/0
            20   VOICE                            active
            1002 fddi-default                     act/unsup
            """,
    },
    ("hq", "acc-sw-01"): {
        "show-cdp-neighbors-detail.txt": "",
        "show-vlan-brief.txt": """
            VLAN Name                             Status    Ports
            ---- -------------------------------- --------- -------------------------------
            10   USERS                            active    Et0/2
            """,
    },
    ("br1", "br1-rtr-01"): {
        "show-running-config-view-full.txt": """
            interface Tunnel0
             ip address 10.0.1.2 255.255.255.252
            !
            """,
        "show-cdp-neighbors-detail.txt": "",
    },
    ("br1", "lonely-sw-01"): {
        "show-cdp-neighbors-detail.txt": "",
    },
}

INVENTORY = """\
# Lab inventory (test)
defaults:
  username: claude-ro
  device_type: cisco_ios
devices:
  - {name: edge-rtr-01, host: 192.0.2.1, site: hq}
  - {name: fw-01, host: 192.0.2.2, site: hq, device_type: fortinet}
  - name: core-sw-01      # the core
    host: 192.0.2.3
    site: hq
    role: core
  - {name: dist-sw-01, host: 192.0.2.4, site: hq}
  - {name: acc-sw-01, host: 192.0.2.5, site: hq}
  - {name: br1-rtr-01, host: 192.0.2.6, site: br1}
  - {name: lonely-sw-01, host: 192.0.2.7, site: br1}
"""


def build(root, inventory=True):
    """Write the fixture repo under root and return root."""
    for (site, dev), files in FILES.items():
        folder = root / site / dev
        folder.mkdir(parents=True, exist_ok=True)
        for name, text in files.items():
            (folder / name).write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    if inventory:
        (root / "inventory.yaml").write_text(INVENTORY, encoding="utf-8")
    return root
