# Tests for the shared device-facts library (issue #18): every fact carries the lines that
# prove it, and "unknown" is its own answer for a feature, never "off".
import sys
from pathlib import Path

import pytest

LIB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LIB))
import devicefacts  # noqa: E402
from devicefacts import asa, fortios, ios, junos, panos  # noqa: E402

IOS_EDGE = """hostname r1
interface GigabitEthernet0/0
 description ISP
 ip address 203.0.113.2 255.255.255.252
 ip nat outside
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
ip http server
snmp-server community s3cr3t RO
no vstack
"""


def _write(repo, site, name, files):
    d = repo / site / name
    d.mkdir(parents=True)
    for f, text in files.items():
        (d / f).write_text(text, encoding="utf-8")


def _states(facts):
    return {n: f["state"] for n, f in facts["features"].items()}


# ---------- every fact carries its proof ----------

def test_ios_internet_interface_carries_its_lines():
    facts = ios.read(IOS_EDGE, {})
    edge = next(i for i in facts["interfaces"] if i["name"] == "GigabitEthernet0/0")
    assert facts["internet_interfaces"] == ["GigabitEthernet0/0"]
    assert edge["internet_why"] == "public IPv4 address"
    assert edge["internet_evidence"] == ["interface GigabitEthernet0/0", "ip address 203.0.113.2 255.255.255.252",
                                         "ip nat outside"]
    inside = next(i for i in facts["interfaces"] if i["name"] == "GigabitEthernet0/1")
    assert "internet_evidence" not in inside


def test_ios_on_and_off_features_carry_proof_and_hide_secrets():
    f = ios.read(IOS_EDGE, {})["features"]
    assert f["http_server"]["state"] == "on" and f["http_server"]["evidence"] == ["ip http server"]
    assert f["http_server"]["internet"] is True
    assert f["snmp"]["evidence"] == ["snmp-server community <hidden> RO"]
    assert f["smart_install"] == {"state": "off", "internet": False, "where": None, "evidence": ["no vstack"],
                                  "detail": "Smart Install is turned off"}
    off = ios.read(IOS_EDGE.replace("ip http server", "no ip http server"), {})["features"]["http_server"]
    assert off["state"] == "off" and off["evidence"] == ["no ip http server"]
    for name, feat in ios.read(IOS_EDGE, {})["features"].items():
        assert feat["evidence"] or feat["detail"], name


def test_ios_ipv6_internet_proof_names_the_route():
    cfg = IOS_EDGE.replace(" ip address 10.0.0.1 255.255.255.0\n",
                           " ip address 10.0.0.1 255.255.255.0\n ipv6 address 2001:db8:1::1/64\n") \
        + "ipv6 route ::/0 GigabitEthernet0/1\n"
    itf = next(i for i in ios.read(cfg, {})["interfaces"] if i["name"] == "GigabitEthernet0/1")
    assert itf["internet_why"] == "IPv6 (IPv6 default route)"
    assert "ipv6 address 2001:db8:1::1/64" in itf["internet_evidence"]
    assert "ipv6 route ::/0 GigabitEthernet0/1" in itf["internet_evidence"]


def test_firewall_readers_carry_proof():
    fgt = fortios.read('config system interface\n edit "wan1"\n  set ip 203.0.113.10 255.255.255.248\n'
                       '  set allowaccess ping https\n  set role wan\n next\nend\n'
                       'config vpn ssl settings\n set source-interface "wan1"\nend\n')
    wan = fgt["interfaces"][0]
    assert wan["internet_why"] == "set role wan" and "set role wan" in wan["internet_evidence"]
    assert fgt["features"]["sslvpn"]["state"] == "on" and "set source-interface wan1" in \
        fgt["features"]["sslvpn"]["evidence"]
    assert fgt["features"]["admin_web"]["evidence"] == ["wan1: set allowaccess ping https"]

    a = asa.read("hostname a\ninterface Gi0/0\n nameif outside\n ip address 198.51.100.2 255.255.255.0\n"
                 "http server enable\nhttp 0.0.0.0 0.0.0.0 outside\n")
    assert a["interfaces"][0]["internet_evidence"] == ["interface Gi0/0", "nameif outside",
                                                       "ip address 198.51.100.2 255.255.255.0"]
    assert a["features"]["mgmt_http"]["evidence"] == ["http server enable", "http 0.0.0.0 0.0.0.0 outside"]
    assert a["features"]["webvpn"]["state"] == "off"

    j = junos.read("set system services web-management https system-generated-certificate\n"
                   "set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.18/30\n"
                   "set security zones security-zone untrust interfaces ge-0/0/0.0 host-inbound-traffic "
                   "system-services https\n")
    assert j["features"]["jweb"]["state"] == "on" and j["features"]["jweb"]["internet"] is True
    assert j["interfaces"][0]["internet_evidence"][0].startswith("set interfaces ge-0/0/0 unit 0")

    p = panos.read("config { devices { localhost.localdomain { network { interface { ethernet { "
                   "ethernet1/1 { layer3 { ip [ 203.0.113.20/28 ]; } } } } } vsys { vsys1 { zone { "
                   "untrust { network { layer3 [ ethernet1/1 ]; } } } } } } } }")
    assert p["internet_interfaces"] == ["ethernet1/1"]
    assert p["interfaces"][0]["internet_evidence"] == ["ethernet1/1 ip [ 203.0.113.20/28 ]",
                                                       "zone untrust layer3 [ ethernet1/1 ]"]
    assert p["features"]["globalprotect"]["state"] == "off"


# ---------- Cisco platforms read by version (issue #27) ----------
# show version as Cisco prints it (Cisco docs and TAC notes; IOS XR and ISE not yet read from a device)
CISCO_SHOW_VERSION = {
    "classic": ("cisco_ios", "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8, "
                "RELEASE SOFTWARE (fc1)\ncisco WS-C2960X-48FPD-L (APM86XXX) processor (revision B0) with 524288K\n"),
    "xe": ("cisco_ios", "Cisco IOS XE Software, Version 17.09.04a\nCisco IOS Software [Cupertino], Catalyst L3 "
           "Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)\n"
           "cisco C9300-48P (X86) processor with 1K\n"),
    "xe3": ("cisco_ios", "Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), "
            "Version 03.06.06E RELEASE SOFTWARE (fc1)\n"),
    "iol": ("cisco_ios", "Cisco IOS Software [IOSXE], Linux Software (X86_64BI_LINUX-ADVENTERPRISEK9-M), Version "
            "17.16.1a, RELEASE SOFTWARE (fc1)\n"),
    "nxos": ("cisco_nxos", "Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version 9.3(8)\n"
             "  cisco Nexus9000 C93180YC-FX Chassis\n"),
    "xr": ("cisco_xr", "RP/0/RSP0/CPU0:pe1#show version\nCisco IOS XR Software, Version 7.9.2\n"
           "cisco ASR9K Series (Intel 686 F6M14S4) processor with 6291456K bytes of memory.\n"),
    "xr_classic": ("cisco_xr", "Cisco IOS XR Software, Version 6.5.3[Default]\n"),
    "ise": ("cisco_ise", "Cisco Application Deployment Engine OS Release: 3.3\nADE-OS Build Version: 3.3.0.430\n\n"
            "Version information of installed applications\n---------------------------------------------\n\n"
            "Cisco Identity Services Engine\n---------------------------------------------\nVersion      : 3.3.0.430\n"
            "Build Date   : Tue Jul 18 2023\n\nCisco Identity Services Engine Patch\n"
            "---------------------------------------------\nVersion      : 1\nInstall Date : Mon Jan 08 2024\n\n"
            "Cisco Identity Services Engine Patch\n---------------------------------------------\n"
            "Version      : 2\nInstall Date : Fri Mar 01 2024\n"),
    "ise_nopatch": ("cisco_ise", "Cisco Identity Services Engine\n---------------------------------------------\n"
                    "Version      : 3.2.0.542\nBuild Date   : Mon Sep 12 2022\n"),
}


@pytest.mark.parametrize("case,version,os_name", [
    ("classic", "15.2(7)E8", "IOS"), ("xe", "17.09.04a", "IOS XE"), ("xe3", "03.06.06E", "IOS XE"), ("iol", "17.16.1a", "IOS XE"),
    ("nxos", "9.3(8)", None), ("xr", "7.9.2", None), ("xr_classic", "6.5.3", None),
    ("ise", "3.3 Patch 2", None), ("ise_nopatch", "3.2", None)])
def test_cisco_version_and_os_are_read_from_show_version(tmp_path, case, version, os_name):
    platform, text = CISCO_SHOW_VERSION[case]
    _write(tmp_path, "hq", "d1", {"show-version.txt": text})
    rec = devicefacts.read_device({"name": "d1", "site": "hq", "device_type": platform}, tmp_path,
                                  devicefacts.load_platforms())
    assert rec["version"] == version
    assert rec["os"] == os_name
    assert rec["vendor"] == "Cisco"
    if os_name:
        assert rec["os_evidence"].startswith("show-version.txt: ")


def test_ise_patch_line_is_part_of_the_version_proof(tmp_path):
    _write(tmp_path, "dc", "ise1", {"show-version.txt": CISCO_SHOW_VERSION["ise"][1]})
    rec = devicefacts.read_device({"name": "ise1", "site": "dc", "device_type": "cisco_ise"}, tmp_path,
                                  devicefacts.load_platforms())
    assert rec["version_evidence"] == "show-version.txt: Version      : 3.3.0.430; patch: Version      : 2"


def test_cisco_models_are_read(tmp_path):
    for case, model in (("xr", "ASR9K"), ("nxos", "Nexus9000 C93180YC-FX")):
        platform, text = CISCO_SHOW_VERSION[case]
        _write(tmp_path, "hq", case, {"show-version.txt": text})
        rec = devicefacts.read_device({"name": case, "site": "hq", "device_type": platform}, tmp_path,
                                      devicefacts.load_platforms())
        assert rec["model"] == model, case


def test_read_device_proves_version_model_and_exposure(tmp_path):
    _write(tmp_path, "hq", "r1", {
        "show-version.txt": "Cisco IOS XE Software, Version 17.09.04\ncisco ISR4331/K9 (1RU) processor with 1K\n",
        "show-running-config-view-full.txt": IOS_EDGE})
    rec = devicefacts.read_device({"name": "r1", "site": "hq", "device_type": "cisco_ios"}, tmp_path,
                                  devicefacts.load_platforms())
    assert rec["version"] == "17.09.04"
    assert rec["version_evidence"] == "show-version.txt: Cisco IOS XE Software, Version 17.09.04"
    assert rec["model"] == "ISR4331/K9"
    assert rec["model_evidence"] == "show-version.txt: cisco ISR4331/K9 (1RU) processor with 1K"
    assert rec["internet_facing"] is True and rec["hostname"] == "r1"
    assert rec["internet_interfaces"] == [{"name": "GigabitEthernet0/0", "why": "public IPv4 address",
                                           "evidence": ["interface GigabitEthernet0/0",
                                                        "ip address 203.0.113.2 255.255.255.252", "ip nat outside"]}]
    assert rec["_parsed"]["facts"]["features"] is rec["features"]


# ---------- unknown is its own answer ----------

def test_smart_install_missing_on_a_switch_is_unknown_not_off():
    cfg = IOS_EDGE.replace("no vstack\n", "")
    f = ios.read(cfg, {"_is_switch": True})
    assert f["features"]["smart_install"]["state"] == "unknown"
    assert f["features"]["smart_install"]["internet"] is None
    assert "show vstack config" in f["features"]["smart_install"]["detail"]
    assert ios.read(cfg, {})["features"]["smart_install"]["state"] == "unknown"
    assert ios.read(cfg + "vstack\n", {"_is_switch": True})["features"]["smart_install"]["state"] == "on"


def test_nearly_empty_ios_config_makes_every_feature_unknown():
    f = ios.read("hostname r1\n", {})
    assert set(f["features"]) == set(ios.FEATURES)
    assert set(_states(f).values()) == {"unknown"}
    assert all(x["internet"] is None for x in f["features"].values())


def test_config_with_no_interfaces_makes_every_feature_unknown(tmp_path):
    _write(tmp_path, "dc", "pa", {"show-system-info.txt": "sw-version: 10.2.7\nmodel: PA-440\n",
                                  "show-config-running.txt": "set deviceconfig system hostname pa\n"})
    rec = devicefacts.read_device({"name": "pa", "site": "dc", "device_type": "paloalto_panos"}, tmp_path,
                                  devicefacts.load_platforms())
    assert set(rec["features"]) == set(panos.FEATURES)
    assert {f["state"] for f in rec["features"].values()} == {"unknown"}
    assert rec["internet_facing"] is True and "assumed edge" in rec["exposure_reason"]


@pytest.mark.parametrize("on,state,internet", [(True, "on", True), (False, "off", False), (None, "unknown", None)])
def test_feature_states(on, state, internet):
    facts = devicefacts.facts.new_facts()
    devicefacts.facts.feature(facts, "x", on, internet=True, detail="d")
    assert facts["features"]["x"]["state"] == state and facts["features"]["x"]["internet"] is internet


def test_platforms_name_a_reader_for_every_parser():
    for p, cfg in devicefacts.load_platforms().items():
        if cfg.get("source") == devicefacts.fmc.SOURCE:      # FTD: facts from FMC records, no snapshot
            assert {"vendor", "kind"} <= set(cfg) and not {"version", "config"} & set(cfg), p
            continue
        assert {"vendor", "kind", "version", "config"} <= set(cfg), p
        assert cfg["config"]["parser"] in set(devicefacts.READERS) | {"none"}, p


# ---------- FTD through FMC (issue #30): facts from saved FMC device records ----------
FMC_ENTRY = {"name": "hq-fmc", "host": "fmc.example.net", "site": "hq", "username": "svc",
             "ftd": {"ftd-1": {"criticality": "essential", "exposure": "internal", "other": "x"}}}
FMC_SAVED = {"fmc": "hq-fmc", "collected": "2026-11-26T10:00:00+00:00",
             "devices": [{"name": "ftd-1", "domain": "Global", "sw_version": "7.2.5", "model": "FPR1120"},
                         {"name": "ftd-2", "domain": "Global", "sw_version": ""},
                         {"name": "ftd-1", "domain": "East", "sw_version": "7.2.5"}]}


def test_fmc_entries_need_name_host_and_username_and_a_safe_name():
    inv = {"fmc": [FMC_ENTRY, {"name": "x", "host": "h"}, {"name": "C:x", "host": "h", "username": "u"}, "nope"]}
    entries, problems = devicefacts.fmc.entries(inv)
    assert [e["name"] for e in entries] == ["hq-fmc"] and len(problems) == 3
    assert devicefacts.fmc.entries({"fmc": {"a": 1}})[0] == []


def test_fmc_records_become_device_facts_with_proof_and_tags():
    recs = devicefacts.fmc.read(FMC_ENTRY, FMC_SAVED, devicefacts.load_platforms(), {"criticality": "minimal"})
    assert [r["name"] for r in recs] == ["ftd-1", "ftd-2"]          # a device listed twice is kept once
    one, two = recs
    assert one["platform"] == "cisco_ftd" and one["source"] == "fmc" and one["managed_by"] == "hq-fmc"
    assert one["version_evidence"] == ("FMC hq-fmc device record (domain Global), read 2026-11-26 10:00: "
                                       "sw_version 7.2.5")
    assert one["model"] == "FPR1120" and one["features"] == {} and not one["internet_facing"]
    assert two["version"] is None and "lists no software version" in two["notes"][0]
    assert two["internet_facing"] and "assumed internet-facing" in two["exposure_reason"]
    tags = devicefacts.fmc.ftd_entry(FMC_ENTRY, "ftd-1", {"criticality": "minimal", "username": "u"})
    assert tags["criticality"] == "essential" and "other" not in tags and "username" not in tags
    assert devicefacts.fmc.ftd_entry(FMC_ENTRY, "ftd-2", {"criticality": "minimal"})["criticality"] == "minimal"
    assert devicefacts.fmc.read(FMC_ENTRY, None, {}) == []


# ---------- FortiOS at full depth (issue #34): off is proven by the lines that rule it out ----------
LAB_FGT = LIB / "tests" / "fixtures" / "lab-v2" / "fw-01" / "show.txt"


def test_fortios_lab_features_and_the_lines_that_decide_them():
    """The lab FortiGate (FortiOS 8.0.1), checked by hand against show.txt."""
    f = fortios.read(LAB_FGT.read_text(encoding="utf-8"))["features"]
    access = ["port1: set allowaccess ping https ssh", "port2: set allowaccess ping",
              "port3: set allowaccess ping", "fortilink: set allowaccess ping fabric"]
    # fgfm: no interface allows it; the proof is every allowaccess line in the config
    assert f["fgfm"]["state"] == "off" and f["fgfm"]["evidence"] == access
    assert f["fgfm"]["detail"] == "no interface allows fgfm (allowaccess on port1, port2, port3, fortilink)"
    # admin web: https on port1 (mgmt, 192.168.1.242/24), not on the WAN port
    assert f["admin_web"]["state"] == "on" and f["admin_web"]["internet"] is False
    assert f["admin_web"]["evidence"] == ["port1: set allowaccess ping https ssh"]
    # SSL VPN: the section is there, with no source-interface: off, the section is the proof
    assert f["sslvpn"]["state"] == "off"
    assert f["sslvpn"]["evidence"] == ["config vpn ssl settings", "set banned-cipher SHA1 SHA256 SHA384",
                                       "set servercert ''", "set port 443"]
    assert f["sslvpn"]["detail"] == "no source-interface under 'config vpn ssl settings'"


def test_fortios_web_off_is_proven_by_the_allowaccess_lines():
    f = fortios.read('config system interface\n edit "wan1"\n  set ip 203.0.113.10 255.255.255.248\n'
                     '  set allowaccess ping ssh\n  set role wan\n next\n edit "lan"\n  set ip 10.0.0.1 '
                     '255.255.255.0\n next\nend\nconfig vpn ssl settings\n set status disable\n'
                     ' set source-interface "wan1"\nend\n')["features"]
    assert f["admin_web"]["state"] == "off" and f["admin_web"]["evidence"] == ["wan1: set allowaccess ping ssh"]
    assert f["admin_web"]["detail"] == "no interface allows http or https (allowaccess on wan1)"
    assert f["sslvpn"]["state"] == "off" and "set status disable" in f["sslvpn"]["evidence"]


def test_fortios_no_allowaccess_anywhere_is_still_off_with_its_reason():
    f = fortios.read('config system interface\n edit "lan"\n  set ip 10.0.0.1 255.255.255.0\n next\nend\n'
                     'config vpn ssl settings\n set port 443\nend\n')["features"]
    assert f["fgfm"]["state"] == "off" and f["fgfm"]["detail"] == "no interface has set allowaccess"


FGT_IF = 'config system interface\n edit "port3"\n  set ip 10.0.0.13 255.255.255.252\n next\nend\n'


def test_fortios_routing_sections_missing_are_unknown():
    """The lab FortiGate peers OSPF with hq-dist-sw-01 and hq-edge-rtr-01, yet its saved show has no
    'config router' section at all: absence there is never taken as OSPF or BGP off."""
    f = fortios.read(LAB_FGT.read_text(encoding="utf-8"))["features"]
    for name in ("ospf", "ibgp"):
        assert f[name]["state"] == "unknown", name
        assert "config router" in f[name]["detail"]
    assert f["gcp_os_login"]["state"] == "unknown"
    assert "Google Cloud" in f["gcp_os_login"]["detail"]


def test_fortios_ospf_on_and_off():
    on = fortios.read(FGT_IF + 'config router ospf\n set router-id 10.255.0.2\n config area\n  edit 0.0.0.0\n'
                               '  next\n end\n config network\n  edit 1\n   set prefix 10.0.0.12 255.255.255.252\n'
                               '  next\n end\nend\n')["features"]["ospf"]
    assert on["state"] == "on" and on["internet"] is False
    assert on["evidence"] == ["config router ospf", "set router-id 10.255.0.2", "set prefix 10.0.0.12 255.255.255.252"]
    off = fortios.read(FGT_IF + 'config router ospf\nend\n')["features"]["ospf"]
    assert off["state"] == "off" and off["evidence"] == ["config router ospf"]
    assert off["detail"] == "no area, network or ospf-interface under 'config router ospf'"


def test_fortios_ibgp_is_a_neighbor_in_the_local_as():
    bgp = ('config router bgp\n set as 65010\n config neighbor\n  edit "10.0.0.14"\n   set remote-as {}\n'
           '  next\n end\nend\n')
    on = fortios.read(FGT_IF + bgp.format(65010))["features"]["ibgp"]
    assert on["state"] == "on" and on["evidence"] == ["config router bgp", "set as 65010", 'edit "10.0.0.14"',
                                                      "set remote-as 65010"]
    off = fortios.read(FGT_IF + bgp.format(64500))["features"]["ibgp"]
    assert off["state"] == "off" and off["detail"] == "no BGP neighbor or neighbor-group in the local AS 65010"
    assert off["evidence"] == ["config router bgp", "set as 65010", 'edit "10.0.0.14"', "set remote-as 64500"]
    group = ('config router bgp\n set as 65010\n config neighbor-group\n  edit "spokes"\n   set remote-as 65010\n'
             '  next\n end\nend\n')
    assert fortios.read(FGT_IF + group)["features"]["ibgp"]["state"] == "on"
    assert fortios.read(FGT_IF + 'config router bgp\nend\n')["features"]["ibgp"]["state"] == "off"


def test_fortios_ssl_vpn_section_missing_is_unknown_not_off():
    # A read-only profile without VPN access shows no 'config vpn ssl settings' at all.
    f = fortios.read('config system interface\n edit "wan1"\n  set ip 203.0.113.10 255.255.255.248\n'
                     '  set role wan\n next\nend\n')["features"]
    assert f["sslvpn"]["state"] == "unknown" and f["sslvpn"]["internet"] is None
    assert "config vpn ssl settings" in f["sslvpn"]["detail"]
