"""Device state, per-VRF commands, no-data, privilege, when: and the read-verb guard on
commands built from device output. Offline: a fake Netmiko connection and a test profile.
Run: python -m pytest plugins (repo root)."""
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import snapshot  # noqa: E402

PROFILE = r"""
netmiko_device_type: cisco_ios
host_table: cisco_ios
invalid_markers: ["% Invalid input"]
no_data_markers: ["does not exist", "% BGP not active"]
privilege: {cmd: show privilege, regex: 'privilege level is (\d+)'}
vrfs: {cmd: show vrf detail, regex: '^VRF (\S+) \(VRF Id'}
uptime: {cmd: show version, regex: 'uptime is (.+)'}
commands:
  - cmd: show running-config
  - cmd: show vrf detail
  - cmd: show ip protocols vrf {vrf}
  - cmd: show bgp all summary
  - cmd: show ip dhcp snooping
    when: '^ip dhcp snooping$'
state_commands:
  - cmd: show ip arp
  - cmd: show ip arp vrf {vrf}
  - cmd: show ipv6 neighbors vrf {vrf}
  - cmd: show mac address-table
  - cmd: show bgp big
    tier: full
  - cmd: show interfaces
health_commands:
  - cmd: show interfaces
mask:
  - pattern: '\b\d{1,2}:\d{2}:\d{2}\b'
    replace: '--:--:--'
"""

VRF_DETAIL = ("VRF MGMT (VRF Id = 1); default RD <not set>; default VPNID <not set>\n"
              "VRF bad;name (VRF Id = 2); default RD <not set>\n"
              "VRF Cust-A (VRF Id = 3); default RD 65000:1\n")


class FakeConn:
    sent = []
    outputs = {}
    clock = 0

    def __init__(self, **kw):
        pass

    def send_command(self, cmd, read_timeout=60):
        FakeConn.sent.append(cmd)
        return FakeConn.outputs.get(cmd, f"output of {cmd} at 10:11:{FakeConn.clock:02d}\n")

    def is_alive(self):
        return True

    def disconnect(self):
        pass


@pytest.fixture
def lab(tmp_path, monkeypatch):
    plat = tmp_path / "platforms"
    plat.mkdir()
    (plat / "testos.yaml").write_text(PROFILE, encoding="utf-8")
    monkeypatch.setattr(snapshot, "PLATFORMS", plat)
    monkeypatch.setitem(sys.modules, "netmiko", types.SimpleNamespace(ConnectHandler=FakeConn))
    monkeypatch.setenv("NETOPS_SECRET_RO", "pw")
    FakeConn.sent = []
    FakeConn.outputs = {
        "show version": "r1 uptime is 2 weeks, 3 days\n",
        "show privilege": "Current privilege level is 5\n",
        "show running-config": "hostname r1\ninterface Ethernet0/0\n",
        "show vrf detail": VRF_DETAIL,
        "show ipv6 neighbors vrf MGMT": "% IPv6 routing table MGMT does not exist\n",
        "show bgp all summary": "% BGP not active\n",
        "show mac address-table": "% Invalid input detected at '^' marker.\n",
        "show ip arp": ("Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
                        "Internet  10.0.0.5              116   aabb.cc00.7420  ARPA   Ethernet0/1\n"),
    }
    repo = tmp_path / "snap"
    repo.mkdir()
    (repo / "inventory.yaml").write_text(
        "devices:\n  - {name: r1, host: 10.0.0.1, site: hq, device_type: testos, username: ro}\n")
    args = types.SimpleNamespace(repo=str(repo), inventory=None, site=None, device=None, workers=1,
                                 health=False, no_state=False, full=False)
    return types.SimpleNamespace(repo=repo, args=args)


def run(lab, capsys, **flags):
    for k, v in flags.items():
        setattr(lab.args, k, v)
    FakeConn.sent = []
    FakeConn.clock += 1  # every default output carries a clock that moves between runs
    snapshot.run(lab.args)
    return json.loads(capsys.readouterr().out)


def git_clean(repo):
    return subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                          capture_output=True, text=True).stdout == ""


def test_state_is_collected_by_default_kept_with_the_previous_run_and_never_committed(lab, capsys):
    first = run(lab, capsys)
    st = first["state"]["r1"]
    sdir = lab.repo / ".snapshot" / "state" / "hq" / "r1"
    assert Path(st["dir"]) == sdir and (sdir / "show-ip-arp.txt").exists()
    assert "show-ip-arp-vrf-mgmt.txt" in st["files"]
    assert st["previous"] is None
    assert git_clean(lab.repo)
    second = run(lab, capsys)
    assert second["state"]["r1"]["previous"]["taken"]
    assert (lab.repo / ".snapshot" / "state-prev" / "hq" / "r1" / "show-ip-arp.txt").exists()
    assert git_clean(lab.repo)


def test_no_state_runs_no_state_command(lab, capsys):
    report = run(lab, capsys, no_state=True)
    assert "show ip arp" not in FakeConn.sent and "state" not in report
    assert "show running-config" in FakeConn.sent


def test_full_tier_runs_only_with_full(lab, capsys):
    run(lab, capsys)
    assert "show bgp big" not in FakeConn.sent
    run(lab, capsys, full=True)
    assert "show bgp big" in FakeConn.sent


def test_vrf_commands_expand_for_valid_names_only(lab, capsys):
    report = run(lab, capsys)
    assert {"show ip arp vrf MGMT", "show ip arp vrf Cust-A", "show ip protocols vrf MGMT"} <= set(FakeConn.sent)
    assert not any("bad" in c for c in FakeConn.sent)
    assert report["state"]["r1"]["vrfs"] == ["MGMT", "Cust-A"]
    assert report["state"]["r1"]["invalid_vrfs"] == ["bad;name"]
    assert (lab.repo / "hq" / "r1" / "show-ip-protocols-vrf-cust-a.txt").exists()


def test_no_data_is_saved_and_listed_apart_from_rejected(lab, capsys):
    report = run(lab, capsys)
    assert "show bgp all summary" in report["no_data_commands"]["r1"]
    assert "show ipv6 neighbors vrf MGMT" in report["state"]["r1"]["no_data"]
    assert "show mac address-table" in report["state"]["r1"]["rejected"]
    assert "show bgp all summary" not in report["unsupported_commands"].get("r1", [])
    assert (lab.repo / "hq" / "r1" / "show-bgp-all-summary.txt").read_text() == "% BGP not active\n"


def test_privilege_level_is_reported_and_no_file_is_saved(lab, capsys):
    report = run(lab, capsys)
    assert report["privilege"] == {"r1": 5}
    assert not (lab.repo / "hq" / "r1" / "show-privilege.txt").exists()


def test_when_skips_a_command_the_config_does_not_call_for(lab, capsys):
    report = run(lab, capsys)
    assert "show ip dhcp snooping" not in FakeConn.sent
    assert report["skipped_by_when"]["r1"] == ["show ip dhcp snooping"]
    FakeConn.outputs["show running-config"] = "hostname r1\nip dhcp snooping\n"
    run(lab, capsys)
    assert "show ip dhcp snooping" in FakeConn.sent


def test_a_command_in_state_and_health_runs_once_and_lands_in_both(lab, capsys):
    report = run(lab, capsys, health=True)
    assert FakeConn.sent.count("show interfaces") == 1
    assert "show-interfaces.txt" in report["health"]["r1"]["files"]
    assert "show-interfaces.txt" in report["state"]["r1"]["files"]


def test_host_table_is_written_and_compared_with_the_previous_run(lab, capsys):
    first = run(lab, capsys)
    assert first["hosts"]["rows"] == 1 and first["hosts"]["changes"] is None
    rows = (lab.repo / ".snapshot" / "hosts.csv").read_text().splitlines()
    assert rows[1].startswith("10.0.0.5,aabb.cc00.7420,default,")
    FakeConn.outputs["show ip arp"] = "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
    second = run(lab, capsys)
    assert second["hosts"]["changes"] == {"new": [], "gone": ["10.0.0.5 aabb.cc00.7420 vrf default"]}
    assert (lab.repo / ".snapshot" / "hosts-prev.csv").exists()


def test_a_second_run_with_only_timers_moving_commits_nothing(lab, capsys):
    first = run(lab, capsys)
    assert first["commit"]
    FakeConn.outputs["show running-config"] = "hostname r1\ninterface Ethernet0/0\n"
    second = run(lab, capsys)  # the fake prints a clock in every default output; masked
    assert second["commit"] is None


# ---- the read-verb guard on every command, including the ones built from device output ----

def test_guard_refuses_anything_that_is_not_a_plain_read():
    for bad in ("configure terminal", "conf t", "write memory", "execute dhcp lease-list",
                "diagnose sys sdwan member", "show run | redirect flash:x.txt",
                "show run | append flash:x", "show run | tee flash:x", "show ip arp vrf A\nconf t",
                "show ip arp vrf A\rreload", "", "copy run start"):
        with pytest.raises(ValueError):
            snapshot.check_command(bad)
    for ok in ("show ip arp vrf MGMT", "get system arp", "display version", "show run | include hostname"):
        assert snapshot.check_command(ok) == ok


def test_vrf_names_are_validated_before_they_reach_a_command():
    good, bad = snapshot.valid_vrfs(["MGMT", "Cust-A", "red_1.2:3", "bad;name", "a b", "x" * 33,
                                     "", "A|redirect", "Mgmt-intf"])
    assert good == ["MGMT", "Cust-A", "red_1.2:3", "Mgmt-intf"]
    assert bad == ["bad;name", "a b", "x" * 33, "", "A|redirect"]


def test_vrf_templates_expand_once_per_vrf_and_pass_the_guard():
    assert snapshot.expand("show ip arp vrf {vrf}", ["MGMT", "Cust-A"]) == [
        ("show ip arp vrf MGMT", "MGMT"), ("show ip arp vrf Cust-A", "Cust-A")]
    assert snapshot.expand("show ip arp vrf {vrf}", []) == []
    assert snapshot.expand("show ip arp", ["MGMT"]) == [("show ip arp", None)]
    with pytest.raises(ValueError):
        snapshot.expand("show ip arp vrf {vrf}", ["bad;name"])


def test_profile_with_a_non_read_state_command_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "PLATFORMS", tmp_path)
    (tmp_path / "x.yaml").write_text(PROFILE.replace("- cmd: show ip arp\n", "- cmd: clear ip arp\n", 1))
    with pytest.raises(ValueError, match="not read-only"):
        snapshot.load_profile("x")
    (tmp_path / "y.yaml").write_text(PROFILE.replace("vrfs: {cmd: show vrf detail, regex: '^VRF (\\S+) \\(VRF Id'}\n", ""))
    with pytest.raises(ValueError, match="vrf"):
        snapshot.load_profile("y")


def test_guard_refuses_nxos_style_redirection_and_chaining():
    for bad in ("show run > bootflash:x", "show run >> bootflash:x", "show version ; conf t"):
        with pytest.raises(ValueError):
            snapshot.check_command(bad)
