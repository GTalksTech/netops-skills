# Tests for push.py. A fake netmiko connection stands in for the device, so nothing here
# touches a network. Each test writes a small inventory and a command file to a temp folder.
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "push.py"
sys.path.insert(0, str(SCRIPT.parent))
import push  # noqa: E402

INVENTORY = """defaults:
  username: claude-ro
  device_type: cisco_ios
devices:
  - {name: sw1, host: 192.0.2.1, site: hq}
  - {name: fw1, host: 192.0.2.2, site: hq, device_type: fortinet}
"""


class FakeConn:
    sent = []
    output = "sw1(config)#vlan 40\nsw1(config-vlan)#name CAMERAS\n"
    raise_error = None
    saves = 0

    def __init__(self, **kwargs):
        FakeConn.kwargs = kwargs

    def send_config_set(self, lines, **kwargs):
        FakeConn.sent.append(list(lines))
        if FakeConn.raise_error:
            raise FakeConn.raise_error
        return FakeConn.output

    def save_config(self):
        FakeConn.saves += 1
        return "Building configuration...\n[OK]"

    def disconnect(self):
        pass


@pytest.fixture
def env(tmp_path, monkeypatch):
    (tmp_path / "inventory.yaml").write_text(INVENTORY, encoding="utf-8")
    FakeConn.sent, FakeConn.raise_error, FakeConn.saves = [], None, 0
    FakeConn.output = "sw1(config)#vlan 40\nsw1(config-vlan)#name CAMERAS\n"
    monkeypatch.setattr(push, "connect", lambda dev: FakeConn(**dev))
    monkeypatch.setattr(push.keyring, "get_password", lambda s, u: "pw")
    return tmp_path


def run(env, monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["push.py", *argv, "--repo", str(env)])
    return push.main()


def cfg(env, text, name="sw1.txt"):
    p = env / "change" / name
    p.parent.mkdir(exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_preview_sends_nothing(env, monkeypatch, capsys):
    f = cfg(env, "configure terminal\nvlan 40\n name CAMERAS\nend\n")
    assert run(env, monkeypatch, "preview", "sw1", f) == 0
    out = capsys.readouterr().out
    assert "PREVIEW sw1" in out and "as admin" in out and "  vlan 40" in out and "configure terminal" not in out
    assert FakeConn.sent == []


def test_push_one_device_and_logs(env, monkeypatch, capsys):
    f = cfg(env, "vlan 40\n name CAMERAS\n")
    assert run(env, monkeypatch, "push", "sw1", f) == 0
    assert FakeConn.sent == [["vlan 40", " name CAMERAS"]]
    assert FakeConn.kwargs["username"] == "admin"  # change account, not the read-only default
    assert FakeConn.saves == 0  # push never saves; save comes after the post-check
    log = (env / "change" / "push-log.md").read_text(encoding="utf-8")
    assert "push sw1 as admin: OK" in log and "name CAMERAS" in log


def test_device_error_fails_and_says_so(env, monkeypatch, capsys):
    FakeConn.output = "sw1(config)#vlan 4099\n% Invalid input detected at '^' marker.\n"
    f = cfg(env, "vlan 4099\n")
    assert run(env, monkeypatch, "push", "sw1", f) == 1
    out = capsys.readouterr().out
    assert "FAILED on sw1" in out and "still on the device" in out
    assert "FAILED" in (env / "change" / "push-log.md").read_text(encoding="utf-8")


def test_netmiko_exception_is_a_failure(env, monkeypatch, capsys):
    FakeConn.raise_error = RuntimeError("Invalid input detected")
    f = cfg(env, "vlan 40\n")
    assert run(env, monkeypatch, "push", "sw1", f) == 1


def test_bare_allowed_vlan_refused(env, monkeypatch, capsys):
    f = cfg(env, "interface Ethernet0/1\n switchport trunk allowed vlan 40\n")
    assert run(env, monkeypatch, "push", "sw1", f) == 2
    assert "REFUSED" in capsys.readouterr().out
    assert FakeConn.sent == []


@pytest.mark.parametrize("line", ["switchport trunk allowed vlan add 40", "switchport trunk allowed vlan remove 40",
                                  "switchport trunk allowed vlan except 99", "switchport trunk allowed vlan none"])
def test_allowed_vlan_keywords_pass(env, monkeypatch, line):
    f = cfg(env, f"interface Ethernet0/1\n {line}\n")
    assert run(env, monkeypatch, "push", "sw1", f) == 0


@pytest.mark.parametrize("line", ["reload", "write erase", "erase startup-config", "delete flash:x.bin",
                                  "format flash:"])
def test_destructive_refused(env, monkeypatch, line):
    f = cfg(env, f"{line}\n")
    assert run(env, monkeypatch, "push", "sw1", f) == 2
    assert FakeConn.sent == []


def test_untested_vendor_refused_for_push_but_previews(env, monkeypatch, capsys):
    f = cfg(env, "config system interface\n", "fw1.txt")
    assert run(env, monkeypatch, "preview", "fw1", f) == 0
    with pytest.raises(SystemExit):
        run(env, monkeypatch, "push", "fw1", f)
    assert FakeConn.sent == []


def test_one_device_per_run(env, monkeypatch):
    f = cfg(env, "vlan 40\n")
    with pytest.raises(SystemExit):
        run(env, monkeypatch, "push", "sw1", "sw2", f)


def test_unknown_device(env, monkeypatch):
    f = cfg(env, "vlan 40\n")
    with pytest.raises(SystemExit):
        run(env, monkeypatch, "push", "nope", f)


def test_save_many(env, monkeypatch, capsys):
    assert run(env, monkeypatch, "save", "sw1", "sw1", "--log", str(env)) == 0
    assert FakeConn.saves == 2
    assert "SAVED sw1" in capsys.readouterr().out


def test_comments_and_blanks_skipped(env, monkeypatch):
    f = cfg(env, "# VLAN 40 on sw1\n\nconf t\nvlan 40\nend\n")
    assert run(env, monkeypatch, "push", "sw1", f) == 0
    assert FakeConn.sent == [["vlan 40"]]
