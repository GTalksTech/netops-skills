# Tests for push.py. A fake netmiko connection stands in for the device, so nothing here
# touches a network. Commands arrive on stdin, the way a here-doc delivers them.
import io
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
  - {name: sw2, host: 192.0.2.3, site: hq}
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


def run(env, monkeypatch, stdin, *argv, log=True):
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    extra = ["--log", str(env / "change")] if log else []
    monkeypatch.setattr(sys, "argv", ["push.py", *argv, "--repo", str(env), *extra])
    return push.main()


def test_push_from_stdin_records_everything(env, monkeypatch, capsys):
    assert run(env, monkeypatch, "configure terminal\nvlan 40\n name CAMERAS\nend\n", "push", "sw1") == 0
    assert FakeConn.sent == [["vlan 40", " name CAMERAS"]]
    assert FakeConn.kwargs["username"] == "admin"  # change account, not the read-only default
    assert FakeConn.saves == 0  # push never saves; save comes after the post-check
    out = capsys.readouterr().out
    assert "SENDING sw1" in out and "  vlan 40" in out
    assert "name CAMERAS" in (env / "change" / "sw1.txt").read_text(encoding="utf-8")
    assert "push sw1 as admin: OK" in (env / "change" / "push-log.md").read_text(encoding="utf-8")


def test_file_argument_is_refused(env, monkeypatch):
    with pytest.raises(SystemExit):
        run(env, monkeypatch, "vlan 40\n", "push", "sw1", "commands.txt")
    assert FakeConn.sent == []


def test_no_stdin_is_refused(env, monkeypatch):
    class Tty(io.StringIO):
        def isatty(self):
            return True
    monkeypatch.setattr(sys, "stdin", Tty(""))
    monkeypatch.setattr(sys, "argv", ["push.py", "push", "sw1", "--repo", str(env), "--log", str(env)])
    with pytest.raises(SystemExit):
        push.main()


def test_log_dir_required(env, monkeypatch):
    with pytest.raises(SystemExit):
        run(env, monkeypatch, "vlan 40\n", "push", "sw1", log=False)


def test_preview_sends_nothing_and_needs_no_log(env, monkeypatch, capsys):
    assert run(env, monkeypatch, "vlan 40\n", "preview", "sw1", log=False) == 0
    assert "PREVIEW (nothing sent) sw1" in capsys.readouterr().out
    assert FakeConn.sent == []


def test_device_error_fails_and_says_so(env, monkeypatch, capsys):
    FakeConn.output = "sw1(config)#vlan 4099\n% Invalid input detected at '^' marker.\n"
    assert run(env, monkeypatch, "vlan 4099\n", "push", "sw1") == 1
    out = capsys.readouterr().out
    assert "FAILED on sw1" in out and "still on the device" in out


def test_netmiko_exception_is_a_failure(env, monkeypatch):
    FakeConn.raise_error = RuntimeError("Invalid input detected")
    assert run(env, monkeypatch, "vlan 40\n", "push", "sw1") == 1


def test_bare_allowed_vlan_refused(env, monkeypatch, capsys):
    assert run(env, monkeypatch, "interface Ethernet0/1\n switchport trunk allowed vlan 40\n", "push", "sw1") == 2
    assert "REFUSED, nothing sent" in capsys.readouterr().out
    assert FakeConn.sent == []


@pytest.mark.parametrize("line", ["switchport trunk allowed vlan add 40", "switchport trunk allowed vlan remove 40",
                                  "switchport trunk allowed vlan except 99", "switchport trunk allowed vlan none"])
def test_allowed_vlan_keywords_pass(env, monkeypatch, line):
    assert run(env, monkeypatch, f"interface Ethernet0/1\n {line}\n", "push", "sw1") == 0


@pytest.mark.parametrize("line", ["reload", "write erase", "erase startup-config", "delete flash:x.bin", "format flash:"])
def test_destructive_refused(env, monkeypatch, line):
    assert run(env, monkeypatch, f"{line}\n", "push", "sw1") == 2
    assert FakeConn.sent == []


def test_untested_vendor_refused_for_push_but_previews(env, monkeypatch):
    assert run(env, monkeypatch, "config system interface\n", "preview", "fw1", log=False) == 0
    assert run(env, monkeypatch, "config system interface\n", "push", "fw1") == 2
    assert FakeConn.sent == []


def test_one_device_per_push(env, monkeypatch):
    with pytest.raises(SystemExit):
        run(env, monkeypatch, "vlan 40\n", "push", "sw1", "sw2")


def test_unknown_device(env, monkeypatch):
    with pytest.raises(SystemExit):
        run(env, monkeypatch, "vlan 40\n", "push", "nope")


def test_save_many(env, monkeypatch, capsys):
    assert run(env, monkeypatch, "", "save", "sw1", "sw2") == 0
    assert FakeConn.saves == 2
    assert "SAVED sw2" in capsys.readouterr().out


BATCH = """@sw1
interface Loopback0
 description Loopback0 | router-id 10.0.0.1
@sw2
interface Vlan10
 no description
"""


def test_batch_pushes_in_order_one_approval(env, monkeypatch, capsys):
    assert run(env, monkeypatch, BATCH, "batch") == 0
    assert [s[1] for s in FakeConn.sent] == [" description Loopback0 | router-id 10.0.0.1", " no description"]
    assert "BATCH OK: sw1, sw2" in capsys.readouterr().out
    assert (env / "change" / "sw2.txt").exists()


def test_batch_refuses_non_description_lines_before_sending(env, monkeypatch, capsys):
    assert run(env, monkeypatch, BATCH + "@sw1\nvlan 40\n", "batch") == 2
    out = capsys.readouterr().out
    assert "REFUSED, nothing sent" in out and "only interface descriptions can be batched" in out
    assert FakeConn.sent == []


def test_batch_stops_at_first_failure(env, monkeypatch, capsys):
    FakeConn.output = "% Invalid input detected at '^' marker.\n"
    assert run(env, monkeypatch, BATCH, "batch") == 1
    assert len(FakeConn.sent) == 1  # sw2 never attempted
    assert "Not sent: ['sw2']" in capsys.readouterr().out


def test_batch_must_start_with_device(env, monkeypatch):
    with pytest.raises(SystemExit):
        run(env, monkeypatch, "interface Loopback0\n description x\n", "batch")


def test_batch_takes_no_device_args(env, monkeypatch):
    with pytest.raises(SystemExit):
        run(env, monkeypatch, BATCH, "batch", "sw1")
