"""FortiGate paging: netmiko's Fortinet driver (4.8.0, fortinet_ssh.py) sends
'config system console' / 'set output standard' when the console pages ('more'), puts 'more' back
at logout, and enters 'config global' on VDOM boxes just to read the mode. The read-only
connection must refuse instead, sending nothing but reads. Offline: a fake base connection
records every string sent. Run: python -m pytest plugins (repo root)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import fortigate_guard  # noqa: E402

STATUS = "Version: FortiGate-VM64 v8.0.1,build0123,251117 (GA.F)\nVirtual domain configuration: {vd}\n"
CONSOLE = "mode                : line\nbaudrate            : 9600\noutput              : {mode}\nlogin               : enable\n"


class FakeBase:
    """Stands in for netmiko's FortinetSSH: the methods the guard calls or overrides."""
    prompt_pattern = r"[#$]"

    def __init__(self, vd="disable", mode="standard"):
        self.sent, self.vd, self.mode = [], vd, mode

    def _test_channel_read(self, pattern=None):
        return "fw-01 # "

    def write_channel(self, data):
        self.sent.append(data)

    def set_base_prompt(self, *a, **k):
        return "fw-01"

    def _send_command_str(self, cmd, **kw):
        self.sent.append(cmd)
        if cmd == "get system status":
            return STATUS.format(vd=self.vd)
        if cmd == "get system console":
            return CONSOLE.format(mode=self.mode) if self.mode else "Command fail. Return code -61\n"
        return ""

    def send_multiline(self, cmds, **kw):
        self.sent.extend(cmds)
        return ""

    def disable_paging(self, *a, **k):  # the driver's version: writes config
        self.send_multiline(["config system console", "set output standard", "end"])

    def cleanup(self, command="exit"):
        self.sent.append(command)


Guarded = type("Guarded", (fortigate_guard.ReadOnlyFortinetMixin, FakeBase), {})


def writes(conn):
    return [s for s in conn.sent if s.split()[0] in ("config", "set", "end", "edit", "unset", "execute")]


def test_console_in_standard_mode_proceeds_with_reads_only():
    c = Guarded(mode="standard")
    c.session_preparation()
    c.disable_paging()
    c.cleanup()
    assert writes(c) == []
    assert c.sent == ["get system status", "get system console", "exit"]


def test_console_in_more_mode_is_refused_before_any_command_with_the_fix():
    c = Guarded(mode="more")
    with pytest.raises(fortigate_guard.ReadOnlyRefused) as e:
        c.session_preparation()
    assert "set output standard" in str(e.value) and "config system console" in str(e.value)
    c.cleanup()
    assert writes(c) == []


def test_unreadable_console_mode_is_refused():
    c = Guarded(mode=None)
    with pytest.raises(fortigate_guard.ReadOnlyRefused):
        c.session_preparation()
    assert writes(c) == []


def test_vdom_mode_is_refused_without_entering_config_global():
    c = Guarded(vd="multiple")
    with pytest.raises(fortigate_guard.ReadOnlyRefused, match="VDOM"):
        c.session_preparation()
    assert writes(c) == [] and "config global" not in c.sent


def test_paging_and_logout_never_write_even_if_called_directly():
    c = Guarded(mode="standard")
    c._original_output_mode = "more"   # what the driver would have recorded
    c.disable_paging()
    c.cleanup()
    assert writes(c) == []
    with pytest.raises(fortigate_guard.ReadOnlyRefused):
        c._config_global()


def test_mode_parser():
    assert fortigate_guard.output_mode(CONSOLE.format(mode="standard")) == "standard"
    assert fortigate_guard.output_mode(CONSOLE.format(mode="more")) == "more"
    assert fortigate_guard.output_mode("Command fail") is None
    assert fortigate_guard.vdoms_enabled(STATUS.format(vd="multiple")) is True
    assert fortigate_guard.vdoms_enabled(STATUS.format(vd="split-task")) is True
    assert fortigate_guard.vdoms_enabled(STATUS.format(vd="disable")) is False


def test_the_installed_driver_still_has_the_behavior_we_guard_against():
    """If netmiko changes these methods, re-read its source and revisit the guard."""
    netmiko = pytest.importorskip("netmiko")
    import inspect
    from netmiko.fortinet.fortinet_ssh import FortinetSSH
    src = inspect.getsource(FortinetSSH)
    assert "set output standard" in src and "config global" in src
    for name in ("session_preparation", "disable_paging", "cleanup", "_config_global", "_get_output_mode"):
        assert hasattr(FortinetSSH, name), name
    assert netmiko.__version__
