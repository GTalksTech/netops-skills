"""Offline tests for snapshot.py --health: no devices, a fake Netmiko connection.
Run: python -m pytest tests/  (from the network-snapshot skill folder)"""
import json
import subprocess
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import snapshot  # noqa: E402

OUTPUTS = {
    "show version": "R1 uptime is 2 weeks, 3 days, 4 hours, 5 minutes\nLast reload reason: Reload Command\n",
    "show environment all": "% Invalid input detected at '^' marker.\n",
    "show logging": "boom",  # raises in the fake connection
}


class FakeConn:
    def __init__(self, **kw):
        pass

    def send_command(self, cmd, read_timeout=60):
        out = OUTPUTS.get(cmd, f"output of {cmd}\n")
        if out == "boom":
            raise OSError("Pattern not detected: timed out")
        return out

    def is_alive(self):
        return True

    def disconnect(self):
        pass


def setup(tmp_path, monkeypatch):
    sys.modules["netmiko"] = types.SimpleNamespace(ConnectHandler=FakeConn)
    monkeypatch.setattr(snapshot.keyring, "get_password", lambda s, u: "pw")
    (tmp_path / "inventory.yaml").write_text(
        "devices:\n  - {name: r1, host: 10.0.0.1, site: hq, device_type: cisco_ios, username: ro}\n")
    return types.SimpleNamespace(repo=str(tmp_path), inventory=None, site=None, device=None,
                                 workers=1, health=True)


def run(args, capsys):
    snapshot.run(args)
    return json.loads(capsys.readouterr().out)


def test_health_rejected_errors_and_previous(tmp_path, monkeypatch, capsys):
    args = setup(tmp_path, monkeypatch)
    first = run(args, capsys)
    h = first["health"]["r1"]
    assert "show environment all" in h["rejected"]                       # refused, kept apart
    assert first["command_errors"]["r1"][0]["cmd"] == "show logging"     # one bad command ...
    assert "show-ntp-status.txt" in h["files"]                           # ... never costs the rest
    assert h["previous"] is None                                         # first run: no baseline
    second = run(args, capsys)
    prev = second["health"]["r1"]["previous"]
    assert prev and prev["taken"] and Path(prev["dir"], "show-ntp-status.txt").exists()
    assert subprocess.run(["git", "-C", str(tmp_path), "status", "--porcelain"],
                          capture_output=True, text=True).stdout == ""  # health never committed


def test_every_profile_loads_read_only():
    for p in snapshot.PLATFORMS.glob("*.yaml"):
        prof = snapshot.load_profile(p.stem)
        assert prof["health_commands"], f"{p.stem} has no health commands"


def test_uptime_zero_minutes_is_zero_not_unknown():
    rx = r"uptime is (.+)"
    assert snapshot.uptime_seconds("R1 uptime is 0 minutes", rx) == 0
    assert snapshot.uptime_seconds("R1 uptime is 1 minute", rx) == 60
    assert snapshot.uptime_seconds("no uptime line here", rx) is None
