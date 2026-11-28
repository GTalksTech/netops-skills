"""snapshot.py gets its passwords from the shared credential lookup (lib/credentials).
Offline: a fake Netmiko connection records the password it was given."""
import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import snapshot  # noqa: E402

SECRET = "s3cr3t-Pa55"


class FakeConn:
    logins = []

    def __init__(self, **kw):
        FakeConn.logins.append((kw["username"], kw["password"]))

    def send_command(self, cmd, read_timeout=60):
        return "R1 uptime is 2 weeks, 3 days\n" if cmd == "show version" else f"output of {cmd}\n"

    def is_alive(self):
        return True

    def disconnect(self):
        pass


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "netmiko", types.SimpleNamespace(ConnectHandler=FakeConn))
    FakeConn.logins = []
    saved = {}
    monkeypatch.setattr(snapshot.credentials.keyring, "get_password", lambda s, u: saved.get((s, u)))
    monkeypatch.delenv("NETOPS_SECRET_RO", raising=False)
    (tmp_path / "inventory.yaml").write_text(
        "devices:\n  - {name: r1, host: 10.0.0.1, site: hq, device_type: cisco_ios, username: ro}\n")
    args = types.SimpleNamespace(repo=str(tmp_path), inventory=None, site=None, device=None,
                                 workers=1, health=False)
    return types.SimpleNamespace(path=tmp_path, store=saved, args=args)


def run(lab, capsys):
    snapshot.run(lab.args)
    out = capsys.readouterr().out
    return json.loads(out), out


def test_password_already_in_the_os_store_still_works(lab, capsys):
    # stored earlier with `snapshot.py --set-credential ro`: same service, same name
    lab.store[("netops-skills", "ro")] = SECRET
    report, _ = run(lab, capsys)
    assert report["devices_ok"] == ["r1"]
    assert FakeConn.logins == [("ro", SECRET)]


def test_password_from_an_environment_variable(lab, monkeypatch, capsys):
    monkeypatch.setenv("NETOPS_SECRET_RO", SECRET)
    report, _ = run(lab, capsys)
    assert report["devices_ok"] == ["r1"] and FakeConn.logins == [("ro", SECRET)]


def test_password_from_the_inventory_command(lab, capsys):
    exe = Path(sys.executable).as_posix()
    (lab.path / "inventory.yaml").write_text(
        f"credentials:\n  command: [\"{exe}\", \"-c\", \"print('{SECRET}')\"]\n"
        "devices:\n  - {name: r1, host: 10.0.0.1, site: hq, device_type: cisco_ios, username: ro}\n")
    report, _ = run(lab, capsys)
    assert report["devices_ok"] == ["r1"] and FakeConn.logins == [("ro", SECRET)]


def test_no_password_anywhere_is_a_failure_that_names_the_fixes(lab, capsys):
    report, _ = run(lab, capsys)
    assert report["devices_ok"] == [] and FakeConn.logins == []
    err = report["failures"][0]["error"]
    assert "NETOPS_SECRET_RO" in err and "--set-credential ro" in err


def test_secret_never_reaches_the_report(lab, capsys):
    lab.store[("netops-skills", "ro")] = SECRET
    _, out = run(lab, capsys)
    assert SECRET not in out
    assert SECRET not in (lab.path / ".snapshot" / "last-report.json").read_text()
    assert not any(SECRET in p.read_text(errors="ignore")
                   for p in lab.path.rglob("*") if p.is_file() and ".git" not in p.parts)
