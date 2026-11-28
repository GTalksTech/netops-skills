"""Shared test setup for every plugin's tests (run: py -m pytest plugins, from the repo root).

Every test runs with its own settings file and its own home folder, so no test can read or
write the real network-ops settings (lib/snapshotrepo) or the real ~/network-snapshots.
Scripts started with subprocess inherit the same environment."""
import pytest


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path_factory, monkeypatch):
    base = tmp_path_factory.mktemp("netops-env")
    home = base / "home"
    home.mkdir()
    monkeypatch.setenv("NETOPS_CONFIG", str(base / "settings" / "config.yaml"))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(base / "appdata"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(base / "xdg"))
    monkeypatch.delenv("NETOPS_REPO", raising=False)
    return base
