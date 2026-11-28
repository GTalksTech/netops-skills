"""snapshotrepo: the order the snapshot repo is found in, the .netops.yaml walk-up, adopting the
old ~/network-snapshots, the no_snapshot_repo failure and --set-repo's refusals. The settings file
and the home folder are temp folders (plugins/conftest.py); nothing real is read or written.
Run: py -m pytest plugins (repo root)."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

LIB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LIB))
import snapshotrepo  # noqa: E402

SNAPSHOT = LIB.parent / "skills" / "network-snapshot" / "scripts" / "snapshot.py"


def settings():
    return yaml.safe_load(snapshotrepo.settings_path().read_text(encoding="utf-8"))


@pytest.fixture
def two(tmp_path):
    """Settings with two networks, lab the default."""
    snapshotrepo.set_repo(tmp_path / "lab-snaps", "lab")
    snapshotrepo.set_repo(tmp_path / "prod-snaps", "prod")
    return tmp_path


def test_settings_file_follows_netops_config_then_the_os_convention(tmp_path):
    assert snapshotrepo.settings_path() == Path(os.environ["NETOPS_CONFIG"])
    if os.name == "nt":
        assert snapshotrepo.settings_path({"APPDATA": r"C:\A"}) == Path(r"C:\A") / "netops" / "config.yaml"
    assert snapshotrepo.settings_path({"XDG_CONFIG_HOME": str(tmp_path)}) == tmp_path / "netops" / "config.yaml"


def test_nothing_set_up_is_no_snapshot_repo_and_creates_nothing(tmp_path):
    with pytest.raises(snapshotrepo.RepoError) as e:
        snapshotrepo.resolve(cwd=tmp_path)
    assert e.value.code == "no_snapshot_repo"
    assert not snapshotrepo.settings_path().exists()
    assert not (Path.home() / "network-snapshots").exists()


def test_order_flag_then_env_then_pointer_then_default(two, monkeypatch):
    project = two / "project" / "sub"
    project.mkdir(parents=True)
    assert snapshotrepo.resolve(cwd=project)["network"] == "lab"                     # 4. default
    (two / "project" / ".netops.yaml").write_text("network: prod\n", encoding="utf-8")
    loc = snapshotrepo.resolve(cwd=project)                                          # 3. pointer, walked up
    assert (loc["network"], loc["path"]) == ("prod", two / "prod-snaps")
    monkeypatch.setenv("NETOPS_REPO", str(two / "lab-snaps"))
    assert snapshotrepo.resolve(cwd=project)["source"] == "NETOPS_REPO"              # 2. env
    assert snapshotrepo.resolve(cwd=project)["network"] == "lab"
    assert snapshotrepo.resolve(network="prod", cwd=project)["source"] == "--network"  # 1. flags
    loc = snapshotrepo.resolve(repo=str(two / "elsewhere"), cwd=project)
    assert (loc["source"], loc["network"]) == ("--repo", None)


def test_pointer_naming_an_unknown_network_fails_clearly(two):
    (two / ".netops.yaml").write_text("network: staging\n", encoding="utf-8")
    with pytest.raises(snapshotrepo.RepoError) as e:
        snapshotrepo.resolve(cwd=two)
    assert e.value.code == "unknown_network" and "staging" in e.value.message


def test_old_default_is_adopted_once_and_saved(tmp_path):
    old = Path.home() / "network-snapshots"
    old.mkdir()
    (old / "inventory.yaml").write_text("devices: []\n", encoding="utf-8")
    loc = snapshotrepo.resolve(cwd=tmp_path)
    assert loc["path"] == old and loc["source"] == "adopted" and "old default" in loc["note"]
    assert settings() == {"networks": {"main": str(old)}, "default": "main"}
    again = snapshotrepo.resolve(cwd=tmp_path)
    assert again["source"] == "default" and again["note"] is None                   # said once only


def test_old_folder_without_inventory_is_not_adopted(tmp_path):
    (Path.home() / "network-snapshots").mkdir()
    with pytest.raises(snapshotrepo.RepoError):
        snapshotrepo.resolve(cwd=tmp_path)


def test_several_networks_and_no_default_asks_for_a_name(tmp_path):
    p = snapshotrepo.settings_path()
    p.parent.mkdir(parents=True)
    p.write_text(f"networks: {{a: {tmp_path / 'a'}, b: {tmp_path / 'b'}}}\n", encoding="utf-8")
    with pytest.raises(snapshotrepo.RepoError) as e:
        snapshotrepo.resolve(cwd=tmp_path)
    assert e.value.code == "no_snapshot_repo" and e.value.extra["networks"] == ["a", "b"]


def test_set_repo_creates_the_folder_and_makes_the_first_network_the_default(tmp_path):
    out = snapshotrepo.set_repo(tmp_path / "snaps")
    assert out["created"] and (tmp_path / "snaps").is_dir()
    assert settings() == {"networks": {"main": str(tmp_path / "snaps")}, "default": "main"}
    assert snapshotrepo.set_repo(tmp_path / "snaps")["created"] is False             # same again: fine


def test_set_repo_never_overwrites_silently(two):
    with pytest.raises(snapshotrepo.RepoError) as e:
        snapshotrepo.set_repo(two / "new", "prod")
    assert e.value.code == "network_exists" and settings()["networks"]["prod"] == str(two / "prod-snaps")
    with pytest.raises(snapshotrepo.RepoError) as e:
        snapshotrepo.set_repo(two / "lab-snaps", "prod")                             # another network's folder
    assert e.value.code == "path_in_use"
    out = snapshotrepo.set_repo(two / "new", "prod", replace=True)
    assert out["replaced"] == str(two / "prod-snaps")
    assert settings()["networks"] == {"lab": str(two / "lab-snaps"), "prod": str(two / "new")}
    assert settings()["default"] == "lab"


def test_banner_and_report_fields(two):
    loc = snapshotrepo.resolve(network="lab")
    assert snapshotrepo.banner(loc) == f"Snapshot repo: {two / 'lab-snaps'} (network: lab)"
    assert snapshotrepo.report_fields(loc) == {"repo": str(two / "lab-snaps"), "network": "lab"}


def cli(*args, cwd):
    return subprocess.run([sys.executable, str(SNAPSHOT), *args], capture_output=True, text=True, cwd=cwd)


def test_snapshot_cli_reports_no_snapshot_repo_as_json_and_exit_3(tmp_path):
    r = cli("--site", "hq", cwd=tmp_path)
    assert r.returncode == snapshotrepo.EXIT_CODE and r.stdout == ""
    assert json.loads(r.stderr.strip().splitlines()[-1])["error"] == "no_snapshot_repo"


def test_snapshot_cli_set_repo_saves_and_refuses_a_silent_move(tmp_path):
    r = cli("--set-repo", str(tmp_path / "snaps"), cwd=tmp_path)
    assert r.returncode == 0 and "network 'main'" in r.stdout and "folder created" in r.stdout
    r = cli("--set-repo", str(tmp_path / "other"), cwd=tmp_path)
    assert r.returncode == snapshotrepo.EXIT_CODE
    assert json.loads(r.stderr)["error"] == "network_exists"
    r = cli("--set-repo", str(tmp_path / "other"), "--replace", cwd=tmp_path)
    assert r.returncode == 0 and "Replaced" in r.stdout
    r = cli("--set-repo", str(tmp_path / "lab"), "--network", "lab", cwd=tmp_path)
    assert r.returncode == 0 and settings()["default"] == "main"
