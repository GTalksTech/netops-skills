"""network-diagram end to end: the draw.io file (pages, valid links), the reports, the tag command,
spreadsheet-only runs, the git commit, and the contract with network-snapshot (the commands the
diagram reads are the ones snapshot saves)."""
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent / "scripts"
LIB = HERE.parents[2] / "lib"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(LIB / "tests"))
import topo_fixture  # noqa: E402
import pluginlib  # noqa: E402,F401
import snapshotfiles  # noqa: E402
import topology  # noqa: E402

SNAPSHOT_PLATFORMS = HERE.parents[1] / "network-snapshot" / "platforms"


def run(*args, cwd=None):
    r = subprocess.run([sys.executable, str(SCRIPTS / "diagram.py"), *args], capture_output=True, text=True, cwd=cwd)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@pytest.fixture
def repo(tmp_path):
    return topo_fixture.build(tmp_path / "snapshots")


def pages(path):
    mx = ET.parse(path).getroot()
    return {d.get("name").split(": ", 1)[1]: d for d in mx.iter("diagram")}


def test_run_writes_every_file_and_three_pages(repo):
    rep = run("run", "--repo", str(repo), "--no-export", "--no-commit", "--title", "Test")
    out = repo / "diagrams"
    for name in ("network-diagram.drawio", "report.md", "report.json", "links.csv"):
        assert (out / name).exists(), name
    assert list(pages(out / "network-diagram.drawio")) == ["Physical (L1)", "Subnets (L3)", "VLANs (L2)"]
    assert rep["links_by_kind"] == {"neighbor": 3, "subnet": 2, "tunnel": 1}
    assert rep["unlinked_devices"] == ["lonely-sw-01"] and rep["unknown_neighbors"] == ["mystery-ap"]


def test_every_edge_joins_cells_on_its_own_page(repo):
    run("run", "--repo", str(repo), "--no-export", "--no-commit")
    for name, page in pages(repo / "diagrams" / "network-diagram.drawio").items():
        ids = [el.get("id") for el in page.iter() if el.get("id")]
        assert len(ids) == len(set(ids)), f"duplicate ids on {name}"
        for c in page.iter("mxCell"):
            for end in ("source", "target"):
                if c.get(end):
                    assert c.get(end) in ids, f"{name}: dangling {end}"


def test_subnet_links_are_dashed_and_labelled(repo):
    run("run", "--repo", str(repo), "--no-export", "--no-commit")
    l1 = pages(repo / "diagrams" / "network-diagram.drawio")["Physical (L1)"]
    dashed = [o for o in l1.iter("object") if "dashed=1" in (o.find("mxCell").get("style") or "")
              and o.find("mxCell").get("edge") == "1"]
    assert sorted(o.get("label") for o in dashed) == ["10.0.0.12/30", "10.0.1.0/30", "198.51.100.8/30"]


def test_port_channel_shows_member_count(repo):
    run("run", "--repo", str(repo), "--no-export", "--no-commit")
    text = (repo / "diagrams" / "network-diagram.drawio").read_text(encoding="utf-8")
    assert "Po1 (2 links)" in text


def test_report_lists_gaps_roles_and_mermaid(repo):
    run("run", "--repo", str(repo), "--no-export", "--no-commit")
    md = (repo / "diagrams" / "report.md").read_text(encoding="utf-8")
    for want in ("Links neighbor discovery can't see", "Device roles to confirm", "lonely-sw-01: no role",
                 "--device dist-sw-01 --role distribution", "Unknown neighbors", "```mermaid", "app.diagrams.net"):
        assert want in md, want
    assert "core-sw-01: **core**" not in md         # set in the inventory: nothing to confirm


def test_spreadsheet_only(tmp_path):
    f = tmp_path / "links.csv"
    f.write_text("device_a,port_a,port_b,device_b\nsw-a,Gi1/0/1,Gi1/0/1,sw-b\n", encoding="utf-8")
    rep = run("run", "--repo", str(tmp_path / "none"), "--links", str(f), "--out", str(tmp_path / "out"), "--no-export")
    assert rep["links_by_kind"] == {"spreadsheet": 1}
    assert "not committed" in rep["git"]


def test_tag_shows_then_writes_with_approval(repo):
    dry = run("tag", "--repo", str(repo), "--device", "lonely-sw-01", "--role", "access")
    assert dry["written"] is False and "role" not in yaml.safe_load((repo / "inventory.yaml").read_text())["devices"][6]
    run("tag", "--repo", str(repo), "--device", "lonely-sw-01", "--role", "access", "--write")
    assert yaml.safe_load((repo / "inventory.yaml").read_text())["devices"][6]["role"] == "access"


def test_commits_into_the_snapshot_repo(repo):
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    assert run("run", "--repo", str(repo), "--no-export")["git"] == "committed"
    files = subprocess.run(["git", "-C", str(repo), "show", "--name-only", "--format=", "HEAD"],
                           capture_output=True, text=True).stdout.split()
    assert sorted(files) == ["diagrams/links.csv", "diagrams/network-diagram.drawio",
                             "diagrams/report.json", "diagrams/report.md"]


def test_snapshot_saves_every_command_the_diagram_reads():
    """The contract with network-snapshot: on Cisco IOS (the lab-tested platform) every command
    lib/topology reads is in the snapshot profile, so the saved file names match."""
    profile = yaml.safe_load((SNAPSHOT_PLATFORMS / "cisco_ios.yaml").read_text(encoding="utf-8"))
    saved = {snapshotfiles.slug(c["cmd"]) for c in profile["commands"]}
    for key in ("cdp", "lldp", "config", "descriptions", "trunks", "vlans", "etherchannel"):
        cmds = topology.CMD[key] if isinstance(topology.CMD[key], tuple) else (topology.CMD[key],)
        assert any(snapshotfiles.slug(c) in saved for c in cmds), f"network-snapshot no longer saves {key}"
    forti = yaml.safe_load((SNAPSHOT_PLATFORMS / "fortinet.yaml").read_text(encoding="utf-8"))
    assert snapshotfiles.slug(topology.CMD["fortios"]) in {snapshotfiles.slug(c["cmd"]) for c in forti["commands"]}
