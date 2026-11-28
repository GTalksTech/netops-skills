"""Shared snapshot file naming: the file network-snapshot saves a command's output to."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import snapshotfiles  # noqa: E402


@pytest.mark.parametrize("cmd,file", [
    ("show running-config", "show-running-config.txt"),
    ("show version", "show-version.txt"),
    ("show configuration | display set", "show-configuration-display-set.txt"),
    ("  Show IP Interface Brief  ", "show-ip-interface-brief.txt"),
    ("get system status", "get-system-status.txt"),
])
def test_slug_is_the_saved_file_name(cmd, file):
    assert snapshotfiles.slug(cmd) == file


def test_both_skills_use_the_one_slug():
    """network-snapshot writes the files and network-diagram (lib/topology) finds them by the same
    name: one function in lib, not a copy in each skill (ADR 0001)."""
    import importlib.util
    skills = Path(__file__).resolve().parents[2] / "skills"
    for script in (skills / "network-snapshot" / "scripts" / "snapshot.py",):
        sys.path.insert(0, str(script.parent))
        try:
            spec = importlib.util.spec_from_file_location(f"_slug_check_{script.stem}", script)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        finally:
            sys.path.remove(str(script.parent))
        assert mod.slug is snapshotfiles.slug, script
    import topology
    assert topology.snapshotfiles is snapshotfiles
