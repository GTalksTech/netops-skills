"""One set of device tags for every skill (ADR 0002): role guessing, kind derived from role,
and the approved-only tag writer that keeps the inventory's comments and layout."""
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import devicetags  # noqa: E402
import topo_fixture  # noqa: E402


@pytest.mark.parametrize("name,role", [
    ("hq-edge-rtr-01", "edge"), ("fw-01", "firewall"), ("hq-core-sw-01", "core"),
    ("hq-dist-sw-02", "distribution"), ("hq-acc-sw-03", "access"), ("isp-rtr-01", "provider"),
    ("branch1-sw-01", None), ("paris-sw-01", None), ("pa-01", "firewall"),
])
def test_guess_role(name, role):
    assert devicetags.guess_role(name)[0] == role


def test_inventory_role_wins_and_bad_values_are_ignored():
    assert devicetags.role_of({"name": "hq-acc-sw-01", "role": "core"}) == ("core", "inventory")
    role, why = devicetags.role_of({"name": "hq-acc-sw-01", "role": "spine"})
    assert role == "access" and "guessed" in why


def test_kind_comes_from_role():
    assert devicetags.kind_of({"role": "firewall"}, "router_switch") == "firewall"
    assert devicetags.kind_of({"role": "core"}, "firewall") == "router_switch"
    assert devicetags.kind_of({"kind": "firewall"}, "router_switch") == "firewall"   # old override still read
    assert devicetags.kind_of({}, "router_switch") == "router_switch"


def test_devicefacts_kind_follows_role(tmp_path):
    import devicefacts
    rec = devicefacts.read_device({"name": "srx-01", "site": "hq", "device_type": "juniper_junos", "role": "firewall"},
                                  tmp_path, devicefacts.load_platforms())
    assert rec["kind"] == "firewall"


def test_apply_shows_then_writes_role_keeping_comments(tmp_path):
    inv = tmp_path / "inventory.yaml"
    inv.write_text(topo_fixture.INVENTORY, encoding="utf-8")
    dry = devicetags.apply(inv, "dist-sw-01", {"role": "distribution"})
    assert dry["written"] is False and inv.read_text(encoding="utf-8") == topo_fixture.INVENTORY
    devicetags.apply(inv, "dist-sw-01", {"role": "distribution"}, write=True)
    devicetags.apply(inv, "core-sw-01", {"role": "edge"}, write=True)            # block mapping, replaced
    text = inv.read_text(encoding="utf-8")
    assert "# the core" in text and "# Lab inventory (test)" in text
    devs = {d["name"]: d for d in yaml.safe_load(text)["devices"]}
    assert devs["dist-sw-01"]["role"] == "distribution" and devs["core-sw-01"]["role"] == "edge"


def test_apply_refuses_unknown_role_and_tags_a_caller_may_not_set(tmp_path):
    inv = tmp_path / "inventory.yaml"
    inv.write_text(topo_fixture.INVENTORY, encoding="utf-8")
    with pytest.raises(devicetags.TagError):
        devicetags.apply(inv, "fw-01", {"role": "spine"}, write=True)
    with pytest.raises(devicetags.TagError):
        devicetags.apply(inv, "fw-01", {"criticality": "essential"}, write=True, allowed={"role": devicetags.ROLES})
    assert inv.read_text(encoding="utf-8") == topo_fixture.INVENTORY
