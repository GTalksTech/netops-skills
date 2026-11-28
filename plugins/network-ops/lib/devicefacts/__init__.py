# ============================================================
# Package:      devicefacts
# Purpose:      Device facts for every network-ops skill that reads saved device output: what
#               a device's snapshot (config and show output saved by network-snapshot) shows
#               about its software version and model, which interfaces face the internet,
#               and which features are on, off or unknown. Each fact carries the lines that
#               prove it. Read-only: works from files, never connects to a device.
# Usage:        import devicefacts
#               platforms = devicefacts.load_platforms()
#               rec = devicefacts.read_device(inventory_entry, snapshot_repo, platforms)
#               rec["features"]["http_server"]["state"]    # "on" | "off" | "unknown"
# Author:       G Talks Tech
# Notes:        See lib/README.md for the record's fields and how a skill imports this.
# ============================================================
import re
from pathlib import Path

import yaml

import devicetags

from . import asa, fmc, fortios, ios, junos, panos  # noqa: F401  (fmc: FTD facts from FMC records)
from .facts import OFF, ON, STATES, UNKNOWN, all_unknown, proof  # noqa: F401  (public names)

HERE = Path(__file__).resolve().parent
READERS = {"ios": ios, "fortios": fortios, "panos": panos, "asa": asa, "junos_set": junos}
SWITCH_MODELS = r"(?i)^(C9[2-6]\d\d|WS-C|C[1-3]\d{3}|IE-|C1000|CBS)"


def load_platforms():
    """{device_type: {vendor, kind, version: {file, regex, model, model_file}, config: {file, parser}}}
    (an entry with source: fmc has vendor and kind only: its facts come from devicefacts.fmc)"""
    return yaml.safe_load((HERE / "platforms.yaml").read_text(encoding="utf-8"))


def read_device(dev, repo, platforms):
    """Device facts for one inventory entry, from its folder <repo>/<site>/<name>.

    platforms: load_platforms(), or a dict whose entries hold at least those keys (a skill may
    merge its own settings in). The record: name, site, platform, vendor, kind, hostname, version
    and model (each with *_evidence, the show line that gave it), os (which OS the device runs
    where one platform covers two, e.g. IOS or IOS XE; None elsewhere), internet_facing and
    exposure_reason, internet_interfaces ([{name, why, evidence}]), interface_ips, features
    ({name: {state, internet, where, evidence, detail}}) and notes (what could not be read).

    The parsed config stays on the record under '_parsed' ({text, facts, dev}) for a caller that
    runs config checks on the same facts; drop it before saving the record."""
    out = {"name": dev["name"], "site": dev.get("site", "unassigned"), "platform": dev.get("device_type", ""),
           "hostname": None, "version": None, "version_evidence": None, "model": None, "model_evidence": None,
           "os": None, "os_evidence": None, "features": {}, "notes": [], "interface_ips": [], "internet_interfaces": [], "_parsed": None}
    p = out["platform"]
    pcfg = platforms.get(p)
    # The folder comes from inventory text: never let a name or site walk out of the snapshot repo.
    bad = [v for v in (str(out["site"]), str(dev["name"])) if ".." in v or "/" in v or "\\" in v or not v.strip()]
    if bad:
        out["notes"].append(f"inventory site/name {bad[0]!r} contains '..', '/' or '\\': device skipped")
        return out
    folder = repo / out["site"] / dev["name"]
    if not pcfg:
        out["notes"].append(f"no settings for device_type '{p}': not read")
        return out
    out["vendor"] = pcfg["vendor"]
    out["kind"] = devicetags.kind_of(dev, pcfg["kind"])   # role firewall -> firewall (ADR 0002)
    if pcfg.get("source") == fmc.SOURCE:
        out["notes"].append(f"{p} versions are read from FMC (the inventory's fmc: entries, devicefacts.fmc), "
                            "not from a snapshot: list the FMC under fmc:, not the device under devices:")
        return out
    if not folder.exists():
        out["notes"].append(f"no snapshot folder {folder}: run network-snapshot first")
        return out
    _version(out, folder, pcfg["version"])

    cfg = folder / pcfg["config"]["file"]
    reader = READERS.get(pcfg["config"]["parser"])
    facts = None
    dev = {**dev, "_is_switch": bool(re.match(SWITCH_MODELS, out["model"] or "")), "_folder": folder}
    if reader and cfg.exists():
        text = cfg.read_text(encoding="utf-8", errors="replace")
        try:
            facts = reader.read(text, dev)
        except Exception as e:  # one unreadable config never stops the run
            out["notes"].append(f"config parser failed on {cfg.name} ({type(e).__name__}: {e}): feature "
                                "conditions skipped. Please report this with a sanitized copy of the config.")
        else:
            out["_parsed"] = {"text": text, "facts": facts, "dev": dev}
    if facts is not None:
        out["hostname"] = facts["hostname"]
        out["notes"] += facts["notes"]
        out["interface_ips"] = [ip.split("/")[0] for i in facts["interfaces"] for ip in i.get("ips", [])]
        out["internet_interfaces"] = [{"name": i["name"], "why": i.get("internet_why"),
                                       "evidence": i.get("internet_evidence", [])}
                                      for i in facts["interfaces"] + facts.get("zones", []) if "internet_evidence" in i]
        if not facts["interfaces"]:
            # Nothing the reader found can be trusted as "off" when it found no interfaces.
            all_unknown(facts, "config parsed to no interfaces")
            out["notes"].append(f"config in {cfg.name} parsed to no interfaces: the format may be one this "
                                "parser doesn't read (for PAN-OS, the default brace format is needed, not "
                                "'set cli config-output-format set/json/xml'). "
                                "Feature conditions are unreliable for this device.")
        out["features"] = facts["features"]
    elif reader and not cfg.exists():
        out["notes"].append(f"config file {cfg.name} missing: feature conditions skipped")
    elif not reader:
        out["notes"].append("no config parser for this platform yet: version only, exposure from the inventory")

    override = dev.get("exposure")
    if override in ("public", "internal"):
        out["internet_facing"] = override == "public"
        out["exposure_reason"] = f"set in inventory (exposure: {override})"
    elif facts is not None:
        out["internet_facing"] = facts["internet_facing"]
        out["exposure_reason"] = facts["exposure_reason"]
        if not facts["internet_facing"] and out["kind"] == "firewall" and not facts["interfaces"]:
            out["internet_facing"], out["exposure_reason"] = True, "firewall with no interfaces parsed: assumed edge"
    else:
        edge = out["kind"] == "firewall"
        out["internet_facing"] = edge
        out["exposure_reason"] = ("firewall: assumed internet-facing" if edge else
                                  "assumed internal (no config parser): set exposure: public in the "
                                  "inventory if it faces the internet")
    return out


def _version(out, folder, vcfg):
    """Software version and model from the show output named in platforms.yaml."""
    vf = folder / vcfg["file"]
    if vf.exists():
        txt = vf.read_text(encoding="utf-8", errors="replace")
        m = re.search(vcfg["regex"], txt, re.M)
        if m:
            g = next(i for i, x in enumerate(m.groups(), 1) if x)
            out["version"] = m.group(g)
            out["version_evidence"] = f"{vf.name}: {_line_at(txt, m.start(g))}"   # the line the version is on
            _suffix(out, txt, vcfg.get("suffix"))
        _os(out, vf.name, txt, vcfg.get("os"))
        if vcfg.get("model"):
            mf = folder / vcfg.get("model_file", vcfg["file"])
            mtxt = mf.read_text(encoding="utf-8", errors="replace") if mf.exists() else ""
            mm = re.search(vcfg["model"], mtxt, re.M | re.I)
            out["model"] = mm.group(1).strip() if mm else None
            out["model_evidence"] = f"{mf.name}: {_line_at(mtxt, mm.start())}" if mm else None
            if not mm:
                out["notes"].append(f"model not found in {mf.name}")
    if not out["version"]:
        out["notes"].append(f"software version not found in {vf.name}: nothing can be matched by version "
                            "(CVEs, end of support)")


def _suffix(out, txt, scfg):
    """A part of the release printed on its own line, added to the version: ISE prints its patch
    in a separate block ('Version : 2' under 'Cisco Identity Services Engine Patch'), and Cisco
    names the release '3.3 Patch 2'. scfg: {regex (group 1 = a number), format ('{}' takes
    it), label (for the proof)}. Several matches (one block per patch installed): the highest."""
    if not scfg:
        return
    found = [(int(m.group(1)), m.start(1)) for m in re.finditer(scfg["regex"], txt, re.M)]
    if found:
        val, pos = max(found)
        out["version"] += scfg["format"].format(val)
        out["version_evidence"] += f"; {scfg.get('label', 'and')}: {_line_at(txt, pos)}"


def _os(out, fname, txt, rules):
    """Which OS the device runs, where one platform covers two (IOS and IOS XE share cisco_ios):
    the first rule [{name, regex}] whose regex is found in the version file."""
    for r in rules or []:
        m = re.search(r["regex"], txt, re.M)
        if m:
            out["os"], out["os_evidence"] = r["name"], f"{fname}: {_line_at(txt, m.start())}"
            return
    if rules and out["version"]:
        out["notes"].append(f"which OS this device runs is not clear from {fname}")


def _line_at(text, pos):
    """The whole line of text that holds position pos, stripped."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start:end if end >= 0 else len(text)].strip()