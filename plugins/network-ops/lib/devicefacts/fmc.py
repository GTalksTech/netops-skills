# ============================================================
# Script:       fmc.py
# Purpose:      Device facts for Cisco Secure Firewall Threat Defense (FTD) devices read from
#               their Firewall Management Center (FMC) instead of a snapshot: FTD is managed
#               through FMC, so its software version and model come from FMC's device records.
#               Reads the inventory's 'fmc:' entries and the device records a skill saved from
#               FMC's read-only REST API; never connects to anything itself.
# Usage:        import devicefacts
#               entries, problems = devicefacts.fmc.entries(inventory)
#               recs = devicefacts.fmc.read(entry, saved, platforms, inventory.get("defaults"))
# Author:       G Talks Tech
# Notes:        The saved records ({fmc, collected, domains, devices: [{id, name, domain,
#               sw_version, model, model_number, ftd_mode}]}) are written by network-vuln-scan
#               (scripts/fmc_api.py) to <out>/fmc/<fmc name>.json. See lib/README.md.
# ============================================================
PLATFORM = "cisco_ftd"
SOURCE = "fmc"
# Per-FTD inventory settings under an fmc entry's 'ftd:' (tags the scan reads, like a device's)
FTD_KEYS = ("criticality", "exposure")


def _bad_name(v):
    v = str(v or "")
    return not v.strip() or ".." in v or any(c in v for c in "/\\:")     # ':' is a drive on Windows


def entries(inventory):
    """The inventory's FMC entries ('fmc:' list, next to 'devices:'): ([entry], [problem]). Each
    entry needs name, host and username; credential (the stored password's name, default the
    username), site, port, ca_file, verify_tls and ftd ({FTD name: {criticality, exposure}}) are
    optional. An entry that can't be used is left out with a problem saying why."""
    raw = (inventory or {}).get("fmc") or []
    if not isinstance(raw, list):
        return [], ["inventory fmc: must be a list of FMC entries (name, host, username)"]
    out, problems = [], []
    for i, e in enumerate(raw, 1):
        if not isinstance(e, dict):
            problems.append(f"inventory fmc entry {i} is not a mapping: left out")
            continue
        missing = [k for k in ("name", "host", "username") if not e.get(k)]
        if missing:
            problems.append(f"inventory fmc entry {e.get('name') or i} has no {', '.join(missing)}: left out")
            continue
        if _bad_name(e["name"]) or _bad_name(e.get("site", "unassigned")):
            problems.append(f"inventory fmc entry {e['name']!r}: name or site contains '..', '/', '\\' or ':': left out")
            continue
        if e.get("ftd") is not None and not isinstance(e["ftd"], dict):
            problems.append(f"inventory fmc entry {e['name']}: ftd: must map FTD names to tags: ignored")
            e = {k: v for k, v in e.items() if k != "ftd"}
        out.append({"site": "unassigned", **e})
    return out, problems


def ftd_entry(entry, name, defaults=None):
    """The inventory-like entry of one FTD the FMC manages: the inventory defaults' tags, then the
    tags set for it under the FMC entry's 'ftd:'. What tags.read and the like take."""
    over = ((entry or {}).get("ftd") or {}).get(name) or {}
    base = {k: v for k, v in (defaults or {}).items() if k in FTD_KEYS}
    return {"name": name, "site": entry.get("site", "unassigned"), "device_type": PLATFORM, "managed_by": entry["name"],
            **base, **{k: v for k, v in (over if isinstance(over, dict) else {}).items() if k in FTD_KEYS}}


def read(entry, saved, platforms, defaults=None):
    """Device facts records for every FTD in one FMC's saved device records (none when nothing was
    saved). The same record fields as devicefacts.read_device, plus source 'fmc', managed_by (the
    FMC's name), collected (when FMC was read) and domain. There is no config: features are empty,
    and exposure is the inventory's tag, else a firewall's assumed edge."""
    pcfg = (platforms or {}).get(PLATFORM) or {}
    out, seen = [], set()
    for dev in (saved or {}).get("devices") or []:
        name = str(dev.get("name") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        inv = ftd_entry(entry, name, defaults)
        when = (saved.get("collected") or "")[:16].replace("T", " ")
        where = f"FMC {entry['name']} device record" + (f" (domain {dev['domain']})" if dev.get("domain") else "") \
            + (f", read {when}" if when else "")
        rec = {"name": name, "site": inv["site"], "platform": PLATFORM, "vendor": pcfg.get("vendor", "Cisco"),
               "kind": pcfg.get("kind", "firewall"), "hostname": None, "version": None, "version_evidence": None,
               "model": None, "model_evidence": None, "os": None, "os_evidence": None, "features": {}, "notes": [],
               "interface_ips": [], "internet_interfaces": [], "_parsed": None, "source": SOURCE,
               "managed_by": entry["name"], "collected": saved.get("collected"), "domain": dev.get("domain")}
        ver = str(dev.get("sw_version") or "").strip()
        if ver:
            rec["version"], rec["version_evidence"] = ver, f"{where}: sw_version {ver}"
        else:
            rec["notes"].append(f"FMC {entry['name']} lists no software version for {name}: nothing can be "
                                "matched by version")
        if dev.get("model"):
            rec["model"] = str(dev["model"]).strip()
            rec["model_evidence"] = f"{where}: model {rec['model']}"
        exp = inv.get("exposure")
        if exp in ("public", "internal"):
            rec["internet_facing"], rec["exposure_reason"] = exp == "public", f"set in inventory (exposure: {exp})"
        else:
            rec["internet_facing"] = True
            rec["exposure_reason"] = ("firewall: assumed internet-facing (FTD read from FMC: no config read); set "
                                      f"exposure under the fmc entry's ftd: {name} in the inventory")
        out.append(rec)
    return out
