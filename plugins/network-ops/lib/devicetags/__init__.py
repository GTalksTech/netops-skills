# ============================================================
# Package:      devicetags
# Purpose:      The device tags every network-ops skill reads from the inventory, defined once
#               (docs/adr/0002): device role, asset criticality and exposure. Reads a device's
#               role (or guesses it from the name, marked as a guess), derives the platform-level
#               kind (firewall | router_switch) from the role, and writes a tag to inventory.yaml
#               only when the engineer approved that exact change.
# Usage:        import devicetags
#               role, why = devicetags.role_of(entry)          # ("core", "inventory") or a guess
#               kind = devicetags.kind_of(entry, platform_kind)
#               devicetags.apply(Path("inventory.yaml"), "hq-core-sw-01", {"role": "core"}, write=True)
# Author:       G Talks Tech
# Notes:        Writing keeps the inventory's comments and layout, and is checked by reading the
#               file back: if anything but those tags would change, nothing is written.
# ============================================================
import os
import re

import yaml

ROLES = ("provider", "edge", "firewall", "core", "distribution", "access")
CRITICALITY = ("essential", "support", "minimal")
EXPOSURE = ("public", "internal")
TAGS = {"role": ROLES, "criticality": CRITICALITY, "exposure": EXPOSURE}

# Words in a device name that suggest its role, checked in this order. A guess is only a guess:
# the report shows it with the word that matched, and the engineer confirms it with the tag command.
ROLE_WORDS = (("provider", ("isp", "carrier", "provider", "internet")),
              ("firewall", ("fw", "firewall", "fgt", "asa", "pa", "srx")),
              ("edge", ("edge", "border", "wan", "rtr", "router", "gw")),
              ("core", ("core", "spine")),
              ("distribution", ("dist", "agg", "leaf")),
              ("access", ("acc", "access", "idf")))


def guess_role(name):
    """(role, word) guessed from a device name, or (None, None). A word must stand on its own
    between separators (hq-fw-01, fw01): 'paris-sw' is not a Palo Alto."""
    n = str(name).lower()
    for role, words in ROLE_WORDS:
        for w in words:
            if re.search(rf"(^|[-_.\s]){w}(\d|$|[-_.\s])", n):
                return role, w
    return None, None


def role_of(dev):
    """(role, source) for an inventory entry. source is 'inventory', 'guessed from name "X"
    (word "w")', or None when there is neither. A role the inventory spells wrong is not used."""
    val = dev.get("role")
    if val in ROLES:
        return val, "inventory"
    role, word = guess_role(dev.get("name", ""))
    if role:
        return role, f'guessed from the name (word "{word}")'
    return None, None


def kind_of(dev, platform_kind):
    """firewall | router_switch for one inventory entry: from its role when it has one in the
    inventory, else from an old 'kind:' override, else the platform's default."""
    if dev.get("role") in ROLES:
        return "firewall" if dev["role"] == "firewall" else "router_switch"
    return dev.get("kind", platform_kind)


# ---------- writing a tag (only from a tag command the user approved) ----------
class TagError(Exception):
    """A tag the command can't write: nothing was changed."""


def apply(inventory, device, values, write=False, allowed=None):
    """Set tags ({tag: value}) on one device in the inventory file. Shows the change, and writes it
    only when write=True (the user approved it). allowed limits which tags this caller may set
    (default: all of TAGS). Returns {device, changes: [{tag, from, to}], written, inventory}."""
    allowed = allowed or TAGS
    if not values:
        raise TagError(f"nothing to set: give {' and/or '.join('--' + t for t in allowed)}")
    for tag, val in values.items():
        if tag not in allowed or val not in allowed[tag]:
            raise TagError(f"{tag} must be one of {', '.join(allowed.get(tag, ()))}, not {val!r}")
    with open(inventory, encoding="utf-8", newline="") as f:     # keep CRLF line endings as they are
        text = f.read()
    before = yaml.safe_load(text) or {}
    entries = [d for d in before.get("devices") or [] if isinstance(d, dict) and d.get("name") == device]
    if len(entries) != 1:
        raise TagError(f"{device!r} is {'not' if not entries else 'more than once'} in {inventory}")
    old = entries[0]
    changes = [{"tag": t, "from": old.get(t), "to": v} for t, v in values.items() if old.get(t) != v]
    out = {"device": device, "changes": changes, "written": False, "inventory": str(inventory)}
    if not changes or not write:
        return out
    new = text
    for c in changes:
        new = _set_key(new, device, c["tag"], c["to"])
    want = {**before, "devices": [{**d, **values} if d is old else d for d in before.get("devices") or []]}
    if (yaml.safe_load(new) or {}) != want:
        raise TagError(f"could not edit {inventory} safely: add "
                       f"{', '.join(f'{t}: {v}' for t, v in values.items())} to {device} by hand")
    tmp = inventory.with_name(inventory.name + ".tagging")
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(new)
    os.replace(tmp, inventory)
    out["written"] = True
    return out


def _set_key(text, device, key, value):
    """The inventory text with key: value set on the device's entry: a one-line flow mapping
    ({name: X, ...}) or a block mapping (name: X on its own line). Unchanged if neither is found
    (apply() then refuses, since the file read back is not what it should be)."""
    lines = text.splitlines(keepends=True)
    name = rf"""(?:{re.escape(device)}|'{re.escape(device)}'|"{re.escape(device)}")"""
    for i, ln in enumerate(lines):
        # one-line flow mapping only: the closing brace must be on the same line, before any comment
        code = ln.split("#", 1)[0]
        if re.match(rf"^\s*-\s*\{{(?:[^}}]*,)?\s*name:\s*{name}\s*[,}}]", ln) and "}" in code:
            cut = code.rindex("}")
            body = ln[:cut]
            if re.search(rf"[{{,]\s*{key}:", body):
                body = re.sub(rf"([{{,]\s*{key}:\s*)[^,}}\s]*", rf"\g<1>{value}", body)
            else:
                body = body.rstrip() + f", {key}: {value}"
            lines[i] = body + ln[cut:]
            return "".join(lines)
    for i, ln in enumerate(lines):
        m = re.match(rf"^(\s*)(-\s+)?name:\s*{name}\s*(#.*)?$", ln.rstrip("\r\n"))
        if not m:
            continue
        indent = len(m.group(1)) + len(m.group(2) or "")     # where this entry's keys start
        start = i
        while not re.match(rf"^\s{{{indent - 2}}}-\s", lines[start]) and start > 0:
            start -= 1                                         # back to the "- " that opens the entry
        end = i + 1
        while end < len(lines):
            s = lines[end]
            if s.strip() and not s.lstrip().startswith("#") and len(s) - len(s.lstrip()) < indent:
                break
            end += 1
        for j in range(start, end):
            km = re.match(rf"^(\s*(?:-\s+)?){key}:[^#\r\n]*?(\s*#[^\r\n]*)?(\r?\n)?$", lines[j])
            if km and len(km.group(1)) == indent:
                lines[j] = f"{km.group(1)}{key}: {value}{km.group(2) or ''}{km.group(3) or ''}"
                return "".join(lines)
        nl = "\r\n" if ln.endswith("\r\n") else "\n"
        if not ln.endswith("\n"):
            lines[i] = ln + nl
        lines.insert(i + 1, " " * indent + f"{key}: {value}{nl}")
        return "".join(lines)
    return text
