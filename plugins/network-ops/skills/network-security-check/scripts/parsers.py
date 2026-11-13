# ============================================================
# Script:       parsers.py
# Purpose:      Turn saved config text into structures the checks can read.
#               ios_blocks: IOS / IOS-XE / ASA indented blocks.
#               fortios_tree: FortiOS "config / edit / set / next / end".
#               panos_tree: PAN-OS "show config running" brace format.
#               junos_set: Junos "show configuration | display set".
# Author:       G Talks Tech
# Notes:        Read-only text parsing. No device access.
# ============================================================
import re
import shlex


def ios_blocks(text):
    """[(header, [child lines])] for every top-level line. Children keep no indent."""
    blocks = []
    delim = None
    for raw in text.replace("\r", "").split("\n"):
        line = raw.rstrip()
        if delim:                       # inside a banner: body lines are text, not config
            if delim in line:
                delim = None
            continue
        m = re.match(r"banner \S+ (\^C|\S)", line)
        if m:
            d = m.group(1)
            rest = line[m.end():]
            if d not in rest:
                delim = d
            blocks.append((line.split(d)[0].strip(), []))
            continue
        if not line.strip() or line.strip() == "!":
            continue
        if line[0] not in " \t":
            blocks.append((line.strip(), []))
        elif blocks:
            blocks[-1][1].append(line.strip())
    return blocks


def ios_acl_lines(blocks, name):
    """Entries of an IOS ACL in order (named or numbered), sequence numbers and remarks dropped.
    None when the ACL is not defined (IOS then permits all traffic on an access-group)."""
    lines, found = [], False
    for h, ch in blocks:
        if h in (f"ip access-list extended {name}", f"ip access-list standard {name}"):
            lines, found = list(ch), True
        elif h.startswith(f"access-list {name} "):
            lines.append(h.split(" ", 2)[2])
            found = True
    out = [re.sub(r"^\d+\s+", "", l) for l in lines]
    return [l for l in out if not l.startswith("remark")] if found else None


def ios_find(blocks, pattern):
    rx = re.compile(pattern)
    return [(h, ch) for h, ch in blocks if rx.search(h)]


def _split(line):
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def fortios_tree(text):
    """{'system interface': {'port1': {'ip': ['203.0.113.2', '255.255.255.0'], ...}}, ...}.
    Nested 'config' inside an edit becomes a dict under its name. 'set' values are lists."""
    root, stack = {}, []
    cur = root
    for raw in text.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = _split(line)
        verb = parts[0]
        if verb == "config":
            name = " ".join(parts[1:])
            stack.append(cur)
            cur = cur.setdefault(name, {})
        elif verb == "edit":
            stack.append(cur)
            cur = cur.setdefault(parts[1] if len(parts) > 1 else "", {})
        elif verb == "set" and len(parts) >= 2:
            cur[parts[1]] = parts[2:]
        elif verb in ("next", "end"):
            cur = stack.pop() if stack else root
    return root


def panos_tree(text):
    """Brace format to nested dicts. 'key value;' -> {key: value}; 'key [ a b ];' -> list;
    'key { ... }' -> dict. Quoted names keep their spaces."""
    toks = re.findall(r'"(?:[^"\\]|\\.)*"|[{}\[\];]|[^\s{}\[\];"]+', text)
    toks = [t[1:-1] if t.startswith('"') else t for t in toks]
    pos = 0

    def block():
        nonlocal pos
        node = {}
        while pos < len(toks):
            t = toks[pos]
            if t == "}":
                pos += 1
                return node
            words = []
            while pos < len(toks) and toks[pos] not in ("{", ";", "[", "}"):
                words.append(toks[pos])
                pos += 1
            if pos >= len(toks):
                break
            t = toks[pos]
            if t == "{":
                pos += 1
                child = block()
                key = " ".join(words)
                node[key] = child
            elif t == "[":
                pos += 1
                items = []
                while pos < len(toks) and toks[pos] != "]":
                    items.append(toks[pos])
                    pos += 1
                pos += 1
                if pos < len(toks) and toks[pos] == ";":
                    pos += 1
                node[" ".join(words)] = items
            elif t == ";":
                pos += 1
                if len(words) == 1:
                    node.setdefault("_items", []).append(words[0])
                elif words:
                    node[words[0]] = " ".join(words[1:])
            else:  # stray '}' handled at loop top
                continue
        return node

    return block()


def get(d, *path, default=None):
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return default
        d = d[p]
    return d


def as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def junos_set(text):
    return [l.strip() for l in text.replace("\r", "").split("\n") if l.strip().startswith("set ")]
