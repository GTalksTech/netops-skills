# ============================================================
# Script:       mask.py
# Purpose:      Hide secret values on config lines, so a fact's proof lines (and a check's
#               evidence) can be shown and saved without leaking a password or key.
# Author:       G Talks Tech
# ============================================================
import re

# Secret values that may sit on a config line. mask() walks the words of a line: after a secret
# keyword it skips an encryption type (0, 6, 7, ENC...), an algorithm or format word (md5,
# hmac-sha2-256, ascii, local...) and hides the next word. Words that name things rather than
# hold a secret (key-chain, key-string, address...) stop the walk, so key chain NAMES stay visible.
# Covered: IOS/IOS-XE enable/username secrets, line passwords, SNMP communities and v3 user keys,
# snmp-server host communities, NTP keys, TACACS+/RADIUS keys, IKE pre-shared keys, OSPF/EIGRP/BGP
# keys, HSRP/VRRP/GLBP keys, WPA PSKs; FortiOS 'set <secret-name> ENC ...'; Junos and ASA forms
# that use the same keywords.
_KEYWORDS = {"community", "secret", "password", "passwd", "psksecret", "key-string", "authentication-key",
             "encrypted-password", "md5", "key", "auth-password", "priv-password", "passphrase", "auth-pwd",
             "secondary-secret", "ldap-password", "private-key", "server-key", "pre-shared-key", "wpa-psk",
             "password-encrypt", "message-digest-key"}
_TYPE = re.compile(r"^(\d{1,3}|ENC|encrypted)$", re.I)
_ALG = re.compile(r"^(md5|sha|sha1|sha-1|sha2?-?(224|256|384|512)|sha256|sha384|sha512|hmac-\S+|cmac-\S+|aes|"
                  r"des|3des|ascii|hex|ascii-text|hexadecimal|local|remote|unencrypted)$", re.I)
_KEEP = {"chain", "key-chain", "key-string", "generate", "key", "md5", "text", "<hidden>", "config-key",
         "address", "hostname", "mode", "algorithm-type", "level"}
# FortiOS: 'set <name> [ENC] <value>' where the name holds a secret.
_FGT_SECRET = re.compile(r"^([\w-]*-)?(password|passwd|pwd|secret|passphrase|psksecret|private-key|key|"
                         r"ppk-secret|ldap-password)(-l\d|\d)?$", re.I)
_FHRP = {"standby", "vrrp", "glbp"}
# Words that never hold a secret when masking prose (a finding's detail): stops a sentence such as
# "VTP mode server with no password on a switch" losing the word "on".
_PROSE = {"a", "an", "and", "as", "at", "by", "for", "from", "in", "is", "it", "no", "not", "of", "on", "or",
          "the", "to", "with", "was", "are", "be", "only", "set", "line", "lines", "string", "strings", "types",
          "name", "names", "list", "lists"}


def _hide_after(w, i, out, prose):
    """Mark the secret word after the keyword at w[i]: skip a type and algorithm/format words."""
    j = i + 1
    skipped_type = None
    while j < len(w) and (_TYPE.match(w[j]) or _ALG.match(w[j])) and w[j].lower() not in _KEEP:
        if _TYPE.match(w[j]):
            skipped_type = j
        j += 1
    if j < len(w):
        tok = w[j]
        if tok.lower() in _KEEP or tok == "<hidden>":
            return
        core = tok.rstrip(":,;.)")
        if prose and (core.lower() in _PROSE or core.isdigit() or tok[:1] in "('\""
                      or (skipped_type is None and re.fullmatch(r"[a-z][a-z()/-]*", core))):
            return
        out.add(j)
    elif skipped_type is not None and w[i].lower() != "key" and not prose:
        out.add(skipped_type)       # "password 1234": a numeric secret, not a type


def mask(line, prose=False):
    """A config line with any secret value replaced by <hidden>. prose=True for free text (a
    finding's detail): common words and words ending in punctuation are never hidden."""
    text = str(line)
    parts = re.split(r"(\s+)", text)
    w = [p for p in parts[::2]]           # words at even positions, whitespace at odd ones
    low = [x.lower() for x in w]
    hide = set()
    first = next((k for k, x in enumerate(low) if x), None)
    if first is not None and low[first] == "set" and first + 1 < len(w) and _FGT_SECRET.match(w[first + 1]):
        hide |= {k for k in range(first + 2, len(w)) if w[k] and low[k] not in ("enc",)}
    for i, x in enumerate(low):
        if x in _KEYWORDS:
            _hide_after(w, i, hide, prose)
        elif x == "text" and i and low[i - 1] == "authentication" and i + 1 < len(w):
            hide.add(i + 1)
        elif x == "authentication" and i + 1 < len(w) and (
                (i >= 1 and low[i - 1] in _FHRP) or (i >= 2 and low[i - 2] in _FHRP and low[i - 1].isdigit())) \
                and low[i + 1] not in ("md5", "text") and w[i + 1]:
            hide.add(i + 1)
    # SNMPv3 user keys: snmp-server user U G [remote ..] v3 [encrypted] auth ALG KEY [priv ALG [BITS] KEY]
    if first is not None and low[first:first + 2] == ["snmp-server", "user"]:
        for i, x in enumerate(low):
            if x in ("auth", "priv"):
                _hide_after(w, i, hide, prose)
    # snmp-server host ADDR [vrf V] [informs|traps] [version 1|2c|3 [auth|noauth|priv]] COMMUNITY ...
    if first is not None and low[first:first + 2] == ["snmp-server", "host"] and len(w) > first + 3:
        i = first + 3
        while i < len(w):
            if low[i] == "vrf":
                i += 2
            elif low[i] == "version":
                i += 2
            elif low[i] in ("informs", "traps", "auth", "noauth", "priv"):
                i += 1
            else:
                if w[i] and w[i] != "<hidden>":
                    hide.add(i)
                break
    for k in hide:
        parts[2 * k] = "<hidden>"
    return "".join(parts)
