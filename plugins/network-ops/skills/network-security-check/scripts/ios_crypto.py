# ============================================================
# Script:       ios_crypto.py
# Purpose:      Cisco IOS / IOS-XE management transport crypto: SSH server algorithms, DH
#               minimum and RSA host key size (IOS-SSH-CRYPTO), and clear-text file transfer
#               for configs and images (IOS-MGMT-CLEARTEXT-XFER, IOS-MGMT-CLEARTEXT-CRED).
# Author:       G Talks Tech
# Notes:        Read-only. Called by vendor_ios.analyze. The saved 'show ip ssh' output is the
#               truth for what the SSH server offers (the defaults change by release and are
#               not written to the config); 'ip ssh server algorithm ...' lines decide only when
#               that output is missing. Sources per check: settings/checks.yaml.
# ============================================================
import re
from pathlib import Path

import ios_mgmt
from common import result

CHECKS = ("IOS-SSH-CRYPTO", "IOS-MGMT-CLEARTEXT-XFER", "IOS-MGMT-CLEARTEXT-CRED")

MIN_BITS = 2048         # NIST SP 800-131A Rev 2 Tables 4 and 5: 112-bit strength = 2048-bit p / n

# Weak per algorithm type, with the reason shown in the finding.
#   encryption: CBC modes (CERT VU#958563 plaintext recovery in SSH), 3DES (SP 800-131A Table 1,
#               disallowed for encryption after 2023), RC4/Blowfish/CAST (not approved).
#   mac:        SHA-1 and MD5 HMACs (DISA CISC-ND-001200 asks for SHA-2), 64-bit UMAC tags.
#   kex:        SHA-1 key exchange (RFC 9142: group1-sha1 and group-exchange-sha1 SHOULD NOT,
#               group14-sha1 only as a last resort; DISA asks for FIPS-validated algorithms).
#   hostkey:    ssh-rsa signs with SHA-1 (SP 800-131A Table 8: SHA-1 signature generation is
#               disallowed). rsa-sha2-256/512 use the same RSA key and are fine.
_WEAK = {
    "encryption": lambda a: bool(re.search(r"cbc|3des|arcfour|blowfish|cast128|^des\b", a)),
    "mac": lambda a: bool(re.match(r"(hmac-sha1|hmac-md5|umac-64)", a)),
    "kex": lambda a: bool(re.search(r"sha1", a)),
    "hostkey": lambda a: a in ("ssh-rsa", "x509v3-ssh-rsa"),
}
_SHOW = {"encryption": "Encryption Algorithms", "mac": "MAC Algorithms", "kex": "KEX Algorithms",
         "hostkey": "Hostkey Algorithms"}
_XFER = r"(tftp|ftp|rcp|http)"
_URL_CRED = re.compile(r"(\b" + _XFER + r"://[^/\s:@]+:)[^@\s]+@", re.I)


def _show_ip_ssh(dev):
    folder = (dev or {}).get("_folder")
    f = Path(folder) / "show-ip-ssh.txt" if folder else None
    return f.read_text(encoding="utf-8", errors="replace") if f and f.exists() else None


def _parse_show(text):
    """Algorithm lists, DH minimum and RSA modulus sizes from 'show ip ssh'."""
    out = {"enabled": not re.search(r"SSH Disabled", text, re.I), "algs": {}, "dh": None, "rsa": []}
    for k, label in _SHOW.items():
        m = re.search(r"^\s*" + label + r"\s*:\s*(\S.*)$", text, re.M | re.I)
        if m:
            out["algs"][k] = [a.strip() for a in m.group(1).split(",") if a.strip()]
    m = re.search(r"Minimum expected Diffie Hellman key size\s*:\s*(\d+)", text, re.I)
    out["dh"] = int(m.group(1)) if m else None
    out["rsa"] = [int(x) for x in re.findall(r"Modulus Size\s*:\s*(\d+)\s*bits", text, re.I)]
    return out


def _parse_config(top):
    """The same facts from config lines; None where the config is silent (release default)."""
    algs, ev = {}, []
    for h in top:
        m = re.match(r"ip ssh server algorithm (encryption|mac|kex|hostkey) (.+)$", h)
        if m:
            algs[m.group(1)] = m.group(2).split()
            ev.append(h)
    dh = None
    for h in top:
        m = re.match(r"ip ssh dh min size (\d+)$", h)
        if m:
            dh = int(m.group(1))
            ev.append(h)
    rsa = []
    for h in top:
        m = re.match(r"crypto key generate rsa\b.*\bmodulus (\d+)", h)
        if m:
            rsa.append(int(m.group(1)))
            ev.append(h)
    ev += [h for h in top if re.match(r"ip ssh rsa keypair-name \S+", h)]
    return {"algs": algs, "dh": dh, "rsa": rsa}, ev


def _ssh_lines(blocks):
    """vty lines that accept SSH (transport input ssh/all, or no transport input line)."""
    out = []
    for h, ch in blocks:
        if not h.startswith("line vty") or "transport input none" in ch:
            continue
        tin = [c for c in ch if c.startswith("transport input")]
        if tin and not any(re.search(r"\b(ssh|all)\b", c) for c in tin):
            continue
        out.append((h, ch))
    return out


def ssh_crypto(blocks, top, internet, dev):
    lines = _ssh_lines(blocks)
    if not any(h.startswith("line vty") for h, _ in blocks):
        return result("IOS-SSH-CRYPTO", "n/a", "no vty lines in the config")
    if not lines:
        return result("IOS-SSH-CRYPTO", "n/a", "no vty line accepts SSH")
    text = _show_ip_ssh(dev)
    cfg, cfg_ev = _parse_config(top)
    shown = _parse_show(text) if text else None
    if shown and not shown["enabled"]:
        return result("IOS-SSH-CRYPTO", "n/a", "show ip ssh reports SSH disabled")
    src = "show ip ssh" if shown else "config"
    algs = {k: (shown["algs"].get(k) if shown and shown["algs"].get(k) else cfg["algs"].get(k)) for k in _SHOW}
    dh = (shown["dh"] if shown and shown["dh"] is not None else cfg["dh"])
    rsa = (shown["rsa"] if shown and shown["rsa"] else cfg["rsa"])

    bad, ev = [], []
    for k, lst in algs.items():
        if lst is None:
            continue
        weak = [a for a in lst if _WEAK[k](a.lower())]
        if weak:
            bad.append(f"{k} {', '.join(weak)}")
        if shown and shown["algs"].get(k):
            ev.append(f"show ip ssh: {_SHOW[k]}: {','.join(lst)}")
    if dh is not None:
        if dh < MIN_BITS:
            bad.append(f"Diffie-Hellman minimum {dh} bits (under {MIN_BITS})")
        if shown and shown["dh"] is not None:
            ev.append(f"show ip ssh: Minimum expected Diffie Hellman key size : {dh} bits")
    small = [b for b in rsa if b < MIN_BITS]
    if small:
        bad.append(f"RSA host key {min(small)} bits (under {MIN_BITS})")
    if rsa and shown and shown["rsa"]:
        ev.append(f"show ip ssh: Modulus Size : {min(rsa)} bits")
    ev = ev + cfg_ev

    unknown = [k for k in _SHOW if algs[k] is None]
    exposed = internet and any(not ios_mgmt.vty_acl_in(ch) for _, ch in lines)
    if bad:
        return result("IOS-SSH-CRYPTO", "fail", f"SSH server offers weak crypto ({src}): " + "; ".join(bad) +
                      (f". Not seen: {', '.join(unknown)} (release default)" if unknown else ""),
                      ev, exposed=exposed)
    if not shown and (unknown or not algs):
        return result("IOS-SSH-CRYPTO", "not-visible",
                      "no saved 'show ip ssh' output and the config does not set "
                      + ", ".join(unknown) + " (the defaults depend on the release)", ev)
    extra = []
    if dh is None:
        extra.append("DH minimum not shown")
    if not rsa:
        extra.append("RSA host key size not shown")
    return result("IOS-SSH-CRYPTO", "pass",
                  "SSH offers no CBC, 3DES, SHA-1 MAC, SHA-1 key exchange or ssh-rsa host key"
                  + (f"; DH minimum {dh} bits" if dh is not None else "")
                  + (f"; RSA host key {min(rsa)} bits" if rsa else "")
                  + (f" ({'; '.join(extra)})" if extra else "") + f" ({src})", ev)


def hide_url_cred(line):
    """'ftp://user:pass@host/x' -> 'ftp://user:<hidden>@host/x'."""
    return _URL_CRED.sub(lambda m: m.group(1) + "<hidden>@", line)


def cleartext(blocks, top):
    """IOS-MGMT-CLEARTEXT-XFER (configs or images moved over TFTP/FTP/RCP/HTTP) and
    IOS-MGMT-CLEARTEXT-CRED (a password stored for those clear-text clients). 'boot network' and
    'service config' are graded by IOS-LEGACY-SERVICES, so they are left out here."""
    xfer, cred = [], []
    url = re.compile(r"\b" + _XFER + r":", re.I)
    for h, ch in blocks:
        if h == "archive":
            for c in ch:
                if re.match(r"path\s+" + _XFER + r":", c, re.I):
                    xfer.append(f"archive: {c}")
                    if _URL_CRED.search(c):
                        cred.append(f"archive: {c}")
        elif re.match(r"(event manager applet|kron policy-list) ", h):
            for c in ch:
                if re.search(r"\bcopy\b", c) and url.search(c):
                    xfer.append(f"{h}: {c}")
                    if _URL_CRED.search(c):
                        cred.append(f"{h}: {c}")
    for h in top:
        if re.match(r"boot system (tftp|ftp|rcp)\b", h) or re.match(r"boot system \S*" + _XFER + r":", h):
            xfer.append(h)
            if _URL_CRED.search(h):
                cred.append(h)
        elif re.match(r"tftp-server \S", h):
            xfer.append(h)
        elif re.match(r"ip (ftp|http client) password \S", h):
            cred.append(h)
    xfer = [hide_url_cred(x) for x in xfer]
    cred = [hide_url_cred(x) for x in cred]
    out = []
    if xfer:
        out.append(result("IOS-MGMT-CLEARTEXT-XFER", "fail",
                          f"{len(xfer)} config line(s) move configs or images over TFTP, FTP, RCP or HTTP "
                          "(clear text: anyone on the path can read or change the file)", xfer))
    else:
        out.append(result("IOS-MGMT-CLEARTEXT-XFER", "pass",
                          "no archive path, boot system, copy job or tftp-server over TFTP, FTP, RCP or HTTP",
                          [h for h in top if h == "ip scp server enable"]))
    if cred:
        out.append(result("IOS-MGMT-CLEARTEXT-CRED", "fail",
                          f"{len(cred)} credential(s) kept for clear-text file transfer (FTP/HTTP client "
                          "password or user:password in a transfer URL); they cross the network unencrypted",
                          cred))
    else:
        out.append(result("IOS-MGMT-CLEARTEXT-CRED", "pass",
                          "no FTP or HTTP client password and no password in a transfer URL"))
    return out


def check(blocks, top, internet, dev):
    return [ssh_crypto(blocks, top, internet, dev)] + cleartext(blocks, top)
