# ============================================================
# Script:       ios_mgmt.py
# Purpose:      Cisco IOS / IOS-XE management plane and visibility checks: idle timeouts,
#               login lockout, AAA (central servers, lines with no authentication,
#               accounting), login banner, NTP authentication and redundancy, syslog depth,
#               SNMP v1/v2c in use.
# Author:       G Talks Tech
# Notes:        Read-only. Called by vendor_ios.analyze. Sources per check: settings/checks.yaml.
# ============================================================
import re

from common import result

CHECKS = ("IOS-EXEC-TIMEOUT", "IOS-LOGIN-BLOCK", "IOS-AAA-CENTRAL", "IOS-LOGIN-NONE",
          "IOS-AAA-ACCOUNTING", "IOS-BANNER", "IOS-NTP-AUTH", "IOS-NTP-REDUNDANT", "IOS-LOG-DEPTH",
          "IOS-SNMP-V2C")

STIG_TIMEOUT = 300          # seconds; DISA CISC-ND-000720: 5 minutes
DEFAULT_TIMEOUT = 600       # seconds; Cisco Doc 13608: "disconnected after ten minutes of inactivity"
TRAP_LEVELS = {"emergencies": 0, "alerts": 1, "critical": 2, "errors": 3, "warnings": 4,
               "notifications": 5, "informational": 6, "debugging": 7}


def _login_lines(blocks):
    """Console and vty lines that accept a login. A vty with 'transport input none' accepts none.
    Aux is left out: most current platforms have no aux modem and the STIG checks con and vty."""
    return [(h, ch) for h, ch in blocks
            if h.startswith("line con") or (h.startswith("line vty") and "transport input none" not in ch)]


def _timeout(ch):
    """Idle timeout of a line in seconds (0 = never) and the line that set it (None = default)."""
    for c in ch:
        if c == "no exec-timeout":
            return 0, c
        m = re.match(r"exec-timeout (\d+)(?: (\d+))?$", c)
        if m:
            return int(m.group(1)) * 60 + int(m.group(2) or 0), c
    return DEFAULT_TIMEOUT, None


def _methods(tokens):
    out, i = [], 0
    while i < len(tokens):
        if tokens[i] == "group" and i + 1 < len(tokens):
            out.append("group " + tokens[i + 1])
            i += 2
        else:
            out.append(tokens[i])
            i += 1
    return out


def _line_auth(h, ch, aaa, lists):
    """How a line authenticates: (kind, text). kind: group (a TACACS+/RADIUS server group
    first), local (local users, line password or enable), none (no authentication) or
    none-fallback (servers first, then none when they don't answer)."""
    if aaa:
        named = [c.split()[2] for c in ch if re.match(r"login authentication \S+$", c)]
        name = named[0] if named else "default"
        methods = lists.get(name)
        if methods is None:
            why = "no default login list (local users)" if name == "default" else \
                f"login list {name} is not defined"
            return "local", why
        text = f"login list {name}: {' '.join(methods)}"
        if methods[0] == "none":
            return "none", text
        if methods[0].startswith("group "):
            return ("none-fallback" if "none" in methods else "group"), text
        return "local", text
    if "no login" in ch:
        return "none", "no login"
    if "login local" in ch:
        return "local", "login local"
    if "login" in ch:
        return "local", "login (line password)"
    if h.startswith("line con"):
        return "none", "no login line (IOS default for the console without aaa new-model)"
    return "local", "login (IOS default for vty)"


def _servers(blocks, top):
    named = [h for h, _ in blocks if re.match(r"(tacacs|radius) server \S+", h)]
    legacy = [h for h in top if re.match(r"(tacacs|radius)-server host \S+", h)]
    return named + legacy


def _snmp_host_masked(h):
    """An 'snmp-server host' line with its community (the token after the version) hidden."""
    t = h.split()
    out, i = t[:3], 3
    while i < len(t):
        if t[i] == "vrf" and i + 1 < len(t):
            out += t[i:i + 2]
            i += 2
        elif t[i] in ("informs", "traps", "version", "1", "2c", "3", "auth", "noauth", "priv"):
            out.append(t[i])
            i += 1
        else:
            out.append("<hidden>")     # the community; the notification types after it are dropped
            break
    return " ".join(out)


def check(blocks, top, internet):
    res = []
    lines = _login_lines(blocks)
    vty = [(h, ch) for h, ch in lines if h.startswith("line vty")]
    aaa = "aaa new-model" in top
    lists = {}
    for h in top:
        m = re.match(r"aaa authentication login (\S+) (.+)", h)
        if m:
            lists[m.group(1)] = _methods(m.group(2).split())

    # --- idle timeout ---
    if not lines:
        res.append(result("IOS-EXEC-TIMEOUT", "n/a", "no console or vty line in the config"))
    else:
        bad, ok = [], []
        for h, ch in lines:
            secs, src = _timeout(ch)
            shown = "never" if secs == 0 else f"{secs // 60} min" + (f" {secs % 60} s" if secs % 60 else "")
            txt = f"{h}: {src}" if src else f"{h}: no exec-timeout line (default 10 min)"
            (bad if secs == 0 or secs > STIG_TIMEOUT else ok).append((txt, shown, h))
        if bad:
            res.append(result("IOS-EXEC-TIMEOUT", "fail",
                              "Idle timeout over 5 minutes: " + "; ".join(f"{h} ({s})" for _, s, h in bad),
                              [t for t, _, _ in bad]))
        else:
            res.append(result("IOS-EXEC-TIMEOUT", "pass", "every console and vty line times out in 5 minutes "
                              "or less", [t for t, _, _ in ok]))

    # --- login lockout ---
    block = [h for h in top if h.startswith("login block-for ")]
    if not vty:
        res.append(result("IOS-LOGIN-BLOCK", "n/a", "no vty line accepts remote logins"))
    elif not block:
        open_vty = [h for h, ch in vty if not any(c.startswith("access-class") for c in ch)]
        res.append(result("IOS-LOGIN-BLOCK", "fail", "No 'login block-for': failed logins are not limited",
                          exposed=internet and bool(open_vty)))
    else:
        m = re.search(r"attempts (\d+)", block[0])
        if m and int(m.group(1)) > 3:
            res.append(result("IOS-LOGIN-BLOCK", "fail", f"login block-for allows {m.group(1)} attempts "
                              "(STIG: 3)", block))
        else:
            res.append(result("IOS-LOGIN-BLOCK", "pass", "failed logins trigger a quiet period", block))

    # --- how each line authenticates ---
    auth = [(h, ch) + _line_auth(h, ch, aaa, lists) for h, ch in lines]
    no_auth = [a for a in auth if a[2] in ("none", "none-fallback")]
    if not lines:
        res.append(result("IOS-LOGIN-NONE", "n/a", "no console or vty line in the config"))
    elif no_auth:
        exposed = internet and any(h.startswith("line vty") and not any(c.startswith("access-class") for c in ch)
                                   for h, ch, _, _ in no_auth)
        res.append(result("IOS-LOGIN-NONE", "fail", "Login without authentication: " + "; ".join(
            f"{h} ({t}{', falls back to none if the servers do not answer' if k == 'none-fallback' else ''}"
            f"{', privilege level 15' if 'privilege level 15' in ch else ''})"
            for h, ch, k, t in no_auth), [f"{h}: {t}" for h, _, _, t in no_auth], exposed=exposed))
    else:
        res.append(result("IOS-LOGIN-NONE", "pass", "every console and vty line asks for a login",
                          [f"{h}: {t}" for h, _, _, t in auth]))

    servers = _servers(blocks, top)
    vty_auth = [a for a in auth if a[0].startswith("line vty")]
    if not vty_auth:
        res.append(result("IOS-AAA-CENTRAL", "n/a", "no vty line accepts remote logins"))
    elif not aaa:
        res.append(result("IOS-AAA-CENTRAL", "fail", "No 'aaa new-model': vty logins use local or line "
                          "passwords, not a TACACS+ or RADIUS server", [f"{h}: {t}" for h, _, _, t in vty_auth]))
    else:
        local = [a for a in vty_auth if a[2] not in ("group", "none-fallback")]
        if local:
            res.append(result("IOS-AAA-CENTRAL", "fail", "Remote logins check local accounts only: "
                              + "; ".join(f"{h} ({t})" for h, _, _, t in local),
                              [f"{h}: {t}" for h, _, _, t in local]))
        elif len(servers) < 2:
            res.append(result("IOS-AAA-CENTRAL", "fail", f"{len(servers)} TACACS+/RADIUS server(s) defined "
                              "(STIG: at least two)", servers))
        else:
            res.append(result("IOS-AAA-CENTRAL", "pass", f"vty logins go to a server group first, "
                              f"{len(servers)} servers defined", [f"{h}: {t}" for h, _, _, t in vty_auth]))

    # --- record of admin activity ---
    acct_exec = [h for h in top if re.match(r"aaa accounting exec \S+ (start-stop|stop-only) .*group ", h)]
    acct_cmd = [h for h in top if re.match(r"aaa accounting commands \d+ \S+ (start-stop|stop-only) .*group ", h)]
    archive = [ch for h, ch in blocks if h == "archive"]
    log_cfg = bool(archive) and "logging enable" in archive[0]
    if acct_cmd or log_cfg:
        ev = acct_exec + acct_cmd + (["archive / log config / logging enable"] if log_cfg else [])
        res.append(result("IOS-AAA-ACCOUNTING", "pass", "configuration commands are recorded"
                          + (" (AAA command accounting)" if acct_cmd else " (archive log config)"), ev))
    else:
        res.append(result("IOS-AAA-ACCOUNTING", "fail", "No AAA command accounting and no 'archive / log config "
                          "/ logging enable': admin commands are not recorded"
                          + (" (exec accounting only records sessions)" if acct_exec else ""), acct_exec))

    # --- banner ---
    banner = [h for h in top if re.match(r"banner (login|motd)\b", h)]
    if banner:
        res.append(result("IOS-BANNER", "pass", "a banner is shown before login", banner))
    else:
        res.append(result("IOS-BANNER", "fail", "No 'banner login' or 'banner motd'"))

    # --- NTP ---
    ntp_src = [h for h in top if re.match(r"ntp (server|peer) ", h)]
    if not ntp_src:
        res.append(result("IOS-NTP-AUTH", "n/a", "no NTP server configured"))
    else:
        trusted = {t for h in top if h.startswith("ntp trusted-key ") for t in h.split()[2:3]}
        keys = {}
        for h in top:
            m = re.match(r"ntp authentication-key (\d+) (\S+)", h)
            if m:
                keys[m.group(1)] = m.group(2)
        missing = []
        if "ntp authenticate" not in top:
            missing.append("no 'ntp authenticate'")
        if not trusted:
            missing.append("no 'ntp trusted-key'")
        nokey = [h for h in ntp_src if not re.search(r"\bkey (\d+)", h)
                 or re.search(r"\bkey (\d+)", h).group(1) not in trusted & set(keys)]
        if nokey:
            missing.append(f"{len(nokey)} of {len(ntp_src)} server(s) without a trusted, defined key")
        if missing:
            res.append(result("IOS-NTP-AUTH", "fail", "NTP is not authenticated: " + ", ".join(missing),
                              nokey or ntp_src))
        else:
            algs = sorted({keys.get(re.search(r"\bkey (\d+)", h).group(1), "?") for h in ntp_src})
            note = " (MD5: the STIG example uses hmac-sha2-256)" if "md5" in algs else ""
            res.append(result("IOS-NTP-AUTH", "pass", f"every NTP server uses a trusted key: {', '.join(algs)}"
                              + note, ntp_src))
    if len(ntp_src) >= 2:
        res.append(result("IOS-NTP-REDUNDANT", "pass", f"{len(ntp_src)} NTP sources", ntp_src))
    else:
        res.append(result("IOS-NTP-REDUNDANT", "fail", f"{len(ntp_src) or 'No'} NTP server"
                          + ("" if len(ntp_src) == 1 else "s") + " (STIG: at least two)", ntp_src))

    # --- syslog depth (no host at all is IOS-NO-REMOTE-LOG) ---
    hosts = [h for h in top if re.match(r"logging (host \S|\d)", h)]
    trap = [h for h in top if re.match(r"(no )?logging trap\b", h)]
    if not hosts:
        res.append(result("IOS-LOG-DEPTH", "n/a", "no syslog host (IOS-NO-REMOTE-LOG)"))
    else:
        why = []
        if len(hosts) < 2:
            why.append("one syslog host (STIG: at least two)")
        level = 6
        if trap:
            if trap[-1] == "no logging trap":
                level = -1
                why.append("'no logging trap': nothing is sent to the syslog hosts")
            else:
                w = trap[-1].split()[2] if len(trap[-1].split()) > 2 else "informational"
                level = int(w) if w.isdigit() else TRAP_LEVELS.get(w, 6)
                if level < 2:
                    why.append(f"logging trap {w} sends only level {level} and above (STIG: critical or lower)")
        if why:
            txt = "; ".join(why)
            res.append(result("IOS-LOG-DEPTH", "fail", txt[0].upper() + txt[1:], hosts + trap))
        else:
            res.append(result("IOS-LOG-DEPTH", "pass", f"{len(hosts)} syslog hosts, trap level "
                              + ("informational (default)" if not trap else trap[-1].split()[2]), hosts + trap))

    # --- SNMP version ---
    communities = [h for h in top if h.startswith("snmp-server community ")]
    v12_hosts = [h for h in top if h.startswith("snmp-server host ") and not re.search(r"\bversion 3\b", h)]
    v3_groups = [h for h in top if re.match(r"snmp-server group \S+ v3 ", h)]
    v3_weak = [h for h in v3_groups if not re.match(r"snmp-server group \S+ v3 priv\b", h)]
    if not (communities or v12_hosts or v3_groups or any(h.startswith("snmp-server host ") for h in top)):
        res.append(result("IOS-SNMP-V2C", "n/a", "no SNMP community, v3 group or trap host configured"))
    elif communities or v12_hosts or v3_weak:
        why = []
        if communities:
            why.append(f"{len(communities)} v1/v2c communit{'y' if len(communities) == 1 else 'ies'}")
        if v12_hosts:
            why.append(f"{len(v12_hosts)} trap host(s) on v1/v2c")
        if v3_weak:
            why.append(f"{len(v3_weak)} v3 group(s) without priv (no encryption)")
        res.append(result("IOS-SNMP-V2C", "fail", "SNMP sends community strings or data in clear text: "
                          + ", ".join(why), [re.sub(r"community \S+", "community <hidden>", h) for h in communities]
                          + [_snmp_host_masked(h) for h in v12_hosts] + v3_weak))
    else:
        res.append(result("IOS-SNMP-V2C", "pass", "SNMPv3 with authentication and privacy only", v3_groups))
    return res
