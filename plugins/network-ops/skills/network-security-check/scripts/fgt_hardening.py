# ============================================================
# Script:       fgt_hardening.py
# Purpose:      FortiGate (FortiOS) management-plane hardening checks (roadmap R7): admin
#               lockout, idle timeout, admin TLS, clear-text admin protocols, two-factor,
#               password policy, remote logging, local-in policy, unused VIPs, stale AV.
# Author:       G Talks Tech
# Notes:        Read-only. FortiOS "show" leaves out every line that is at its default, so
#               an absent line means the documented default (research/sources.md, R7 rows:
#               FortiOS 7.6.6 / 8.0.0 CLI reference). Each check states the default it used.
# ============================================================
import datetime as dt
import re

from common import result

CHECKS = ("FGT-ADMIN-LOCKOUT", "FGT-ADMIN-TIMEOUT", "FGT-WEAK-ADMIN-TLS", "FGT-ADMIN-CLEARTEXT",
          "FGT-ADMIN-NO-2FA", "FGT-PASSWORD-POLICY", "FGT-NO-REMOTE-LOG", "FGT-WAN-NO-LOCAL-IN",
          "FGT-VIP-UNUSED", "FGT-AV-STALE")

# STIG FGFW-ND values (DISA FortiGate NDM STIG V1R6)
STIG_LOCKOUT_THRESHOLD = 3
STIG_LOCKOUT_DURATION = 900
STIG_ADMINTIMEOUT = 10
STIG_PASSWORD_LENGTH = 15
# FortiOS defaults, 7.6.6 / 8.0.0 CLI reference "config system global"
DEFAULT_LOCKOUT_THRESHOLD = 3
DEFAULT_LOCKOUT_DURATION = 60
DEFAULT_ADMINTIMEOUT = 5
STALE_DAYS = 30            # same bar as FGT-IPS-STALE (SCORING.md house rule 8)
OLD_TLS = {"sslv3", "tlsv1-0", "tlsv1-1"}
OLD_MIN_PROTO = {"sslv3", "tlsv1", "tlsv1-0", "tlsv1-1"}
MGMT = {"http", "https", "ssh", "telnet", "snmp"}     # FGT-MGMT-ON-WAN reports these on WAN


def version(text):
    """(major, minor, patch) from the '#config-version=FGVM64-8.0.1-FW-...' header, else None."""
    m = re.search(r"^#config-version=[^-\n]+-(\d+)\.(\d+)\.(\d+)", text, re.M)
    return tuple(int(x) for x in m.groups()) if m else None


def _int(cfg, key):
    try:
        return int(cfg[key][0])
    except (KeyError, IndexError, ValueError):
        return None


def _defaults_note(ver):
    if ver and ver < (7, 6, 0):
        return (f" Defaults are from the FortiOS 7.6/8.0 CLI reference; this config is "
                f"{'.'.join(map(str, ver))}, whose defaults were not checked.")
    return ""


def _global_checks(glob, ver, wan_admin):
    out = []
    note = _defaults_note(ver)
    if glob is None:
        return [result(c, "not-visible", "'config system global' is not in the saved config")
                for c in ("FGT-ADMIN-LOCKOUT", "FGT-ADMIN-TIMEOUT", "FGT-WEAK-ADMIN-TLS")]

    # --- lockout ---
    thr = _int(glob, "admin-lockout-threshold")
    dur = _int(glob, "admin-lockout-duration")
    t = thr if thr is not None else DEFAULT_LOCKOUT_THRESHOLD
    d = dur if dur is not None else DEFAULT_LOCKOUT_DURATION
    ev = [f"set admin-lockout-threshold {thr}" if thr is not None else
          f"(no admin-lockout-threshold line: default {DEFAULT_LOCKOUT_THRESHOLD})",
          f"set admin-lockout-duration {dur}" if dur is not None else
          f"(no admin-lockout-duration line: default {DEFAULT_LOCKOUT_DURATION} s)"]
    bad = []
    if t > STIG_LOCKOUT_THRESHOLD:
        bad.append(f"lockout after {t} failed logins (STIG: {STIG_LOCKOUT_THRESHOLD})")
    if d < STIG_LOCKOUT_DURATION:
        bad.append(f"lockout lasts {d} s{' (FortiOS default)' if dur is None else ''} (STIG: "
                   f"{STIG_LOCKOUT_DURATION} s)")
    detail = ("; ".join(bad) + (note if thr is None or dur is None else "")) if bad else \
        f"lockout after {t} failures for {d} s"
    out.append(result("FGT-ADMIN-LOCKOUT", "fail" if bad else "pass", detail, ev,
                      exposed=wan_admin, where="system global"))

    # --- idle timeout ---
    to = _int(glob, "admintimeout")
    v = to if to is not None else DEFAULT_ADMINTIMEOUT
    ev = [f"set admintimeout {to}" if to is not None else
          f"(no admintimeout line: default {DEFAULT_ADMINTIMEOUT} min)"]
    out.append(result("FGT-ADMIN-TIMEOUT", "fail" if v > STIG_ADMINTIMEOUT else "pass",
                      f"admin sessions time out after {v} min idle" +
                      (f" (STIG: {STIG_ADMINTIMEOUT} or less)" + (note if to is None else "")
                       if v > STIG_ADMINTIMEOUT else ""),
                      ev, where="system global"))

    # --- admin crypto: strong-crypto, admin TLS versions, min SSL version, SSH v1 ---
    bad, ev = [], []
    if glob.get("strong-crypto") == ["disable"]:
        bad.append("strong-crypto disable")
        ev.append("set strong-crypto disable")
    tls = [x.lower() for x in glob.get("admin-https-ssl-versions", [])]
    if set(tls) & OLD_TLS:
        bad.append("admin HTTPS allows " + ", ".join(sorted(set(tls) & OLD_TLS)))
        ev.append("set admin-https-ssl-versions " + " ".join(glob["admin-https-ssl-versions"]))
    mp = [x.lower() for x in glob.get("ssl-min-proto-version", [])]
    if mp and mp[0] in OLD_MIN_PROTO:
        bad.append(f"ssl-min-proto-version {glob['ssl-min-proto-version'][0]}")
        ev.append(f"set ssl-min-proto-version {glob['ssl-min-proto-version'][0]}")
    if glob.get("admin-ssh-v1") == ["enable"]:
        bad.append("SSH v1 enabled")
        ev.append("set admin-ssh-v1 enable")
    if bad:
        out.append(result("FGT-WEAK-ADMIN-TLS", "fail", "; ".join(bad), ev, exposed=wan_admin,
                          where="system global"))
    else:
        out.append(result("FGT-WEAK-ADMIN-TLS", "pass",
                          "strong-crypto, admin TLS 1.2/1.3 and SSH v2 at their secure defaults or set "
                          "explicitly" + note,
                          [f"set {k} {' '.join(glob[k])}" for k in ("strong-crypto", "admin-https-ssl-versions",
                                                                     "ssl-min-proto-version", "admin-ssh-v1")
                           if k in glob] or ["(no lines: FortiOS defaults)"], where="system global"))
    return out


def _cleartext(ifaces, internet_if, glob):
    """Telnet or HTTP admin access on interfaces that are not internet-facing (FGT-MGMT-ON-WAN
    reports every admin protocol on the internet-facing ones)."""
    out, ev = [], []
    redirect = (glob or {}).get("admin-https-redirect") != ["disable"]
    for name, cfg in ifaces.items():
        if name in internet_if:
            continue
        acc = cfg.get("allowaccess", [])
        bad = sorted({"telnet", "http"} & set(acc))
        if not bad:
            continue
        what = " and ".join(bad)
        if bad == ["http"] and redirect:
            what = "http (redirected to HTTPS, but the HTTP listener still answers)"
        out.append(result("FGT-ADMIN-CLEARTEXT", "fail", f"{name} allows {what} admin access",
                          [f'edit "{name}"', f"set allowaccess {' '.join(acc)}"] +
                          (["set admin-https-redirect disable"] if not redirect and "http" in bad else []),
                          where=name))
        ev.append(name)
    if not ifaces:
        return [result("FGT-ADMIN-CLEARTEXT", "not-visible", "no interfaces in the saved config")]
    if not out:
        out.append(result("FGT-ADMIN-CLEARTEXT", "pass", "no telnet or http in allowaccess on any internal "
                          "interface", [f"{n}: set allowaccess {' '.join(c['allowaccess'])}"
                                        for n, c in ifaces.items() if c.get("allowaccess")]))
    return out


def _two_factor(admins, partial, wan_admin):
    if not admins:
        return [result("FGT-ADMIN-NO-2FA", "not-visible", "'config system admin' is not in the saved config")]
    if partial:
        return [result("FGT-ADMIN-NO-2FA", "not-visible", "only the snapshot account is visible under "
                       "'config system admin': two-factor of the other admins was not checked",
                       [f'edit "{n}"' for n in admins])]
    out, remote = [], []
    for name, cfg in admins.items():
        tf = (cfg.get("two-factor") or ["disable"])[0]
        if cfg.get("remote-auth") == ["enable"] or cfg.get("wildcard") == ["enable"]:
            remote.append(name)          # MFA, if any, happens on the RADIUS/LDAP/SAML side
            continue
        if tf == "disable" and cfg.get("peer-auth") != ["enable"]:
            out.append(result("FGT-ADMIN-NO-2FA", "fail", f"local admin '{name}' logs in with a password only",
                              [f'edit "{name}"', "(no two-factor line: default disable)"],
                              exposed=wan_admin, where=name))
    if not out:
        msg = f"all {len(admins) - len(remote)} local admin accounts use two-factor or certificates"
        if remote:
            msg += f"; {', '.join(remote)} authenticate remotely (MFA there not checked)"
        out.append(result("FGT-ADMIN-NO-2FA", "pass", msg,
                          [f'edit "{n}": two-factor {(c.get("two-factor") or ["disable"])[0]}'
                           for n, c in admins.items()]))
    return out


def _password_policy(pp, ver):
    """Defaults: status disable and minimum-length 8 up to 7.6.4 (7.6.0 CLI reference); from
    7.6.5 the policy is enabled on upgrade with minimum-length 12 (8.0.0 CLI reference and
    Fortinet's 7.6.5 tip). Unknown version: the older defaults."""
    if pp is None:
        return result("FGT-PASSWORD-POLICY", "not-visible", "'config system password-policy' is not in the "
                      "saved config")
    new = bool(ver and ver >= (7, 6, 5))
    status = (pp.get("status") or ["enable" if new else "disable"])[0]
    length = _int(pp, "minimum-length") or (12 if new else 8)
    apply_to = pp.get("apply-to") or ["admin-password"]
    ev = [f"set status {pp['status'][0]}" if "status" in pp else f"(no status line: default {status})",
          f"set minimum-length {length}" if "minimum-length" in pp else f"(no minimum-length line: default {length})"]
    if "apply-to" in pp:
        ev.append("set apply-to " + " ".join(apply_to))
    if status != "enable":
        return result("FGT-PASSWORD-POLICY", "fail", "no password policy for admin passwords (status "
                      f"{status})", ev, where="system password-policy")
    if "admin-password" not in apply_to:
        return result("FGT-PASSWORD-POLICY", "fail", "password policy does not apply to admin passwords",
                      ev, where="system password-policy")
    if length < STIG_PASSWORD_LENGTH:
        return result("FGT-PASSWORD-POLICY", "fail", f"admin passwords need only {length} characters "
                      f"(STIG: {STIG_PASSWORD_LENGTH})", ev, where="system password-policy")
    return result("FGT-PASSWORD-POLICY", "pass", f"policy enabled, minimum length {length}", ev)


def _remote_log(sections):
    """At least one enabled remote log target: syslogd..syslogd4, fortianalyzer..3 or
    fortianalyzer-cloud, FortiGuard (FortiCloud). status defaults to disable."""
    if not any(k.startswith("log ") for k in sections):
        return result("FGT-NO-REMOTE-LOG", "not-visible", "no 'config log ...' section in the saved config")
    on, off = [], []
    for k in sorted(sections):
        if re.fullmatch(r"log (syslogd\d?|fortianalyzer\d?|fortianalyzer-cloud|fortiguard) setting", k):
            cfg = sections[k]
            target = " ".join(cfg.get("server", [])) or k.split()[1]
            (on if cfg.get("status") == ["enable"] else off).append((k, target))
    if on:
        return result("FGT-NO-REMOTE-LOG", "pass", "logs sent to " + ", ".join(t for _, t in on),
                      [f"config {k}: set status enable" + (f", server {t}" if t != k.split()[1] else "")
                       for k, t in on])
    return result("FGT-NO-REMOTE-LOG", "fail", "no syslog, FortiAnalyzer or FortiGuard log target is "
                  "enabled: logs stay on the device", [f"config {k}: status not enable" for k, _ in off]
                  or ["(no log syslogd / fortianalyzer / fortiguard setting: default status disable)"])


def _local_in(ifaces, zones, internet_if, local_in):
    """WAN interfaces that answer more than ping and admin protocols (fabric, fgfm, ftm,
    radius-acct, probe-response, speed-test...) with no local-in policy on that interface."""
    def covered(name):
        for p in local_in.values():
            if p.get("status") == ["disable"]:
                continue
            intf = set(p.get("intf", []))
            if "any" in intf or name in intf or any(name in zones.get(z, {}).get("interface", [])
                                                    for z in intf):
                return True
        return False

    out, open_ifs = [], []
    for name in sorted(internet_if):
        extra = sorted(set(ifaces.get(name, {}).get("allowaccess", [])) - {"ping"} - MGMT)
        if not extra:
            continue
        open_ifs.append(name)
        if not covered(name):
            out.append(result("FGT-WAN-NO-LOCAL-IN", "fail",
                              f"{name} answers {' '.join(extra)} from the internet and no local-in policy "
                              "covers it", [f'edit "{name}"',
                                            f"set allowaccess {' '.join(ifaces[name]['allowaccess'])}"],
                              exposed=True, where=name))
    if out:
        return out
    if not open_ifs:
        return [result("FGT-WAN-NO-LOCAL-IN", "n/a", "internet-facing interfaces allow nothing beyond ping "
                       "and the admin protocols FGT-MGMT-ON-WAN already reports" if internet_if else
                       "no internet-facing interface")]
    return [result("FGT-WAN-NO-LOCAL-IN", "pass", f"local-in policy covers {', '.join(open_ifs)}",
                   [f"local-in-policy {k}: intf {' '.join(v.get('intf', []))}" for k, v in local_in.items()])]


def _vip_unused(vips, vipgrp, policy_sections, settings):
    if not vips:
        return [result("FGT-VIP-UNUSED", "n/a", "no VIP (destination NAT) objects")]
    if settings.get("central-nat") == ["enable"]:
        return [result("FGT-VIP-UNUSED", "n/a", "central NAT is on: VIPs apply without a policy reference",
                       ["set central-nat enable"])]
    used = set()
    for sec in policy_sections:
        for p in sec.values():
            for k in ("dstaddr", "dstaddr6", "dstaddr4"):
                used |= set(p.get(k, []))
    for g in list(used & set(vipgrp)):
        used |= set(vipgrp[g])
    unused = sorted(set(vips) - used)
    if not unused:
        return [result("FGT-VIP-UNUSED", "pass", f"all {len(vips)} VIPs are used by a policy")]
    return [result("FGT-VIP-UNUSED", "fail", f"VIP '{v}' ({(vips[v].get('extip') or ['?'])[0]} -> "
                   f"{' '.join(vips[v].get('mappedip', []))}) is not used by any policy",
                   [f'edit "{v}"'], where=v) for v in unused]


def _av_stale(folder, av_in_use, internet):
    """Virus definitions older than STALE_DAYS on the day of the snapshot, when an AV profile is
    used by a policy. IPS age is FGT-IPS-STALE (seccheck.py); application control ships in the
    same package as IPS, so only AV is added here."""
    if not av_in_use:
        return result("FGT-AV-STALE", "n/a", "no antivirus profile on any active policy")
    when, line, src = None, None, None
    for fname, rx in (("get-system-fortiguard-service-status.txt",
                       r"^Virus Definitions\s+\S+(?:\s+signed)?\s+(\d{4}-\d{2}-\d{2})"),
                      ("get-system-status.txt", r"^Virus-DB:\s*\S+?\((\d{4}-\d{2}-\d{2})")):
        f = folder / fname if folder else None
        if f and f.exists():
            m = re.search(rx, f.read_text(encoding="utf-8", errors="replace"), re.M)
            if m:
                try:
                    when, line, src = dt.date.fromisoformat(m.group(1)), m.group(0).strip(), f
                    break
                except ValueError:
                    pass
    if not when:
        return result("FGT-AV-STALE", "not-visible", "no virus definitions date in the saved FortiGuard status")
    taken = dt.date.fromtimestamp(src.stat().st_mtime)
    age = (taken - when).days
    stale = age > STALE_DAYS
    return result("FGT-AV-STALE", "fail" if stale else "pass",
                  f"virus definitions dated {when}, {age} days old when the snapshot was taken",
                  [re.sub(r"\s{2,}", "  ", line)], exposed=internet and stale)


def analyze(tree, text, dev, section, ifaces, zones, internet_if, policies, vips, vipgrp):
    """All R7 results for one FortiGate. `section` is vendor_fortios._section."""
    ver = version(text)
    glob = section(tree, "system global") if (tree.get("system global") or
                                              tree.get("global", {}).get("system global")) else None
    admin_on = {"https", "http", "ssh", "telnet"}
    wan_admin = any(admin_on & set(ifaces.get(i, {}).get("allowaccess", [])) for i in internet_if)
    out = _global_checks(glob, ver, wan_admin)
    out += _cleartext(ifaces, internet_if, glob)

    admins = section(tree, "system admin")
    partial = bool(admins) and list(admins) == [dev.get("username")]
    out += _two_factor(admins, partial, wan_admin)

    has_pp = "system password-policy" in tree or "system password-policy" in tree.get("global", {})
    out.append(_password_policy(section(tree, "system password-policy") if has_pp else None, ver))

    logs = {}
    for scope in [tree, tree.get("global", {})] + list(tree.get("vdom", {}).values()):
        for k, v in scope.items():
            if k.startswith("log "):
                logs.setdefault(k, {}).update(v)
    out.append(_remote_log(logs))

    out += _local_in(ifaces, zones, internet_if, section(tree, "firewall local-in-policy"))
    out += _vip_unused(vips, vipgrp, [policies, section(tree, "firewall proxy-policy"),
                                      section(tree, "firewall policy6"), section(tree, "firewall policy46")],
                       section(tree, "system settings"))

    av = any((p.get("av-profile") or p.get("profile-group")) and p.get("action") == ["accept"]
             and p.get("status") != ["disable"] for p in policies.values())
    out.append(_av_stale(dev.get("_folder"), av, bool(internet_if)))
    return out
