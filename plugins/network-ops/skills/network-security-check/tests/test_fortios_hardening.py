# Tests for the FortiGate hardening checks (roadmap R7, scripts/fgt_hardening.py). Offline:
# the sanitized lab v2 fw-01 config (FortiGate-VM 8.0.1) and small configs built here.
import os
import re
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import common  # noqa: E402
import fgt_hardening  # noqa: E402
import seccheck  # noqa: E402
import vendor_fortios  # noqa: E402

LAB = HERE / "fixtures" / "lab-v2" / "fw-01"
LAB_TEXT = (LAB / "show.txt").read_text(encoding="utf-8")
HEADER = "#config-version=FGVM64-8.0.1-FW-build0245-260909:opmode=1:vdom=0:user=x\n"
IFACES = """config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.248
        set allowaccess ping
        set role wan
    next
    edit "lan"
        set ip 10.20.0.1 255.255.255.0
        set allowaccess ping https ssh
        set role lan
    next
end
"""


def run(text, user="x", folder=None):
    facts, found = vendor_fortios.analyze(text, {"username": user, "_folder": folder})
    return facts["results"], found


def status(results, check):
    return sorted({r["status"] for r in results if r["check"] == check})


def one(results, check):
    hits = [r for r in results if r["check"] == check]
    assert len(hits) == 1, hits
    return hits[0]


def cfg(global_lines="", extra="", ifaces=IFACES, header=HEADER):
    g = "config system global\n    set hostname \"fw\"\n" + "".join(f"    {l}\n" for l in global_lines.splitlines()
                                                              if l.strip()) + "end\n"
    return header + g + ifaces + extra


# ---------- lab v2 fw-01: every check reports, by-hand verdicts ----------
def test_lab_fw01_results():
    res, found = run(LAB_TEXT, user="claude-ro-cli", folder=LAB)
    assert {r["check"] for r in res} == set(vendor_fortios.CHECKS)
    assert found == common.fails(res)
    expect = {"FGT-ADMIN-LOCKOUT": "fail",       # default 60 s < STIG 900 s
              "FGT-ADMIN-TIMEOUT": "pass", "FGT-WEAK-ADMIN-TLS": "pass", "FGT-ADMIN-CLEARTEXT": "pass",
              "FGT-ADMIN-NO-2FA": "not-visible",  # read-only profile sees only itself
              "FGT-PASSWORD-POLICY": "fail",     # enabled, default 12 chars on 8.0 < 15
              "FGT-NO-REMOTE-LOG": "pass", "FGT-WAN-NO-LOCAL-IN": "n/a", "FGT-VIP-UNUSED": "n/a",
              "FGT-AV-STALE": "n/a"}
    for c, st in expect.items():
        assert status(res, c) == [st], c
    lock = one(res, "FGT-ADMIN-LOCKOUT")
    assert "60 s (FortiOS default)" in lock["detail"] and not lock["exposed"]
    assert "default 12" in " ".join(one(res, "FGT-PASSWORD-POLICY")["evidence"])
    assert "192.168.1.230" in one(res, "FGT-NO-REMOTE-LOG")["detail"]


def test_version_header():
    assert fgt_hardening.version(LAB_TEXT) == (8, 0, 1)
    assert fgt_hardening.version("config system global\nend\n") is None


# ---------- lockout and timeout ----------
def test_lockout_grading():
    res, _ = run(cfg("set admin-lockout-threshold 3\nset admin-lockout-duration 900"))
    assert status(res, "FGT-ADMIN-LOCKOUT") == ["pass"]
    res, _ = run(cfg("set admin-lockout-threshold 5\nset admin-lockout-duration 900"))
    r = one(res, "FGT-ADMIN-LOCKOUT")
    assert r["status"] == "fail" and "after 5 failed logins" in r["detail"]
    assert not r["exposed"]                       # admin only on the LAN
    wan_admin = IFACES.replace("set allowaccess ping\n        set role wan", "set allowaccess ping https\n"
                                                                            "        set role wan")
    res, _ = run(cfg("", ifaces=wan_admin))
    assert one(res, "FGT-ADMIN-LOCKOUT")["exposed"]


def test_timeout_default_passes_explicit_high_fails():
    res, _ = run(cfg(""))
    assert status(res, "FGT-ADMIN-TIMEOUT") == ["pass"]
    res, _ = run(cfg("set admintimeout 10"))
    assert status(res, "FGT-ADMIN-TIMEOUT") == ["pass"]
    res, _ = run(cfg("set admintimeout 30"))
    r = one(res, "FGT-ADMIN-TIMEOUT")
    assert r["status"] == "fail" and r["evidence"] == ["set admintimeout 30"]


def test_older_release_says_defaults_unchecked():
    old = HEADER.replace("8.0.1", "7.4.2")
    res, _ = run(cfg("", header=old))
    assert "7.4.2, whose defaults were not checked" in one(res, "FGT-ADMIN-LOCKOUT")["detail"]
    res, _ = run(cfg("set admintimeout 30", header=old))      # explicit value: no default caveat
    assert "not checked" not in one(res, "FGT-ADMIN-TIMEOUT")["detail"]


def test_global_missing_is_not_visible():
    res, _ = run(HEADER + IFACES)
    for c in ("FGT-ADMIN-LOCKOUT", "FGT-ADMIN-TIMEOUT", "FGT-WEAK-ADMIN-TLS"):
        assert status(res, c) == ["not-visible"], c


# ---------- crypto ----------
def test_weak_admin_tls():
    res, _ = run(cfg("set strong-crypto enable\nset admin-https-ssl-versions tlsv1-2 tlsv1-3"))
    assert status(res, "FGT-WEAK-ADMIN-TLS") == ["pass"]
    res, _ = run(cfg("set strong-crypto disable\nset admin-https-ssl-versions tlsv1-1 tlsv1-2\n"
                     "set ssl-min-proto-version TLSv1-1\nset admin-ssh-v1 enable"))
    r = one(res, "FGT-WEAK-ADMIN-TLS")      # one finding: one place to fix
    assert r["status"] == "fail"
    for part in ("strong-crypto disable", "tlsv1-1", "ssl-min-proto-version TLSv1-1", "SSH v1"):
        assert part in r["detail"], part


# ---------- clear-text admin ----------
def test_cleartext_internal_only():
    lan_telnet = IFACES.replace("set allowaccess ping https ssh", "set allowaccess ping https ssh telnet http")
    res, _ = run(cfg("", ifaces=lan_telnet))
    r = one(res, "FGT-ADMIN-CLEARTEXT")
    assert r["status"] == "fail" and r["where"] == "lan" and "http and telnet" in r["detail"]
    lan_http = IFACES.replace("set allowaccess ping https ssh", "set allowaccess ping http https")
    res, _ = run(cfg("", ifaces=lan_http))
    assert "redirected to HTTPS" in one(res, "FGT-ADMIN-CLEARTEXT")["detail"]
    res, _ = run(cfg("set admin-https-redirect disable", ifaces=lan_http))
    assert "redirected" not in one(res, "FGT-ADMIN-CLEARTEXT")["detail"]
    # telnet on WAN is FGT-MGMT-ON-WAN's finding, not counted twice
    wan_telnet = IFACES.replace("set allowaccess ping\n        set role wan", "set allowaccess ping telnet\n"
                                                                              "        set role wan")
    res, found = run(cfg("", ifaces=wan_telnet))
    assert status(res, "FGT-ADMIN-CLEARTEXT") == ["pass"]
    assert "FGT-MGMT-ON-WAN" in {f["check"] for f in found}


# ---------- two-factor ----------
ADMINS = """config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC SH2nlSm7BqZ2rqOtlL0Yu2O8wVaLxGPWB9wRBd=
    next
    edit "ops"
        set accprofile "super_admin"
        set two-factor fortitoken
        set fortitoken "FTKMOB0000000000"
    next
    edit "radius-admins"
        set remote-auth enable
        set wildcard enable
        set remote-group "ops-radius"
    next
end
"""


def test_two_factor():
    res, _ = run(cfg("", extra=ADMINS))
    fails = [r for r in res if r["check"] == "FGT-ADMIN-NO-2FA"]
    assert [r["where"] for r in fails] == ["admin"] and fails[0]["status"] == "fail"
    fixed = ADMINS.replace('set accprofile "super_admin"\n        set password', 'set two-factor email\n'
                           '        set password')
    res, _ = run(cfg("", extra=fixed))
    r = one(res, "FGT-ADMIN-NO-2FA")
    assert r["status"] == "pass" and "radius-admins authenticate remotely" in r["detail"]
    # only the snapshot account visible: not-visible, never a pass
    res, _ = run(cfg("", extra=ADMINS.split('    edit "ops"')[0] + "end\n"), user="admin")
    assert status(res, "FGT-ADMIN-NO-2FA") == ["not-visible"]


# ---------- password policy ----------
def test_password_policy_versions():
    pp = "config system password-policy\n    set status enable\nend\n"
    res, _ = run(cfg("", extra=pp))
    assert "only 12 characters" in one(res, "FGT-PASSWORD-POLICY")["detail"]       # 8.0 default
    res, _ = run(cfg("", extra=pp, header=HEADER.replace("8.0.1", "7.4.2")))
    assert "only 8 characters" in one(res, "FGT-PASSWORD-POLICY")["detail"]        # pre-7.6.5 default
    empty = "config system password-policy\nend\n"
    res, _ = run(cfg("", extra=empty, header=HEADER.replace("8.0.1", "7.4.2")))
    assert "status disable" in one(res, "FGT-PASSWORD-POLICY")["detail"]
    res, _ = run(cfg("", extra=empty))                                             # 8.0: on by default
    assert "status" not in one(res, "FGT-PASSWORD-POLICY")["detail"]
    good = "config system password-policy\n    set status enable\n    set minimum-length 15\nend\n"
    res, _ = run(cfg("", extra=good))
    assert status(res, "FGT-PASSWORD-POLICY") == ["pass"]
    psk_only = good.replace("set minimum-length 15", "set minimum-length 15\n    set apply-to ipsec-preshared-key")
    res, _ = run(cfg("", extra=psk_only))
    assert "does not apply to admin" in one(res, "FGT-PASSWORD-POLICY")["detail"]
    res, _ = run(cfg(""))
    assert status(res, "FGT-PASSWORD-POLICY") == ["not-visible"]


# ---------- remote logging ----------
def test_remote_log():
    local_only = "config log memory setting\n    set status enable\nend\nconfig log syslogd setting\nend\n"
    res, _ = run(cfg("", extra=local_only))
    assert status(res, "FGT-NO-REMOTE-LOG") == ["fail"]
    faz = local_only + "config log fortianalyzer setting\n    set status enable\n    set server \"10.9.9.9\"\nend\n"
    res, _ = run(cfg("", extra=faz))
    assert status(res, "FGT-NO-REMOTE-LOG") == ["pass"]
    res, _ = run(cfg(""))
    assert status(res, "FGT-NO-REMOTE-LOG") == ["not-visible"]
    # multi-VDOM: log settings under config global count
    mv = (HEADER + "config global\nconfig system global\n    set hostname \"fw\"\nend\n" + IFACES +
          "config log syslogd2 setting\n    set status enable\n    set server \"10.9.9.8\"\nend\nend\n")
    res, _ = run(mv)
    assert status(res, "FGT-NO-REMOTE-LOG") == ["pass"]


# ---------- local-in ----------
def test_wan_local_in():
    fabric = IFACES.replace("set allowaccess ping\n        set role wan", "set allowaccess ping fabric fgfm\n"
                                                                          "        set role wan")
    res, _ = run(cfg("", ifaces=fabric))
    r = one(res, "FGT-WAN-NO-LOCAL-IN")
    assert r["status"] == "fail" and r["exposed"] and "fabric fgfm" in r["detail"]
    li = ("config firewall local-in-policy\n    edit 1\n        set intf \"wan1\"\n        set srcaddr \"fmg\"\n"
          "        set dstaddr \"all\"\n        set action accept\n        set service \"ALL\"\n"
          "        set schedule \"always\"\n    next\nend\n")
    res, _ = run(cfg("", ifaces=fabric, extra=li))
    assert status(res, "FGT-WAN-NO-LOCAL-IN") == ["pass"]
    res, _ = run(cfg("", ifaces=fabric, extra=li.replace("set schedule", "set status disable\n"
                                                                          "        set schedule")))
    assert status(res, "FGT-WAN-NO-LOCAL-IN") == ["fail"]
    # https on WAN alone: FGT-MGMT-ON-WAN's finding, this one is n/a
    https = IFACES.replace("set allowaccess ping\n        set role wan", "set allowaccess ping https\n"
                                                                          "        set role wan")
    res, _ = run(cfg("", ifaces=https))
    assert status(res, "FGT-WAN-NO-LOCAL-IN") == ["n/a"]


# ---------- unused VIPs ----------
VIPS = """config firewall vip
    edit "web"
        set extip 203.0.113.12
        set mappedip "10.20.0.80"
        set extintf "wan1"
    next
    edit "old"
        set extip 203.0.113.13
        set mappedip "10.20.0.30"
        set extintf "wan1"
    next
    edit "grp-member"
        set extip 203.0.113.14
        set mappedip "10.20.0.40"
        set extintf "wan1"
    next
end
config firewall vipgrp
    edit "g1"
        set member "grp-member"
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "lan"
        set action accept
        set srcaddr "all"
        set dstaddr "web" "g1"
        set service "HTTPS"
        set ips-sensor "default"
    next
end
"""


def test_vip_unused():
    res, _ = run(cfg("", extra=VIPS))
    fails = [r for r in res if r["check"] == "FGT-VIP-UNUSED"]
    assert [r["where"] for r in fails] == ["old"] and not fails[0]["exposed"]
    central = VIPS + "config system settings\n    set central-nat enable\nend\n"
    res, _ = run(cfg("", extra=central))
    assert status(res, "FGT-VIP-UNUSED") == ["n/a"]


# ---------- AV definitions ----------
AV_POLICY = """config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set av-profile "default"
        set nat enable
    next
end
"""


def _taken(folder, name, when):
    f = folder / name
    t = time.mktime(time.strptime(when, "%Y-%m-%d"))
    os.utime(f, (t, t))


def test_av_stale_reads_fortiguard_status(tmp_path):
    shutil.copy(LAB / "get-system-fortiguard-service-status.txt", tmp_path)
    _taken(tmp_path, "get-system-fortiguard-service-status.txt", "2026-11-13")
    res, _ = run(cfg("", extra=AV_POLICY), folder=tmp_path)
    r = one(res, "FGT-AV-STALE")
    assert r["status"] == "fail" and r["exposed"] and "2026-04-02, 225 days old" in r["detail"]
    _taken(tmp_path, "get-system-fortiguard-service-status.txt", "2026-04-20")
    res, _ = run(cfg("", extra=AV_POLICY), folder=tmp_path)
    assert status(res, "FGT-AV-STALE") == ["pass"]


def test_av_stale_falls_back_to_system_status_and_n_a(tmp_path):
    shutil.copy(LAB / "get-system-status.txt", tmp_path)
    _taken(tmp_path, "get-system-status.txt", "2026-11-13")
    res, _ = run(cfg("", extra=AV_POLICY), folder=tmp_path)
    assert status(res, "FGT-AV-STALE") == ["fail"]
    res, _ = run(cfg("", extra=AV_POLICY), folder=tmp_path / "missing")
    assert status(res, "FGT-AV-STALE") == ["not-visible"]
    res, _ = run(cfg(""), folder=tmp_path)                # no AV profile in use
    assert status(res, "FGT-AV-STALE") == ["n/a"]


# ---------- catalog and secrets ----------
def test_new_checks_in_catalog():
    _, checks = seccheck.load_settings()
    for c in fgt_hardening.CHECKS:
        assert c in checks, c
        assert checks[c]["known_exploited"] is False, c      # no tier-1 exploitation source for these
        assert checks[c]["weight"] <= 0.4, c


def test_hardening_evidence_masks_secrets():
    res, _ = run(cfg("set admintimeout 30", extra=ADMINS + VIPS))
    text = " ".join(e for r in res for e in r["evidence"]) + " ".join(r["detail"] for r in res)
    assert "SH2nlSm7" not in text and not re.search(r"ENC (?!<hidden>)\S", text)
