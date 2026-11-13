# Tests for ios_mgmt.py (round 6, R2 + R3): IOS-XE idle timeout, login lockout, AAA, lines
# without authentication, accounting, banner, NTP, syslog depth and SNMP version. Each check
# gets a pass and a fail case, plus its result on the sanitized lab v2 router.
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import common  # noqa: E402
import ios_mgmt  # noqa: E402
import seccheck  # noqa: E402
import vendor_ios  # noqa: E402

LAB = HERE / "fixtures" / "lab-v2" / "hq-edge-rtr-01"

# A hardened base config: every ios_mgmt check passes on it.
GOOD = """hostname r1
aaa new-model
aaa group server tacacs+ ISE
 server name ISE-1
 server name ISE-2
aaa authentication login default group ISE local
aaa accounting exec default start-stop group ISE
aaa accounting commands 15 default start-stop group ISE
login block-for 900 attempts 3 within 120
tacacs server ISE-1
 address ipv4 10.0.20.61
tacacs server ISE-2
 address ipv4 10.0.20.62
interface Ethernet0/0
 ip address 10.0.0.1 255.255.255.0
logging host 10.0.20.50
logging host 10.0.20.51
snmp-server group NMS v3 priv access MGMT
ntp authentication-key 1 hmac-sha2-256 7 0822455D0A16
ntp authenticate
ntp trusted-key 1
ntp server 10.0.20.40 key 1
ntp server 10.0.20.41 key 1
banner login ^C
Authorized access only.
^C
line con 0
 exec-timeout 5 0
line vty 0 4
 access-class MGMT in
 exec-timeout 5 0
 transport input ssh
"""


def _run(cfg):
    facts, _ = vendor_ios.analyze(cfg, {})
    return {r["check"]: r for r in facts["results"] if r["check"] in ios_mgmt.CHECKS}


def _st(cfg, check):
    return _run(cfg)[check]["status"]


def test_every_new_check_is_in_catalog():
    _, checks = seccheck.load_settings()
    assert set(ios_mgmt.CHECKS) <= set(checks)
    assert set(ios_mgmt.CHECKS) <= set(vendor_ios.CHECKS)


def test_hardened_config_passes_every_check():
    res = _run(GOOD)
    assert set(res) == set(ios_mgmt.CHECKS)
    assert {c: r["status"] for c, r in res.items()} == {c: "pass" for c in ios_mgmt.CHECKS}


# ---------- each check: fail cases ----------
@pytest.mark.parametrize("old,new,check", [
    # idle timeout: never, above 5 min, default (no line = 10 min)
    (" exec-timeout 5 0\nline vty", " exec-timeout 0 0\nline vty", "IOS-EXEC-TIMEOUT"),
    ("access-class MGMT in\n exec-timeout 5 0", "access-class MGMT in\n exec-timeout 15 0", "IOS-EXEC-TIMEOUT"),
    ("access-class MGMT in\n exec-timeout 5 0\n", "access-class MGMT in\n", "IOS-EXEC-TIMEOUT"),
    ("line con 0\n exec-timeout 5 0\n", "line con 0\n no exec-timeout\n", "IOS-EXEC-TIMEOUT"),
    # lockout absent or too loose
    ("login block-for 900 attempts 3 within 120\n", "", "IOS-LOGIN-BLOCK"),
    ("attempts 3 within", "attempts 10 within", "IOS-LOGIN-BLOCK"),
    # local only, one server, no aaa new-model
    ("aaa authentication login default group ISE local", "aaa authentication login default local", "IOS-AAA-CENTRAL"),
    ("tacacs server ISE-2\n address ipv4 10.0.20.62\n", "", "IOS-AAA-CENTRAL"),
    ("aaa new-model\n", "", "IOS-AAA-CENTRAL"),
    # no authentication on a line
    ("aaa authentication login default group ISE local",
     "aaa authentication login default group ISE local\naaa authentication login CON none", None),
    ("aaa authentication login default group ISE local", "aaa authentication login default group ISE none",
     "IOS-LOGIN-NONE"),
    # accounting: none, or exec only
    ("aaa accounting commands 15 default start-stop group ISE\n", "", "IOS-AAA-ACCOUNTING"),
    ("banner login ^C\nAuthorized access only.\n^C\n", "", "IOS-BANNER"),
    # NTP auth: no authenticate, server without key, key not defined
    ("ntp authenticate\n", "", "IOS-NTP-AUTH"),
    ("ntp server 10.0.20.41 key 1", "ntp server 10.0.20.41", "IOS-NTP-AUTH"),
    ("ntp authentication-key 1 hmac-sha2-256 7 0822455D0A16\n", "", "IOS-NTP-AUTH"),
    ("ntp server 10.0.20.41 key 1\n", "", "IOS-NTP-REDUNDANT"),
    # syslog: one host, no logging trap, trap alerts
    ("logging host 10.0.20.51\n", "", "IOS-LOG-DEPTH"),
    ("logging host 10.0.20.51\n", "logging host 10.0.20.51\nno logging trap\n", "IOS-LOG-DEPTH"),
    ("logging host 10.0.20.51\n", "logging host 10.0.20.51\nlogging trap alerts\n", "IOS-LOG-DEPTH"),
    # SNMP: a v2c community with an ACL, a v2c trap host, a v3 group without priv
    ("snmp-server group NMS v3 priv access MGMT", "snmp-server community Zq81long RO MGMT", "IOS-SNMP-V2C"),
    ("snmp-server group NMS v3 priv access MGMT",
     "snmp-server group NMS v3 priv access MGMT\nsnmp-server host 10.0.20.70 version 2c Zq81long", "IOS-SNMP-V2C"),
    ("snmp-server group NMS v3 priv", "snmp-server group NMS v3 auth", "IOS-SNMP-V2C"),
])
def test_fail_cases(old, new, check):
    assert old in GOOD
    cfg = GOOD.replace(old, new)
    if check is None:      # a defined but unused 'none' list is not a finding
        assert _st(cfg, "IOS-LOGIN-NONE") == "pass"
        return
    assert _st(cfg, check) == "fail", _run(cfg)[check]


def test_pass_variants():
    # archive log config is the STIG form of the admin audit trail
    cfg = GOOD.replace("aaa accounting commands 15 default start-stop group ISE\n",
                       "archive\n log config\n  logging enable\n  hidekeys\n")
    assert _st(cfg, "IOS-AAA-ACCOUNTING") == "pass"
    # banner motd counts, critical trap level passes, legacy server lines count
    cfg = GOOD.replace("banner login", "banner motd").replace("logging host 10.0.20.51\n",
                                                                   "logging host 10.0.20.51\nlogging trap critical\n")
    assert _st(cfg, "IOS-BANNER") == "pass" and _st(cfg, "IOS-LOG-DEPTH") == "pass"
    cfg = GOOD.replace("tacacs server ISE-1\n address ipv4 10.0.20.61\ntacacs server ISE-2\n address ipv4 10.0.20.62\n",
                       "tacacs-server host 10.0.20.61\ntacacs-server host 10.0.20.62\n")
    assert _st(cfg, "IOS-AAA-CENTRAL") == "pass"
    # a vty that accepts no logins is not judged
    cfg = GOOD.replace(" transport input ssh", " transport input none")
    res = _run(cfg)
    assert res["IOS-LOGIN-BLOCK"]["status"] == "n/a" and res["IOS-AAA-CENTRAL"]["status"] == "n/a"


def test_without_aaa_console_default_is_no_login():
    cfg = "hostname r1\ninterface Ethernet0/0\n ip address 10.0.0.1 255.255.255.0\nlogging host 10.0.0.9\n" \
          "line con 0\n exec-timeout 5 0\nline vty 0 4\n login local\n transport input ssh\n"
    r = _run(cfg)["IOS-LOGIN-NONE"]
    assert r["status"] == "fail" and "line con 0" in r["detail"] and "line vty" not in r["detail"]
    r = _run(cfg.replace("line con 0\n", "line con 0\n login local\n"))["IOS-LOGIN-NONE"]
    assert r["status"] == "pass"
    r = _run(cfg.replace(" login local", " no login"))["IOS-LOGIN-NONE"]
    assert r["status"] == "fail" and "line vty 0 4" in r["detail"]


def test_vty_with_no_auth_on_the_internet_is_exposed():
    cfg = GOOD.replace("10.0.0.1 255.255.255.0", "203.0.113.2 255.255.255.252").replace(
        " access-class MGMT in\n", "").replace("group ISE local", "none")
    r = _run(cfg)["IOS-LOGIN-NONE"]
    assert r["status"] == "fail" and r["exposed"] is True
    assert _run(cfg)["IOS-LOGIN-BLOCK"]["exposed"] is False     # lockout is in place in GOOD


def test_n_a_without_ntp_syslog_or_snmp():
    cfg = "hostname r1\ninterface Ethernet0/0\n ip address 10.0.0.1 255.255.255.0\nno ip http server\n" \
          "no vstack\nip ssh version 2\nline vty 0 4\n transport input ssh\n"
    res = _run(cfg)
    assert res["IOS-NTP-AUTH"]["status"] == "n/a" and res["IOS-LOG-DEPTH"]["status"] == "n/a"
    assert res["IOS-SNMP-V2C"]["status"] == "n/a"
    assert res["IOS-NTP-REDUNDANT"]["status"] == "fail"       # no NTP at all: no time source


def test_snmp_evidence_hides_community_strings():
    cfg = GOOD.replace("snmp-server group NMS v3 priv access MGMT",
                       "snmp-server community Zq81long RO MGMT\n"
                       "snmp-server host 10.0.20.70 vrf MGMT version 2c Zq81long udp-port 162\n"
                       "snmp-server host 10.0.20.71 Zq81long")
    r = _run(cfg)["IOS-SNMP-V2C"]
    text = " ".join(r["evidence"]) + r["detail"]
    assert "Zq81long" not in text and "<hidden>" in text
    assert "1 v1/v2c community" in r["detail"] and "2 trap host(s)" in r["detail"]


def test_nearly_empty_config_is_not_visible():
    facts, _ = vendor_ios.analyze("hostname r1\n", {})
    assert {r["status"] for r in facts["results"] if r["check"] in ios_mgmt.CHECKS} == {"not-visible"}


# ---------- lab v2 (hq-edge-rtr-01, IOL IOS-XE 17.16.1a, sanitized) ----------
def test_lab_results():
    text = (LAB / "show-running-config-view-full.txt").read_text(encoding="utf-8")
    facts, found = vendor_ios.analyze(text, {"_folder": LAB})
    res = {r["check"]: r for r in facts["results"] if r["check"] in ios_mgmt.CHECKS}
    assert {c: r["status"] for c, r in res.items()} == {c: "fail" for c in ios_mgmt.CHECKS}
    assert "line con 0 (never)" in res["IOS-EXEC-TIMEOUT"]["detail"]
    assert "line vty 0 4 (30 min)" in res["IOS-EXEC-TIMEOUT"]["detail"]
    assert "login list CONSOLE: none" in res["IOS-LOGIN-NONE"]["detail"]
    assert "privilege level 15" in res["IOS-LOGIN-NONE"]["detail"]
    assert "login list default: local" in res["IOS-AAA-CENTRAL"]["detail"]
    assert res["IOS-LOG-DEPTH"]["detail"].startswith("One syslog host")
    assert res["IOS-NTP-REDUNDANT"]["detail"].startswith("1 NTP server")
    # the lab vty has an access-class and the console is physical: nothing here is internet-exposed
    assert not any(r["exposed"] for r in res.values())
    assert all(r in found for r in res.values())
    assert all(r["status"] in common.STATUSES for r in facts["results"])
