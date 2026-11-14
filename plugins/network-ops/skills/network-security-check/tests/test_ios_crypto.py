# Tests for round 14 (B3): management transport crypto. IOS-SSH-CRYPTO from saved 'show ip ssh'
# and 'ip ssh ...' config, IOS-MGMT-CLEARTEXT-XFER / -CRED from transfer config, and the FortiGate
# FGT-ADMIN-SSH-CRYPTO. Offline: the sanitized lab v2 configs and small configs built here.
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import ios_crypto  # noqa: E402
import vendor_fortios  # noqa: E402
import vendor_ios  # noqa: E402

LAB = HERE / "fixtures" / "lab-v2"
CHECKS = yaml.safe_load((HERE.parent / "settings" / "checks.yaml").read_text(encoding="utf-8"))

# The IOS-XE 17.16.1a lab output (all 11 devices print these same algorithm lines).
STRONG_SHOW = """SSH Enabled - version 2.0
Authentication methods:publickey,keyboard-interactive,password
Hostkey Algorithms:ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
Encryption Algorithms:chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-gcm,aes256-gcm,aes128-ctr,aes192-ctr,aes256-ctr
MAC Algorithms:hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KEX Algorithms:curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512
Authentication timeout: 120 secs; Authentication retries: 3
Minimum expected Diffie Hellman key size : 2048 bits
IOS Keys in SECSH format(ssh-rsa, base64 encoded): SSH
Modulus Size : 2048 bits
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest
"""
WEAK_SHOW = """SSH Enabled - version 2.0
Hostkey Algorithms:rsa-sha2-512,rsa-sha2-256,ssh-rsa
Encryption Algorithms:aes128-ctr,aes256-ctr,aes128-cbc,3des-cbc
MAC Algorithms:hmac-sha2-256,hmac-sha1
KEX Algorithms:diffie-hellman-group14-sha256,diffie-hellman-group14-sha1
Minimum expected Diffie Hellman key size : 1024 bits
Modulus Size : 1024 bits
"""

BASE = """hostname r1
interface Ethernet0/0
 ip address 203.0.113.2 255.255.255.252
interface Ethernet0/1
 ip address 10.0.0.1 255.255.255.0
logging host 10.0.20.50
ip access-list standard MGMT
 permit 10.0.20.0 0.0.0.255
line con 0
 exec-timeout 5 0
"""
VTY_ACL = "line vty 0 4\n access-class MGMT in\n transport input ssh\n"
VTY_OPEN = "line vty 0 4\n transport input ssh\n"


def _results(cfg, show=None, tmp_path=None):
    dev = {}
    if show is not None:
        (tmp_path / "show-ip-ssh.txt").write_text(show, encoding="utf-8")
        dev["_folder"] = str(tmp_path)
    facts, _ = vendor_ios.analyze(cfg, dev)
    return {r["check"]: r for r in facts["results"] if r["check"] in ios_crypto.CHECKS}


# ---------- IOS-SSH-CRYPTO ----------
def test_lab_devices_pass_by_hand():
    """By hand: every lab show ip ssh lists only GCM/CTR/chacha20, SHA-2 ETM MACs, curve25519/ECDH/
    group14-sha256/group16-sha512, no ssh-rsa host key, DH minimum 2048, RSA modulus 2048."""
    for name in ("hq-edge-rtr-01", "hq-dist-sw-01", "hq-acc-sw-01"):
        folder = LAB / name
        text = (folder / "show-running-config-view-full.txt").read_text(encoding="utf-8")
        facts, found = vendor_ios.analyze(text, {"_folder": str(folder)})
        r = {x["check"]: x for x in facts["results"]}
        assert r["IOS-SSH-CRYPTO"]["status"] == "pass", (name, r["IOS-SSH-CRYPTO"])
        assert "DH minimum 2048 bits" in r["IOS-SSH-CRYPTO"]["detail"]
        # some sanitized fixtures drop the key block (Modulus Size); the real lab shows 2048 bits on all 11
        shown = "Modulus Size" in (folder / "show-ip-ssh.txt").read_text(encoding="utf-8")
        assert ("RSA host key 2048 bits" if shown else "RSA host key size not shown") in r["IOS-SSH-CRYPTO"]["detail"]
        assert r["IOS-MGMT-CLEARTEXT-XFER"]["status"] == "pass"
        assert r["IOS-MGMT-CLEARTEXT-CRED"]["status"] == "pass"
        assert not any(f["check"] in ios_crypto.CHECKS for f in found)


def test_show_strong_passes(tmp_path):
    r = _results(BASE + VTY_ACL, STRONG_SHOW, tmp_path)["IOS-SSH-CRYPTO"]
    assert r["status"] == "pass"
    assert "(show ip ssh)" in r["detail"]
    assert not any("AAAAB3" in e for e in r["evidence"])       # the key blob is not evidence


def test_show_weak_fails_each_reason(tmp_path):
    r = _results(BASE + VTY_ACL, WEAK_SHOW, tmp_path)["IOS-SSH-CRYPTO"]
    assert r["status"] == "fail"
    d = r["detail"]
    for part in ("aes128-cbc", "3des-cbc", "hmac-sha1", "diffie-hellman-group14-sha1", "hostkey ssh-rsa",
                 "Diffie-Hellman minimum 1024 bits", "RSA host key 1024 bits"):
        assert part in d, part
    assert "aes128-ctr" not in d.split("encryption")[1].split(";")[0]
    assert "rsa-sha2-512" not in d                                # rsa-sha2 host keys are fine
    assert r["exposed"] is False                                  # vty has an inbound access-class


def test_exposed_only_internet_and_no_vty_acl(tmp_path):
    assert _results(BASE + VTY_OPEN, WEAK_SHOW, tmp_path)["IOS-SSH-CRYPTO"]["exposed"] is True
    internal = BASE.replace("203.0.113.2", "10.9.9.2")
    assert _results(internal + VTY_OPEN, WEAK_SHOW, tmp_path)["IOS-SSH-CRYPTO"]["exposed"] is False


def test_show_wins_over_config(tmp_path):
    cfg = BASE + "ip ssh server algorithm encryption aes256-cbc\n" + VTY_ACL
    r = _results(cfg, STRONG_SHOW, tmp_path)["IOS-SSH-CRYPTO"]
    assert r["status"] == "pass"            # show ip ssh is what the server really offers


def test_no_show_no_config_not_visible():
    r = _results(BASE + VTY_ACL)["IOS-SSH-CRYPTO"]
    assert r["status"] == "not-visible"
    assert "show ip ssh" in r["detail"]


def test_config_only_weak_fails():
    cfg = BASE + "ip ssh server algorithm encryption aes256-ctr aes256-cbc\nip ssh dh min size 1024\n" + VTY_ACL
    r = _results(cfg)["IOS-SSH-CRYPTO"]
    assert r["status"] == "fail"
    assert "aes256-cbc" in r["detail"] and "1024" in r["detail"]
    assert "Not seen" in r["detail"]                 # mac, kex, hostkey left at the release default


def test_config_only_all_strong_passes():
    cfg = BASE + ("ip ssh server algorithm encryption aes256-gcm aes256-ctr\n"
                  "ip ssh server algorithm mac hmac-sha2-256-etm@openssh.com\n"
                  "ip ssh server algorithm kex ecdh-sha2-nistp384 diffie-hellman-group16-sha512\n"
                  "ip ssh server algorithm hostkey rsa-sha2-512\n"
                  "ip ssh dh min size 4096\n") + VTY_ACL
    r = _results(cfg)["IOS-SSH-CRYPTO"]
    assert r["status"] == "pass"
    assert "RSA host key size not shown" in r["detail"]


def test_partial_config_strong_not_visible():
    cfg = BASE + "ip ssh server algorithm encryption aes256-gcm\n" + VTY_ACL
    assert _results(cfg)["IOS-SSH-CRYPTO"]["status"] == "not-visible"


def test_na_cases(tmp_path):
    assert _results(BASE)["IOS-SSH-CRYPTO"]["status"] == "n/a"                       # no vty
    telnet_only = BASE + "line vty 0 4\n access-class MGMT in\n transport input telnet\n"
    assert _results(telnet_only)["IOS-SSH-CRYPTO"]["status"] == "n/a"
    off = "SSH Disabled - version 2.0\n"
    assert _results(BASE + VTY_ACL, off, tmp_path)["IOS-SSH-CRYPTO"]["status"] == "n/a"


def test_mac_and_kex_edge_names():
    w = ios_crypto._WEAK
    assert w["mac"]("hmac-sha1-96") and w["mac"]("hmac-md5") and w["mac"]("umac-64@openssh.com")
    assert not w["mac"]("hmac-sha2-256") and not w["mac"]("umac-128@openssh.com")
    assert w["kex"]("diffie-hellman-group1-sha1") and w["kex"]("diffie-hellman-group-exchange-sha1")
    assert not w["kex"]("diffie-hellman-group14-sha256") and not w["kex"]("curve25519-sha256")
    assert w["encryption"]("rijndael-cbc@lysator.liu.se") and w["encryption"]("arcfour256")
    assert not w["encryption"]("chacha20-poly1305@openssh.com")
    assert w["hostkey"]("x509v3-ssh-rsa") and not w["hostkey"]("rsa-sha2-256")


# ---------- IOS-MGMT-CLEARTEXT-XFER / -CRED ----------
def test_archive_tftp_is_xfer_not_cred():
    r = _results(BASE + VTY_ACL + "archive\n path tftp://10.0.20.9/$h-$t\n write-memory\n")
    assert r["IOS-MGMT-CLEARTEXT-XFER"]["status"] == "fail"
    assert r["IOS-MGMT-CLEARTEXT-XFER"]["exposed"] is False
    assert r["IOS-MGMT-CLEARTEXT-CRED"]["status"] == "pass"


def test_url_password_is_cred_and_masked():
    secret = "Sup3rS3cret"
    cfg = BASE + VTY_ACL + f"archive\n path ftp://backup:{secret}@10.0.20.9/cfg/$h\n"
    r = _results(cfg)
    assert r["IOS-MGMT-CLEARTEXT-XFER"]["status"] == "fail"
    assert r["IOS-MGMT-CLEARTEXT-CRED"]["status"] == "fail"
    blob = repr(r)
    assert secret not in blob
    assert "ftp://backup:<hidden>@10.0.20.9" in blob


def test_ip_ftp_password_masked():
    secret = "0822455D0A16"
    cfg = BASE + VTY_ACL + f"ip ftp username backup\nip ftp password 7 {secret}\n"
    r = _results(cfg)["IOS-MGMT-CLEARTEXT-CRED"]
    assert r["status"] == "fail"
    assert secret not in repr(r)
    assert any(e.startswith("ip ftp password") for e in r["evidence"])


def test_http_client_password_cred():
    r = _results(BASE + VTY_ACL + "ip http client password 0 plainpw\n")["IOS-MGMT-CLEARTEXT-CRED"]
    assert r["status"] == "fail" and "plainpw" not in repr(r)


def test_eem_boot_and_tftp_server():
    cfg = BASE + VTY_ACL + ("event manager applet BACKUP\n event syslog pattern \"%SYS-5-CONFIG_I\"\n"
                            " action 1.0 cli command \"enable\"\n"
                            " action 2.0 cli command \"copy run tftp://10.0.20.9/r1.cfg\"\n"
                            "boot system tftp c8000v.bin 10.0.20.9\n"
                            "tftp-server flash:c8000v.bin\n")
    r = _results(cfg)["IOS-MGMT-CLEARTEXT-XFER"]
    assert r["status"] == "fail"
    assert r["detail"].startswith("3 config line(s)")


def test_scp_and_boot_network_not_flagged():
    cfg = BASE + VTY_ACL + ("ip scp server enable\narchive\n path scp://backup@10.0.20.9/$h\n"
                            "event manager applet B\n action 1 cli command \"copy run scp://10.0.20.9/r1\"\n"
                            "boot system flash:c8000v.bin\nboot network tftp://10.0.20.9/net.cfg\n")
    r = _results(cfg)
    assert r["IOS-MGMT-CLEARTEXT-XFER"]["status"] == "pass"   # boot network: IOS-LEGACY-SERVICES
    assert r["IOS-MGMT-CLEARTEXT-CRED"]["status"] == "pass"


def test_hide_url_cred():
    assert ios_crypto.hide_url_cred("path ftp://u:p@h/x") == "path ftp://u:<hidden>@h/x"
    assert ios_crypto.hide_url_cred("path tftp://h/x") == "path tftp://h/x"


# ---------- catalog wiring ----------
def test_catalog_entries():
    for cid in ios_crypto.CHECKS + ("FGT-ADMIN-SSH-CRYPTO",):
        assert cid in CHECKS, cid
        assert CHECKS[cid]["plane"] == "management"
        assert CHECKS[cid]["known_exploited"] is False
    assert CHECKS["IOS-MGMT-CLEARTEXT-XFER"]["tier"] == "advisory"
    assert CHECKS["IOS-MGMT-CLEARTEXT-XFER"]["suppressed_by"] == ["IOS-MGMT-CLEARTEXT-CRED"]
    assert CHECKS["IOS-MGMT-CLEARTEXT-CRED"].get("tier", "standard") == "standard"
    assert set(ios_crypto.CHECKS) <= set(vendor_ios.CHECKS)
    assert "FGT-ADMIN-SSH-CRYPTO" in vendor_fortios.CHECKS


def test_nearly_empty_config_reports_not_visible():
    facts, _ = vendor_ios.analyze("hostname r1\n", {})
    st = {r["check"]: r["status"] for r in facts["results"]}
    assert all(st[c] == "not-visible" for c in ios_crypto.CHECKS)


# ---------- FortiGate FGT-ADMIN-SSH-CRYPTO ----------
HEADER = "#config-version=FGVM64-8.0.1-FW-build0245-260909:opmode=1:vdom=0:user=x\n"
FGT_IFACES = """config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.248
        set allowaccess ping ssh
        set role wan
    next
end
"""


def _fgt(extra="", glob=""):
    text = HEADER + "config system global\n    set hostname \"fw\"\n" + glob + "end\n" + FGT_IFACES + extra
    facts, _ = vendor_fortios.analyze(text, {"username": "x"})
    return next(r for r in facts["results"] if r["check"] == "FGT-ADMIN-SSH-CRYPTO")


def test_fgt_lab_defaults_pass():
    text = (LAB / "fw-01" / "show.txt").read_text(encoding="utf-8")
    facts, _ = vendor_fortios.analyze(text, {"username": "claude-ro-cli", "_folder": LAB / "fw-01"})
    r = next(x for x in facts["results"] if x["check"] == "FGT-ADMIN-SSH-CRYPTO")
    assert r["status"] == "pass" and "defaults" in r["detail"]


def test_fgt_ssh_config_weak_fails_and_exposed():
    r = _fgt("config system ssh-config\n    set ssh-enc-algo aes256-ctr aes128-cbc\n"
             "    set ssh-mac-algo hmac-sha2-256 hmac-sha1\n    set ssh-hsk-algo ssh-rsa rsa-sha2-512\nend\n")
    assert r["status"] == "fail"
    assert "aes128-cbc" in r["detail"] and "hmac-sha1" in r["detail"] and "ssh-rsa" in r["detail"]
    assert "rsa-sha2-512" not in r["detail"]
    assert r["exposed"] is True                    # admin SSH allowed on the WAN interface


def test_fgt_global_70_style_kex_fails():
    r = _fgt(glob="    set ssh-kex-algo diffie-hellman-group14-sha256 diffie-hellman-group14-sha1\n")
    assert r["status"] == "fail" and "diffie-hellman-group14-sha1" in r["detail"]


def test_fgt_explicit_strong_passes():
    r = _fgt("config system ssh-config\n    set ssh-enc-algo aes256-gcm@openssh.com\n"
             "    set ssh-kex-algo curve25519-sha256@libssh.org\nend\n")
    assert r["status"] == "pass" and "set explicitly" in r["detail"]
