# mask() must hide every secret value that can sit on an IOS or FortiOS config line, because
# evidence lines are quoted in reports.
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from common import mask, result  # noqa: E402

LEAKS = ["SECRETVALUE1"]


@pytest.mark.parametrize("line,kept", [
    ("standby 10 authentication text SECRETVALUE1", "standby 10 authentication text"),
    ("standby 10 authentication md5 key-string 7 SECRETVALUE1", "key-string 7"),
    ("standby 1 authentication SECRETVALUE1", "standby 1 authentication"),
    ("vrrp 5 authentication text SECRETVALUE1", "vrrp 5 authentication text"),
    ("snmp-server community SECRETVALUE1 RO MGMT-ONLY", "RO MGMT-ONLY"),
    ("username admin privilege 15 secret 9 SECRETVALUE1", "secret 9"),
    ("ip ospf message-digest-key 1 md5 7 SECRETVALUE1", "md5 7"),
    ("neighbor 192.0.2.1 password 7 SECRETVALUE1", "password 7"),
    ("key-string 7 SECRETVALUE1", "key-string 7"),
    ("set password ENC SECRETVALUE1", "set password ENC"),
    ("crypto isakmp key SECRETVALUE1 address 0.0.0.0", "address 0.0.0.0"),
])
def test_secret_values_are_hidden(line, kept):
    out = mask(line)
    assert "SECRETVALUE1" not in out and "<hidden>" in out and kept in out


@pytest.mark.parametrize("line", ["standby 10 authentication md5 key-chain HSRP-KEYS",
                                  "ip ospf authentication key-chain OSPF-KEYS"])
def test_key_chain_names_are_kept(line):
    assert mask(line) == line


# Corpus: every line holds one or more distinctive fake secrets (Sx...); none may survive.
CORPUS = [
    "ntp authentication-key 1 hmac-sha2-256 Sx1ntpSha 7",
    "ntp authentication-key 2 md5 Sx2ntpMd5 7",
    "ntp authentication-key 3 cmac-aes-128 Sx3ntpCmac",
    "snmp-server user ops OPS v3 auth sha Sx4authKey priv aes 128 Sx5privKey",
    "snmp-server user ops OPS v3 auth sha256 Sx6authKey priv aes 256 Sx7privKey access 99",
    "snmp-server user ops OPS v3 encrypted auth md5 Sx8authKey priv des Sx9privKey",
    "snmp-server user old OLD remote 192.0.2.9 v3 auth md5 Sx10authKey",
    " pre-shared-key Sx11psk",
    " pre-shared-key local Sx12pskLocal",
    " pre-shared-key remote 6 Sx13pskRemote",
    " pre-shared-key address 192.0.2.1 key Sx14pskAddr",
    " server-key 7 Sx15serverKey",
    " server-key Sx16serverKey",
    " key 7 Sx17tacKey",
    " key Sx18radKey",
    "tacacs-server key 7 Sx19tacLegacy",
    "radius-server key Sx20radLegacy",
    "tacacs-server host 192.0.2.5 key Sx21tacHost",
    " wpa-psk ascii 0 Sx22wpa",
    " wpa-psk hex 7 Sx23wpaHex",
    "snmp-server host 192.0.2.7 traps version 2c Sx24comm",
    "snmp-server host 192.0.2.7 informs version 2c Sx25comm udp-port 162 config",
    "snmp-server host 192.0.2.7 version 1 Sx26comm",
    "snmp-server host 192.0.2.7 Sx27comm",
    "snmp-server host 192.0.2.7 vrf MGMT traps version 2c Sx28comm",
    "    set passphrase ENC Sx29pass",
    "    set auth-pwd ENC Sx30authPwd",
    "    set secondary-secret ENC Sx31sec",
    "    set ldap-password ENC Sx32ldap",
    '    set private-key "Sx33privKeyBlob"',
    "    set psksecret ENC Sx34psk",
    "    set password ENC Sx35pw",
    "    set auth-password-l1 ENC Sx36l1",
    "    set secret ENC Sx37radius",
    "enable secret 9 Sx38enable",
    "enable password Sx39enablePw",
    "enable password 7 Sx40enable7",
    "username u1 privilege 15 password 0 Sx41user",
    "username u2 password Sx42userClear",
    "username u3 algorithm-type scrypt secret Sx43scrypt",
    " password 7 Sx44line",
    " password Sx45lineClear",
    "snmp-server community Sx46comm RW",
    "crypto isakmp key 6 Sx47ike address 0.0.0.0 0.0.0.0",
    " ip ospf authentication-key 7 Sx48ospf",
    " ip ospf message-digest-key 1 md5 Sx49ospfMd5",
    " neighbor 192.0.2.1 password Sx50bgp",
    " standby authentication Sx51hsrp",
    " glbp 4 authentication text Sx52glbp",
    " vrrp 2 authentication md5 key-string Sx53vrrp",
    "key config-key password-encrypt Sx54master",
    " authentication-key 0 Sx55eigrp",
]


@pytest.mark.parametrize("line", CORPUS)
def test_corpus_secrets_are_hidden(line):
    out = mask(line)
    leaked = [t for t in line.replace('"', " ").split() if t.startswith("Sx") and t in out]
    assert not leaked, out
    assert "<hidden>" in out


@pytest.mark.parametrize("line", [
    "key chain OSPF-KEYS", " key 1", " cryptographic-algorithm hmac-sha-256",
    " ip authentication key-chain eigrp 10 EIGRP-KEYS", " neighbor 192.0.2.1 ao BGP-AO",
    "snmp-server group OPS v3 priv", "ntp trusted-key 1", "crypto key generate rsa modulus 2048",
])
def test_names_and_non_secrets_are_kept(line):
    assert mask(line) == line


def test_detail_is_masked_but_prose_is_kept():
    r = result("X", "fail", "line vty 0 4: password 7 Sx60detail; VTP mode server with no password on a switch",
               ["password 7 Sx61evidence"])
    assert "Sx60detail" not in r["detail"] and "Sx61evidence" not in r["evidence"][0]
    assert "no password on a switch" in r["detail"]
    r = result("X", "fail", "enable secret type 5 (MD5); community 1: default/guessable name, no ACL")
    assert r["detail"] == "enable secret type 5 (MD5); community 1: default/guessable name, no ACL"
