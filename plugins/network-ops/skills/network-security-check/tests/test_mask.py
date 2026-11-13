# mask() must hide every secret value that can sit on an IOS or FortiOS config line, because
# evidence lines are quoted in reports.
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from common import mask  # noqa: E402

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
