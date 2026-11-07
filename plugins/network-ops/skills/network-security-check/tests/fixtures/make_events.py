# Builds the event fixtures in tests/fixtures/events/ with a fixed seed, so the files are
# reproducible. Field names follow each vendor's documented log format:
#   PAN-OS threat log CSV export (Monitor > Logs > Threat > Export to CSV)
#   FortiGate IPS log (type=utm subtype=ips), FortiOS Log Message Reference
#   Suricata eve.json alert records (as OPNsense and pfSense Suricata write them)
# Addresses: RFC 5737 for internet hosts, RFC 1918 inside. Signature names are made up except
# the Palo Alto threat ID 95187, which Palo Alto's CVE-2024-3400 advisory lists.
import csv
import datetime as dt
import json
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent / "events"
rnd = random.Random(20261107)
T0 = dt.datetime(2026, 11, 5, 0, 0, 0)


def pan():
    rows = []
    background = [("HTTP Directory Traversal Request Attempt(30844)", "30844", "medium"),
                  ("SIPVicious Scanner Detection(32760)", "32760", "low"),
                  ("Microsoft Windows SMB Probe(31914)", "31914", "informational")]
    for h in range(36):
        for _ in range(rnd.randint(4, 9)):
            name, tid, sev = rnd.choice(background)
            rows.append((T0 + dt.timedelta(hours=h, minutes=rnd.randint(0, 59)), name, tid, sev,
                         f"192.0.2.{rnd.randint(10, 200)}", "203.0.113.21", "reset-both"))
    # hour 30: GlobalProtect exploit attempts against pa-fw-01's untrust IP. Some only alerted.
    for i in range(140):
        rows.append((T0 + dt.timedelta(hours=30, minutes=rnd.randint(0, 59)),
                     "Palo Alto Networks GlobalProtect OS Command Injection Vulnerability(95187)", "95187",
                     "critical", rnd.choice(["198.51.100.66", "198.51.100.67"]), "203.0.113.20",
                     "alert" if i % 7 == 0 else "reset-both"))
    # hour 33: one scanner working through many signatures
    for i in range(60):
        name, tid, sev = background[i % 3]
        rows.append((T0 + dt.timedelta(hours=33, minutes=i % 60), f"{name.split('(')[0]} Variant {i % 15}({40000 + i % 15})",
                     str(40000 + i % 15), "high" if i % 15 == 0 else sev, "198.51.100.99", "203.0.113.21",
                     "reset-both"))
    rows.sort()
    with open(OUT / "pan-threat.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Receive Time", "Type", "Threat/Content Type", "Source address", "Destination address",
                    "Rule", "Source Zone", "Destination Zone", "Threat/Content Name", "Threat ID",
                    "Severity", "Action", "Repeat Count"])
        for t, name, tid, sev, src, dst, act in rows:
            w.writerow([t.strftime("%Y/%m/%d %H:%M:%S"), "THREAT", "vulnerability", src, dst,
                        "Inbound DMZ", "untrust", "dmz", name, tid, sev, act, 1])


def forti():
    lines = []
    for h in range(24):
        for _ in range(rnd.randint(1, 3)):
            t = T0 + dt.timedelta(hours=h, minutes=rnd.randint(0, 59))
            lines.append((t, "Web.Server.Password.Files.Access", "12345", "medium", "dropped",
                          f"192.0.2.{rnd.randint(10, 200)}", "10.20.20.80"))
    for i in range(12):
        t = T0 + dt.timedelta(hours=14, minutes=i * 4)
        lines.append((t, "MS.Windows.RDP.Remote.Code.Execution", "54321", "critical", "detected",
                      "198.51.100.40", "10.20.20.15"))
    lines.sort()
    with open(OUT / "fortigate-ips.log", "w", encoding="utf-8") as f:
        for t, attack, aid, sev, act, src, dst in lines:
            f.write(f'date={t:%Y-%m-%d} time={t:%H:%M:%S} devname="fw-01" devid="FGT60FTK00000000" '
                    f'logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" '
                    f'vd="root" severity="{sev}" srcip={src} srcport={rnd.randint(1025, 65000)} '
                    f'srcintf="wan1" dstip={dst} dstport=3389 dstintf="internal" policyid=2 '
                    f'sessionid={rnd.randint(1, 9999999)} action="{act}" proto=6 service="RDP" '
                    f'attack="{attack}" attackid={aid} profile="default" ref="http://www.fortinet.com/ids/VID{aid}" '
                    f'msg="applications3: {attack}," crscore=50 craction=4096 crlevel="{sev}"\n')


def suricata():
    with open(OUT / "eve.json", "w", encoding="utf-8") as f:
        for i in range(9):
            t = T0 + dt.timedelta(hours=20, minutes=i * 5)
            rec = {"timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000000+0000"), "event_type": "alert",
                   "src_ip": "192.0.2.77", "src_port": 51000 + i, "dest_ip": "203.0.113.2", "dest_port": 443,
                   "proto": "TCP",
                   "alert": {"action": "allowed", "gid": 1, "signature_id": 2049000, "rev": 1,
                             "signature": "LAB Cisco IOS XE Web UI implant check (CVE-2023-20198)",
                             "category": "Attempted Administrator Privilege Gain", "severity": 1}}
            f.write(json.dumps(rec) + "\n")
        f.write(json.dumps({"timestamp": "2026-11-05T21:00:00.000000+0000", "event_type": "flow",
                            "src_ip": "10.0.0.5", "dest_ip": "10.0.0.6"}) + "\n")


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    pan()
    forti()
    suricata()
    print("written to", OUT)
