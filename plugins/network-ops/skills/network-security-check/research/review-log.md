# Review log

Each round: the output read as a demanding senior network and security engineer would read
it, what was wrong, what changed. Tests pin each fix.

## Round 1: first full run on the fixtures

Wrong or noisy:
- CVE titles were the first 120 characters of the description ("Cisco is providing an update
  for the ongoing investigation...").
- The normal outbound "LAN to internet, all/all/ALL" rule on the FortiGate was flagged as
  any-any. Every small-business firewall has one. The FortiGate STIG rule this check follows
  is about interface "any".
- IoT rules were reported twice, as any-any and as a segmentation finding.
- ASA flagged the inside `permit ip any any`, the usual outbound default, instead of looking
  for any-any on the outside.
- SNMP detail merged two communities into one unreadable line.
- Smart Install "verify" note showed on a router (Smart Install is a switch feature).
- Config findings marked known-exploited got "3 days + forensic triage" even on internal
  devices. A misconfiguration is not evidence of compromise.
- One GlobalProtect attack produced four findings (target, not blocked, two spikes), and the
  spike was split across two hour buckets because buckets started at the first event's minute.
- Internal feature names (`http_server`) in the report text.

Missing:
- Stale IPS signatures. The fixture FortiGate's IPS-DB was two years old, the classic expired
  FortiGuard license.

Changed: outbound default rules skipped; segmentation finding replaces any-any; ASA any-any
only on internet-facing or global ACLs; per-community SNMP detail; switch-only Smart Install
note; config findings capped at 3 days and exploitation evidence needs exposure (house rules
4 and 5); clock-aligned buckets, back-to-back spike hours merged, one finding per campaign;
KEV names as titles; readable feature labels; new check FGT-IPS-STALE.

Also found while testing: Palo Alto version data. CVE.org's copy of CVE-2024-3400 flags the
fixed 10.2.7-h8 as affected, and Palo Alto's own list leaves out the affected 10.2.8. Now read
per maintenance release (research/sources.md, `panw-json`).

## Round 2: full advisory fetch (1313 real CVE records, IOS-XE and FortiOS)

Wrong or noisy:
- DHCP snooping DoS (CVE-2025-20162) scored "fix in 3 days" on the edge router just because
  the router has a public IP. The router doesn't run DHCP snooping.
- SD-WAN-only CVE (CVE-2025-20221) hit every IOS-XE device, and with the feature off it was
  still capped at 14 days.
- SNMP feature was only detected when the community was weak, so the SNMP RCE (CVE-2025-20352)
  on switches with an ACL'd community fell back to generic exposure.
- 84 CVEs on one router as a flat list. Nobody reads that. The real action is per device: one
  upgrade clears them all.

Changed: CVSS attack vector Adjacent/Local/Physical = not publicly exposed; feature-off CVEs go
to "next upgrade" with the reason shown; features added (SNMP, SD-WAN, DHCP snooping, IOx, IKE,
FortiManager fgfm); per-device upgrade plan at the top of the report; full detail only for 3
and 14 day CVEs.

Also checked: full fetch for two vendors takes about 80 seconds without an NVD key.

## Round 3: independent review of parsers and matching

A separate reviewer (no access to my reasoning) probed the parsers with real config variants
and broken input. Confirmed and fixed:

- **Critical:** FortiOS multi-VDOM (`config global`) lost every interface, so exposed
  management, VIPs and inbound rules disappeared. Fixed, and pinned with a wrapped copy of the
  fixture.
- **Critical:** a config the parser couldn't read made CVE features look "off", which pushed KEV
  CVEs to "next upgrade". Features are now unknown when no interfaces were parsed.
- **Critical:** Junos `apply-groups` ignored (telnet and untrust services hidden). Expanded now.
- False positives fixed: banner text read as config; public IP in the IOS management VRF or
  on an ASA management-only interface counted as internet-facing; `line vty ... transport
  input none` flagged for no ACL; `logging host <hostname>` not seen; ASA single jump host
  treated like 0.0.0.0/0; inactive ACEs; FortiOS profile groups read as "no IPS"; all-ports
  static NAT flagged when the outside ACL or security policy restricts it.
- False negatives fixed: IOS WAN on DHCP (`ip nat outside`) now internet-facing; ACL with an
  early deny to one host still counts as open; ASA `any6`, `nat (inside,any)`, two-field
  `ssh ::/0 outside`; FortiOS `srcintf any` treated as inbound and VIP groups resolved;
  PAN-OS pre/post-rulebase read (Panorama).
- Version compare: EOS four-part builds (4.31.1.1F vs 4.31.1F), 7.6 = 7.6.0, Junos `21.4*`
  train bounds.
- Scoring vs doc: event "total control" now follows the tied CVE; IPS age is measured from the
  snapshot date.
- Crashes: truncated PAN config, missing device_type, cache index without a fetch time, corrupt
  cache record, bad IPS date. Each now becomes a note on that device instead of stopping the run.

Known gaps left (listed for the next round):
- ASA twice NAT (`nat (...) source static ...`) is not parsed.
- PAN-OS rules with negate-source/destination are skipped, not analysed.
- PAN-OS set/json/xml output formats aren't parsed (a note says so).
- IOS vty with no `transport input` line gives a note, not a finding, because the default
  depends on the release.
- Junos EVO version strings (`-EVO`) sort above the plain release.

## Round 4: first run on real devices (lab v2, 2026-11-13)

Ran on a machine that reaches lab v2: network-snapshot of all 12 devices (11 IOL IOS-XE
17.16.1a, one FortiGate-VM 8.0.1), then `fetch` (1,022 Cisco and 299 FortiOS candidate CVEs)
and `run`. First run: 54 findings (3 at 3 days, 15 at 14 days). Each finding checked by hand
against the saved configs.

Correct on the first run:
- Version strings parse on both: IOL reports "Cisco IOS Software [IOSXE], Linux Software ...
  Version 17.16.1a"; FortiOS "FortiGate-VM64 v8.0.1,build0245".
- Edge detection: hq-edge-rtr-01, branch1-rtr-01 and fw-01 port2 (role wan) internet-facing,
  switches internal. isp-rtr-01 also shows as edge; it plays the internet in the lab.
- FGT-IPS-STALE: IPS-DB from 2015 because the eval VM has no FortiGuard license. A known lab
  condition, reported correctly.
- CVE-2025-20352 (SNMP, KEV) held at 14 days: SNMP is on but bound to ACL MGMT-ONLY.
- IOS-NO-REMOTE-LOG only on isp-rtr-01, the one device with no `logging host`.
- Quiet, correctly: telnet, VTY ACL, password storage (all type 9), web UI, FortiGate
  management on WAN. Segmentation found nothing because lab v2 has no IoT or guest VLAN, so
  that check is still covered by fixtures only.

Fixed (fixtures in tests/fixtures/lab-v2, sanitized; tests named test_lab_*):
- **False positive on all 11 Cisco devices:** IOS-SSH-V1. 17.x runs SSH v2 only and writes no
  `ip ssh version 2` line. The check now also reads the saved `show ip ssh` ("version 2.0").
- **False positives on CVE exposure:** CVEs whose feature is off still scored as reachable,
  because the CVE text names the feature in words the matcher didn't know. Added, each with
  the config condition from Cisco's advisory (sources.md, cisco-sa-feature-conditions):
  "web services" (Remote Access SSL VPN), "HTTP API" (HTTP server), Web Authentication, NBAR
  CAPWAP, BEEP, XMCP, Meraki. Seven CVEs on the edge routers moved from 14 days to next upgrade.
- **Overstated firewall finding:** FGT-INBOUND-ANY-SERVICE (86) and FGT-INBOUND-NO-IPS (70) on
  a WAN-side policy whose source is a named group of private and /30 subnets (branch LAN,
  loopbacks, tunnel, transit). Sources are now resolved through address objects and groups:
  when every source is private or no wider than a /24 the finding says "from the WAN side,
  limited to ..." and is not marked internet-exposed (now 52 and 47).
- **Silent gap:** a FortiOS read-only profile sees only its own entry under `config system
  admin`, so the other admins' trusted hosts were never checked and the report didn't say so.
  It now adds a note.

After the fixes: 43 findings (2 at 3 days, 9 at 14 days). IOS-XE and FortiOS marked `tested`.

Not changed, for the next round:
- The handoff expected SNMP v2c, no routing auth and public lab passwords to show up. SNMP has
  an ACL and passwords are type 9 hashes, so nothing to flag. Routing auth had no check; added
  below as round 4b.
- The seven "Security Hardening Release" CVEs (CVE-2026-20267 to 20273) name no feature, so
  they stay version-matched. Check Cisco's advisory for conditions before changing that.
- A BEEP listener made with the exec command `bingd device` isn't in the config.
- isp-rtr-01 could carry `exposure: internal` in the lab inventory so the ISP stand-in doesn't
  add to the counts. Left for Garrett.

## Round 4b: routing protocol authentication (2026-11-13)

New check IOS-ROUTING-NO-AUTH, sourced to DISA CISC-RT-000050 (V-216645) and Cisco's "Harden
IOS Devices" guide. Finds OSPF and EIGRP interfaces that form adjacencies without
authentication (interface or area auth for OSPF, classic or named mode for EIGRP; loopbacks
and passive interfaces skipped) and BGP neighbors with no `password` or `ao`, on the neighbor or
its peer-group.

Exposure: OSPF and EIGRP use link-local packets, so only a device on the link can inject routes:
never internet-exposed. BGP to a public neighbor address is. Not known exploited, not
automatable, partial impact, so it scores low: 60 days for the eBGP routers, next upgrade for
internal OSPF.

Lab v2 result, checked by hand against every router config: hq-edge-rtr-01 (OSPF on Tunnel0
and the fw-01 transit, eBGP to isp-rtr-01), isp-rtr-01 (eBGP), hq-core-sw-01 (three p2p
links), both distribution switches and branch1-rtr-01 (the one non-passive interface each).
Access switches run no routing and are clean. 49 findings in total after this check.

Not graded in 4b: MD5 vs HMAC-SHA and key lifetimes (MD5 added in 4c). OSPFv3, IS-IS and RIP
are not read.

## Round 4c: MD5 vs HMAC-SHA grading (2026-11-13)

Each adjacency is now graded by how it authenticates. Clear-text keys (OSPF `ip ospf
authentication` or `area X authentication` without message-digest) join IOS-ROUTING-NO-AUTH,
because anyone on the link can read the key. New IOS-ROUTING-WEAK-AUTH (DISA CISC-RT-000050:
MD5 is not FIPS 198-1) covers OSPF message-digest, EIGRP md5 (classic and named mode), BGP
`neighbor X password` (TCP MD5), and key chains whose cryptographic-algorithm is md5 or not set.
HMAC-SHA-1/256/384/512 and AES-CMAC key chains, EIGRP named-mode hmac-sha-256 and BGP TCP-AO
with such a chain pass.

Scores lower than no authentication (weight 0.2, same exposure rule: only a public BGP neighbor
is exposed). Cisco's hardening guide still shows MD5 as the recommended form; the STIG is the
stricter bar and the one followed here.

Lab v2 has no routing authentication at all, so this check doesn't fire there; it is covered by
tests of every form. Key lifetimes (STIG: 180 days or less) are still not graded.

## Round 5 (R1): result model, accepted risk, catalog fields (2026-11-13)

Every config check now returns a result per device: pass, fail, n/a or not-visible, with
`check`, `status`, `detail`, `evidence`, `exposed`, `where` (`common.result()`). Evidence lines
go through `common.mask()`, which hides the value after community, secret, password, key-string,
ENC and similar keywords. Fails are still the scored findings; nothing about scoring changed.
The JSON report carries `devices[].results`, `devices[].result_counts` and a total
`result_counts`; the markdown has one count line and a "Not visible" list. IOS and FortiOS
checks report each status explicitly. PAN-OS, ASA and Junos still only look for failures, so
their passes mean "searched, found nothing" (`common.fill_passes`). A config that parses to no
interfaces turns every non-fail result into not-visible. Routing authentication moved to
`scripts/ios_routing.py`; `vendor_ios._routing_auth` is still importable.

checks.yaml gained `plane`, `validated`, `controls` (NIST SP 800-53r5) and `zt_pillar` (CISA
ZTMM v2) on all 40 checks; check-settings requires plane and validated and checks the formats.
Marked fixture although IOS/FGT: IOS-ROUTING-WEAK-AUTH, IOS-SEGMENT-ROUTED, FGT-SEGMENT and
FGT-VIP-RISKY (lab v2 has no auth, no segmented VLAN and no VIP, so they never ran on a real
object).

Accepted risk: optional `exceptions.yaml` next to inventory.yaml (format in
exceptions.example.yaml). A matching config finding moves to `accepted_risk` and an "Accepted
risk" section with reason and expiry, out of the deadline counts. Expired, malformed and
unused waivers each produce a note. CVE and event findings are not waivable. Basis: 800-53
CA-5 and RA-7.

Config and event findings in the lowest band now read "Fix in the next maintenance window".

Lab v2 run after the change: 49 findings, 2 / 9 / 6 / 32 (3d / 14d / 60d / lowest band), same
IDs, devices and scores as before (only the FGT-IPS-STALE detail gained "when the snapshot was
taken"). Results: 79 pass, 10 fail, 40 n/a, 1 not-visible (fw-01 FGT-ADMIN-NO-TRUSTHOST: the
read-only profile sees only its own admin entry). Smart Install is n/a on the lab switches
because IOL L2 models don't match the Catalyst model pattern; on a real Catalyst with no
`no vstack` line it is not-visible. 120 tests.

## Round 6 (R2+R3): IOS-XE management plane, NTP, syslog depth, SNMP version (2026-11-13)

Ten new IOS checks in `scripts/ios_mgmt.py`, called from `vendor_ios.analyze`. Each reports
pass, fail or n/a with masked evidence. Sources are DISA IOS XE Router NDM STIG V3R7 rules,
Cisco Doc 13608, RFC 8633 and CISA's communications hardening guidance (rows in sources.md).

| Check | Fails when | Absent line |
|---|---|---|
| IOS-EXEC-TIMEOUT | con or vty idle timeout over 5 min, or 0 0 / no exec-timeout | default 10 min (Cisco 13608), over the STIG value: fails |
| IOS-LOGIN-BLOCK | no `login block-for`, or more than 3 attempts | no lockout by default |
| IOS-AAA-CENTRAL | vty login list has no server group first, no aaa new-model, or fewer than two TACACS+/RADIUS servers | aaa new-model with no default list = local users only |
| IOS-LOGIN-NONE | a con or vty list is or falls back to `none`, or `no login` | without aaa new-model the console has no login |
| IOS-AAA-ACCOUNTING | no `aaa accounting commands` to a group and no `archive / log config / logging enable` | nothing recorded by default |
| IOS-BANNER | no `banner login` or `banner motd` | no banner |
| IOS-NTP-AUTH | no `ntp authenticate`, no trusted key, or a server without a trusted, defined key | n/a with no NTP server |
| IOS-NTP-REDUNDANT | fewer than two `ntp server`/`peer` lines (zero included) | no NTP by default |
| IOS-LOG-DEPTH | one syslog host, `no logging trap`, or trap emergencies/alerts | trap default informational passes; n/a with no host (IOS-NO-REMOTE-LOG) |
| IOS-SNMP-V2C | any v1/v2c community (ACL or not), v1/v2c trap host, or v3 group without priv | n/a with no SNMP |

All are known_exploited false, automatable false. Only IOS-LOGIN-NONE is total control
(weight 0.5); it becomes exposed (14 days) when a vty without an access-class has no
authentication on an internet-facing device. The rest sit in the maintenance-window band,
weights 0.05 (banner) to 0.25 (lockout).

Dropped: IOS-VTY-RANGES. IOS-VTY-ACL and IOS-TELNET already judge every vty range on its own,
and the new timeout and login checks do too, so a `line vty 5 15` missing what `0 4` has is
already a finding under the right check. Not checked: `logging source-interface` (no STIG
rule found), `ip http timeout-policy` (the web UI has its own check), aux lines (not in the
STIG check text; most platforms have no aux modem), local-account count and method order
(CISC-ND-000490).

Lab v2 run, read by hand against every running config: all 11 IOS devices (hq-edge-rtr-01,
hq-core-sw-01, hq-dist-sw-01/02, hq-acc-sw-01..04, branch1-rtr-01, branch1-sw-01, isp-rtr-01)
fail all ten, except isp-rtr-01 where IOS-LOG-DEPTH is n/a (no syslog host; IOS-NO-REMOTE-LOG
already fails). Configs confirm: `line con 0` has `exec-timeout 0 0`, `privilege level 15` and
`login authentication CONSOLE` with `aaa authentication login CONSOLE none`; vty 0 4 has
`exec-timeout 30 0` and the default list `local`; no login block-for, archive, accounting,
banner, TACACS/RADIUS, NTP auth or SNMPv3; one `ntp server` and one `logging host`; one v2c
community with an ACL (known lab exception, correctly reported). 109 new findings, all in the
maintenance-window band; the 49 earlier findings keep their IDs, devices and scores. Results:
79 pass, 119 fail, 41 n/a, 1 not-visible.

The clean-switch fixture (snapshots/hq/hq-acc-sw-01) gained AAA, accounting, lockout, NTP auth,
a second syslog host, SNMPv3 and a banner so it stays clean. New tests in
tests/test_ios_mgmt.py; 152 tests in the suite.

## Round 7 (R4+R5): control plane, edge anti-spoofing, eBGP hygiene (2026-11-13)

Nine new IOS checks: four in `scripts/ios_cp.py` (control plane) and five in
`scripts/ios_edge.py` (anti-spoofing and eBGP), both called from `vendor_ios.analyze`. Sources
are DISA IOS XE Router RTR STIG V3R5 rules, RFC 6192, 2827, 3704, 8704, 7454, 8212 and 5082,
Cisco Doc 13608 and the IOS XE 17 IP services guide (rows in sources.md). ACL entry reading moved
to `parsers.ios_acl_lines`, shared by `vendor_ios._acl_is_open` and the anti-spoofing check.

"External interface" here means internet-facing (public IP or NAT outside, not management VRF,
not shut), not a loopback or Null, and not forming an OSPF or EIGRP adjacency. An IGP link talks
to your own router: on hq-edge-rtr-01 that leaves out Ethernet0/1, the public transit to fw-01.

| Check | Fails when | Absent line | Exposed when |
|---|---|---|---|
| IOS-NO-COPP | no `service-policy input` under control-plane, or it names an undefined policy-map | no CoPP by default | device has an external interface; internal routers fail unexposed; no routing and no external interface = n/a |
| IOS-EDGE-IP-SERVICES | external interface without `no ip proxy-arp`, `no ip redirects`, `no ip unreachables` (or global `ip icmp rate-limit unreachable`), or with `ip directed-broadcast` | proxy ARP, redirects, unreachables ON | unreachables or directed broadcast on (reach beyond the link) |
| IOS-EDGE-CDP-LLDP | CDP on and no `no cdp enable`, or `lldp run` and no `no lldp transmit`, on an external interface | CDP read from show cdp neighbors, else assumed on; LLDP off unless `lldp run` | never (link-local) |
| IOS-LEGACY-SERVICES | any STIG CISC-ND-000470 service line (small servers, finger, identd, BOOTP/DNS server, rcmd, PAD, service config, boot network); `ip source-route`; or release before 17.1 without `no ip source-route` | present-line test; source routing off from IOS XE 17.1.1 | a listening service is on and an external interface has no inbound ACL or an open one |
| IOS-EDGE-NO-ANTISPOOF | external interface with no uRPF and no inbound ACL that denies 10/8, 172.16/12 and 192.168/16 as sources before any permit that could match them | no uRPF by default | always (external) |
| IOS-BGP-NO-POLICY | eBGP neighbor without an inbound or an outbound prefix-list, route-map, filter-list or distribute-list | RFC 8212 default in IOS XE not verified: missing = finding | public neighbor |
| IOS-BGP-MAX-PREFIX | eBGP neighbor without maximum-prefix | no limit by default | public neighbor |
| IOS-BGP-NO-GTSM | single-hop eBGP without `ttl-security hops`; multihop is n/a | no GTSM by default | public neighbor |
| IOS-BGP-INBOUND-PERMISSIVE | the inbound prefix-list of a public eBGP neighbor provably permits a bogon or (via ge/le) an IPv4 prefix longer than /24 | n/a with a route-map or no readable list | always (public neighbors only) |

eBGP neighbors are resolved through peer-groups (session and per-AF settings) and peer
templates (`inherit peer-session`, `inherit peer-policy`, with template-to-template
inheritance). Each neighbor is graded in every unicast AF it is active in (`no bgp default
ipv4-unicast` respected). iBGP and confederation peers are not graded.

All nine are known_exploited false, automatable false, partial impact: exposed ones land in the
60-day band, the rest in the maintenance window. Weights 0.1 (CDP/LLDP) to 0.5 (no policy).

Judgment calls:
- CoPP is a CAT I router rule, but on a switch with no routing protocol and no internet
  interface only the management network reaches the CPU, so it is n/a there.
- Proxy ARP, redirects, unreachables and directed broadcast are one check: one interface, one
  change. An edge ACL ending in `permit ip any any` is folded into IOS-EDGE-NO-ANTISPOOF (the
  fix is the same deny lines); with strict uRPF on the interface it passes.
- Loose uRPF (`reachable-via any`) is credited with a note (RFC 8704 3.7 recommends it on
  transit and peer links); `allow-default` is not credited.
- Exact one-prefix entries (`permit 198.51.100.4/30`) are not graded for length: a deliberate
  exception. Private-address eBGP (MPLS VPN and similar) is not graded for content. The
  documentation ranges are not treated as bogons, matching `common.is_public`.
- CDP: the STIG says CDP is not on by default on the router, but IOL IOS-XE 17.16.1a ran it with
  no `cdp run` line (show cdp neighbors listed peers on every router), so the saved show output
  decides and an absent file is "assumed on". The lab-v2 fixture gained show cdp/lldp output.

Not checked or not verified: global `ip arp proxy disable` (not in the sources; a config using
it would show a proxy-arp false positive), BOOTP server and PAD defaults on 17.x (present-line
only), IPv6 too-specific length, route-map contents, dynamic neighbors (`bgp listen range`),
the IP options ACL (CISC-RT-000350), ICMP mask reply, unused interfaces shut, own-AS prefix and
AS-path filtering, unique BGP keys per AS.

Lab v2 run, read by hand against each running config and its show cdp/lldp output: 19 new
findings, the 158 earlier ones unchanged (IDs, devices, scores). Totals: 177 = 3d 2, 14d 9,
60d 19, maintenance window 147.

| Device | New findings | By hand |
|---|---|---|
| hq-edge-rtr-01 | NO-COPP, EDGE-IP-SERVICES (Eth0/2), BGP-NO-GTSM, BGP-INBOUND-PERMISSIVE (60d); EDGE-CDP-LLDP (window) | `control-plane` empty; Eth0/2 has only the EDGE-IN access-group; CDP neighbor isp-rtr-01 on Eth0/2; no ttl-security; ISP-IN seq 15 `203.0.113.0/24 le 32`. Passes: EDGE-IN denies 10/8, 172.16/12, 192.168/16 first; ISP-IN in, HQ-OUT out; maximum-prefix 100 80 |
| isp-rtr-01 | NO-COPP, EDGE-IP-SERVICES, EDGE-NO-ANTISPOOF, BGP-NO-POLICY, BGP-MAX-PREFIX, BGP-NO-GTSM (60d); EDGE-CDP-LLDP (window) | neighbor 198.51.100.2 has only activate and default-originate; Eth0/1 and Eth0/2 have no ACL or uRPF; Loopback0 left out. INBOUND-PERMISSIVE n/a (no list) |
| branch1-rtr-01 | NO-COPP, EDGE-IP-SERVICES, EDGE-NO-ANTISPOOF (60d); EDGE-CDP-LLDP (window) | Eth0/1 (NAT outside, public) has no ACL or uRPF; CDP sees isp-rtr-01 there; no BGP (n/a) |
| hq-core-sw-01, hq-dist-sw-01/02 | NO-COPP (window) | run OSPF, `control-plane` empty, no policy-map |
| access switches, branch1-sw-01 | none | no routing, no internet interface: n/a |

IOS-LEGACY-SERVICES passes on all 11 (none of the lines present, version 17.16), so it stays
`validated: fixture`. 25 new tests in tests/test_ios_edge.py; 177 tests in the suite.

## Round 8 (R7): FortiOS hardening (2026-11-13)

Ten FortiGate checks in fgt_hardening.py, sourced to DISA FortiGate Firewall NDM STIG V1R6
(FGFW-ND-*) and Fortinet's 7.6 best practices and 8.0 CLI reference: admin lockout, admin
timeout, weak admin TLS / strong-crypto / SSHv1, cleartext admin protocols on internal
interfaces, admins without two-factor, password policy, no remote logging, WAN services without
a local-in policy, unused VIPs, stale AV definitions. FortiOS `show` omits defaults, so an absent
line is graded by the documented default (lockout 3 tries / 60 s, admintimeout 5, strong-crypto
on, TLS 1.2+).

fw-01 (real, 8.0.1), checked by hand: lockout fails (60 s default vs STIG 900 s), password
policy fails on length; timeout, TLS, cleartext and remote log pass; local-in, unused VIP and AV
age n/a; two-factor not-visible (read-only profile).

Open: 7.0-7.4 defaults unverified; FGT-AV-STALE rests on the same sources as FGT-IPS-STALE (house
rule 8 should name AV too); 8.0.1 prints `set status enable` for the password policy although
the 8.0.0 reference gives enable as default.

## Round 9 (R8): end of support (2026-11-13)

lifecycle.py and settings/lifecycle.yaml: per release train, end of maintenance, end of
vulnerability support and end of support, each read on the vendor page on 2026-11-13 (Cisco
IOS XE 17.9-17.18, PAN-OS 10.1-12.1, Junos 21.4-26.2, FortiOS 7.4 and 7.6 from a Fortinet staff
post citing CSB-260330-1, tier 2). LIFECYCLE-EOS (past end of security fixes) and LIFECYCLE-SOON
(within 12 months). House rule 10 in SCORING.md: CISA BOD 26-02 treats end-of-support edge
devices as a standing risk, so an internet-facing device past end of security fixes scores as
exposed, automatable, total impact (3 days); internal devices 60 days.

Lab v2: all 11 devices run 17.16.1a, whose security support ended 2026-01-13 (Cisco notice
re-read by the lead: migrate to 17.17.1 or later). hq-edge-rtr-01, branch1-rtr-01 and
isp-rtr-01 now lead the report at 3 days. fw-01 on 8.0.1 is n/a: Fortinet's lifecycle grid did
not load, so no 8.0 dates yet.

Merge of R4+R5, R7 and R8: 212 tests, 71 checks, lab 190 findings (3d 5, 14d 9, 60d 27,
lowest band 149).

## Round 10 (R9): report rebuild (2026-11-13)

scripts/report.py renders the report from the JSON, which stays the source of truth. New JSON
fields, nothing removed: `summary` (counts, all actions, `top_actions`), `posture` (device x
plane fail / pass counts with the worst open deadline per cell, plus a CVE column), `controls`
(NIST SP 800-53r5 control and CISA ZTMM pillar to failing and passing checks), `snapshot`
(commit and date of the snapshot repo, read with git log).

Markdown and a new self-contained HTML file (inline CSS, no scripts or external assets, light
and dark), in this order: scope and method, summary with top actions, posture grid, findings by
deadline grouped by check (one evidence line, why, fix, sources), accepted risk, what is good,
what the check could not see, control map.

Judgment calls:
- Top actions group by fix. One upgrade action per (platform, version) carries its CVEs and
  LIFECYCLE findings. Related config checks merge into themes (eBGP, edge interfaces, routing
  auth, inbound firewall policy, management baseline, NTP, logging, FortiGate admin baseline);
  layer 2 checks form one theme by plane. Ranked by deadline, then score, then exposure.
- The upgrade hint quotes the lifecycle.yaml note only when it names a recommended release
  ("Cisco recommends 17.17.1 or later"); otherwise "see the vendor advisory".
- CVEs that share title, devices and advisory print as one line (the Cisco hardening bundle:
  six CVEs, one advisory). The lowest band lists checks one line each and CVE IDs by version.
- "What is good" lists checks that passed on every device they apply to; partial passes stay
  in the findings.
- The markdown control map groups controls by family to stay short; the HTML has a row per
  control with the failing check IDs.

Lab v2 run with R6 merged, read end to end: 211 findings, unchanged by the rebuild; markdown 260
lines, HTML about 70 KB.
Top actions: upgrade IOS-XE 17.16.1a on all 11 devices (3 days), upgrade FortiOS 8.0.1 on
fw-01 (3 days), FortiGate IPS signatures (14 days), then inbound firewall policy, eBGP, edge
interfaces and routing auth (60 days). 15 tests in tests/test_report.py (sections and order,
grouping, device ranges, no fixture secrets in md or HTML, no external assets, HTML escaping of a
crafted finding, accepted risk); 254 in the suite.

Open: the fw-01 trusted-host note repeats the FGT-ADMIN-NO-TRUSTHOST not-visible line. The
markdown is a little over the 250-line aim since the layer 2 checks added a dozen lines.

## Round 11 (R6): layer 2 and first hop (2026-11-13)

Nine checks in ios_l2.py, sourced to DISA Cisco IOS XE Switch L2S STIG V3R2 (CISC-L2-*) and, for
HSRP/VRRP authentication (no STIG rule exists), Cisco's Harden IOS Devices guide: BPDU guard,
DHCP snooping, DAI, port security / 802.1X / MAB, unused ports, DTP, trunk native VLAN and
allowed list, VTP authentication, FHRP authentication. Saved show output (switchport, trunk,
vtp, standby) is the truth when present. Server/DMZ VLANs are skipped for snooping and DAI as
the STIG allows. L2 findings are never internet-exposed.

Lab v2, checked by hand by the builder: 21 new findings, all lowest band (DHCP snooping and DAI
on user VLANs, DTP on trunks, native VLAN 1, HSRP without authentication on both distribution
switches, port authentication). BPDU guard, VTP transparent and the PARKED VLAN pass.

Found on the way and fixed by the lead: common.mask() left HSRP `authentication text <key>` and
the value in `md5 key-string 7 <key>` visible. Fixed, with tests/test_mask.py. Lab scan of 326
evidence lines: no leaks.

Open: IP Source Guard (CISC-L2-000140) not implemented; network-snapshot should save
`show vtp password`; IOL support for snooping/DAI/port-security not confirmed on the device.
