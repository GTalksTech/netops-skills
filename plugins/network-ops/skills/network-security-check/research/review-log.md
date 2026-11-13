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
  an ACL and passwords are type 9 hashes, so nothing to flag; there is no routing-protocol
  authentication check in the catalog yet (a gap, needs a source).
- The seven "Security Hardening Release" CVEs (CVE-2026-20267 to 20273) name no feature, so
  they stay version-matched. Check Cisco's advisory for conditions before changing that.
- A BEEP listener made with the exec command `bingd device` isn't in the config.
- isp-rtr-01 could carry `exposure: internal` in the lab inventory so the ISP stand-in doesn't
  add to the counts. Left for Garrett.
