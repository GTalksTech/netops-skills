# Handoff: network-security-check

For the next session working on this skill. Written 2026-11-13 at the end of the cloud session
that built it. Delete this file before the branch merges.

## Where things stand

- **Branch:** `claude/affectionate-volta-27wctx`, pushed. 6 commits on top of main `74c42a8`
  (network-ops 0.2.0, health-check v2). Not merged, not published. Garrett reviews first.
- **Skill:** `plugins/network-ops/skills/network-security-check/`. Read-only security check that
  works from files only: network-snapshot output, a local advisory cache, firewall event exports.
- **Read first:** `docs/security-skill-architecture.md`, then the skill's `SKILL.md`,
  `SCORING.md`, `research/sources.md` and `research/review-log.md` (rounds 1 to 3).
- **Tests:** 81 in `network-security-check/tests`, all offline, all passing. Snapshot and push
  suites (28) also pass. Needs Python 3.9+, pyyaml (plus netmiko and keyring for the other suites).

## What it does

- **CVEs:** vendor CVE records from CVE.org (Palo Alto's own JSON for PAN-OS), NVD to find CVE IDs,
  CISA KEV, FIRST EPSS. Checks whether the affected feature is on an internet-facing interface.
  Per-device upgrade plan at the top of the report.
- **Config:** 38 checks, each sourced (STIG rule IDs, CISA, NIST, NSA, vendor docs).
- **Events:** PAN-OS threat CSV, FortiGate IPS log, Suricata eve.json, FMC-style CSV. Attacks on a
  CVE you're vulnerable to, critical hits not blocked, spikes per signature or source.
- **Score:** CISA BOD 26-04 Table 1 (exposed, known exploited, automatable, total control) gives a
  deadline and a non-overlapping 0-100 band. Nine written house rules in SCORING.md.

## Vendor coverage

| Vendor | CVE matching | Config checks |
|---|---|---|
| Cisco IOS-XE | yes | 9, untested on real gear |
| FortiOS | yes | 9, untested on real gear |
| PAN-OS | yes | 7, untested |
| Cisco ASA | yes | 6, untested |
| Junos | yes | 3 management checks, untested; no SRX policy checks |
| NX-OS, EOS, AOS-CX, Dell OS10, Extreme EXOS, ArubaOS-Switch | yes | none |
| Huawei VRP, Nokia SR OS | version only, PSIRT link (their CVE records are free text) | none |

## Next job: test on lab v2 (the reason for this handoff)

The cloud session could not reach the lab, so nothing has run against real devices. Run this on a
machine that can reach lab v2, in a local clone (not a Google Drive folder):

```
git clone -b claude/affectionate-volta-27wctx https://github.com/GTalksTech/netops-skills.git ~/code/netops-skills
```

1. Run all three test suites. All must pass.
2. Take a fresh network-snapshot of lab v2, then `seccheck.py fetch` and `seccheck.py run`.
3. Review every finding against the real configs as a senior network and security engineer:
   correct, false positive, or missed. Watch for:
   - What counts as internet-facing. isp-rtr-01 plays the internet; hq-edge-rtr-01 and fw-01
     should come out as edge.
   - IOS-XE 17.16 version strings (IOL image) and the version regex.
   - FortiOS 8.0.1: the FortiOS parser and the FortiGate fixtures were written against 7.x docs.
   - The IoT / segmentation check against the real lab VLANs.
   - Known lab exceptions in `lab-workspace/AGENTS.md` (SNMP v2c, no routing auth, public lab
     passwords) will show up as findings. That is correct behavior: report them, don't "fix" them.
4. Fix parsers and checks. Add sanitized real lab output as fixtures with a test per fix. When
   IOS-XE and FortiOS pass on real devices, mark them `tested` in `settings/platforms.yaml` and
   SKILL.md, the way network-snapshot does.
5. If Garrett exports a FortiGate IPS log, run the event analysis on it.
6. Log it as round 4 in `research/review-log.md`.

## Rules (from Garrett)

- Read-only on the network: read-only account, show commands, devices from the inventory only.
- Never ask for, print or write a password. Lab creds admin/cisco123 are fine in examples.
- Don't merge to main or publish. Commit to the branch and push.
- Touch only this skill's folder plus clearly shared files (READMEs, docs). Another session may be
  working on network-health-check.
- Writing: no em dashes, no hype words ("game changer", "unlock", "next level"), plain and
  direct. Short reports. Keep each skill's description short (the skill listing is capped).
- Every check and score weight needs a source in `research/sources.md`. Tier 3 sources never
  stand alone.

## Waiting on Garrett

1. **Decision: scoring basis.** BOD 26-04 (US government, freely reusable) is what's built. The
   alternative, CERT/CC SSVC's deployer table, is CC BY-NC, a poor fit for a public MIT repo used
   by a business. Confirm BOD 26-04 is the method to teach on the channel.
2. **Decision: firewalls whose interfaces can't be parsed.** Built: assumed internet-facing
   (conservative, matches BOD 26-04 "if one method finds it exposed, yes"). Alternative: assume
   internal and flag it.
3. **Optional lab additions** for the untested adapters, in order of value: Cisco ASAv (a CML
   reference platform), Palo Alto VM-Series (eval), Juniper vSRX or vJunos, Arista cEOS
   (containerlab, free).
4. **Plugin version bump** (`plugin.json`, marketplace description) was left alone to avoid
   colliding with the health-check session. Garrett's call at merge time.

## Known gaps (not bugs, not done yet)

- ASA twice NAT not parsed. PAN-OS rules with negate-source/destination skipped. PAN-OS
  set/json/xml output formats not parsed (a note says so). Junos EVO versions sort slightly wrong.
- IOS vty with no `transport input` line: note only, because the default depends on the release.
- No end-of-support check yet (CISA BOD 26-02 covers end-of-support edge devices; needs vendor
  lifecycle data).
- Firewall rule shadowing and hit-count based "unused rule" checks not done (need runtime data).
- Not covered: Check Point (needs the Management API or its official MCP as a collector),
  SonicWall, Sophos, pfSense/OPNsense configs, WatchGuard, Meraki, FTD/FMC.
- The architecture doc lists which of these can run as separate sessions.
