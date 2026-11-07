# Security check: architecture recommendation

Question from Garrett: one security skill across route/switch and firewalls, or a separate
firewall skill? Firewall vendors increasingly ship their own AI and MCP servers, and each has
its own CLI and API.

Researched 2026-11-07. Sources are linked inline, and the per-check sources are in
`plugins/network-ops/skills/network-security-check/research/sources.md`.

## Recommendation

**One skill, `network-security-check`, that only analyzes files. Collection stays in
network-snapshot. Vendor differences live in small per-vendor adapters (a config parser plus
a settings entry). Vendor MCP servers are an optional way to collect data for the few vendors
that need an API. They are never part of the scoring, and they ship as separate plugins if we
ship them at all.**

Built that way on this branch.

```
network-snapshot (SSH, read-only account)  -->  ~/network-snapshots/<site>/<device>/*.txt
firewall event exports (CSV, syslog, JSON) -->  --events files
public advisory data (fetch step)          -->  ~/network-security/advisories/
                                                     |
                     network-security-check: parse -> check -> match CVEs -> score -> report
                     (no device access, works offline, same input = same output)
```

## Why not a separate firewall skill

1. **The findings that matter most cross device types.** An IoT VLAN that "routes freely" is
   usually an L3 switch SVI with no ACL, so the firewall never sees that traffic. You only
   catch it by reading the switch and the firewall together. Whether a router CVE is urgent
   depends on whether that router is the internet edge. A firewall-only skill would miss the
   first and misjudge the second.
2. **The engine is the same for both.** CVE matching, KEV/EPSS lookups, the BOD 26-04 scoring
   and the report don't change between a Catalyst and a FortiGate. Only parsing differs, and
   that is already per vendor inside one skill.
3. **The skill listing is capped.** Two skills with overlapping descriptions ("security
   check", "firewall audit") also make Claude guess which to load.
4. **Larry asks one question:** "what do I fix first on my network?" One report with one
   scale answers it. Two reports with two scales make him merge them.

What a split would buy: a firewall skill could go deeper on rule analysis (shadowed rules,
hit counts, object sprawl). That depth fits inside this skill as more checks per firewall
adapter. If firewall rule optimisation (not security) becomes its own job, that is a
different skill with a different question, and worth splitting then.

## Why not "prefer the vendor's MCP server"

- **Few vendors ship one.** Found official, 2026-11-07:
  - **Check Point**: `CheckPointSW/mcp-servers`, a family of servers for management, logs,
    threat prevention, HTTPS inspection and gateway CLI. The README describes them as query
    servers. Read-only status per package is not verified.
  - **Juniper**: `Juniper/junos-mcp-server`. It **can load and commit config**
    (`load_and_commit_config`, with a blocklist guardrail).
  - **Cisco**: the FMC MCP server is in the CiscoDevNet org but named "community"
    (`CiscoFMC-MCP-server-community`). The README says it runs without bearer auth.
  - **Palo Alto**: only the Prisma AIRS MCP server, which is for AI-agent security, not
    firewall config. No official PAN-OS/Panorama config MCP found.
  - **Fortinet**: no official FortiOS/FortiManager MCP found. Several community servers.
  - SonicWall, Sophos, WatchGuard, pfSense, OPNsense: no official server found. OPNsense and
    Sophos have community servers.
- **A security audit should not run next to a write-capable tool.** Junos MCP can commit config.
  A read-only scope then rests on the device account alone. Our rule is read-only by design, so
  the engine never calls a device at all.
- **MCP output can't be tested offline.** Tool names and shapes change between releases, and
  the result depends on the live device. Files in, report out can be pinned with fixtures,
  which is what the tests on this branch do.
- **Where MCP does help:** Check Point. Its rulebase lives on the management server, behind the
  Management API, not in a gateway CLI dump. For Check Point, the official MCP (or a small
  read-only API exporter) is the right collector. It writes the rulebase to the snapshot
  folder and the Check Point adapter parses that file. Collector and engine stay separate.

## Per firewall vendor: what a skill can rely on

"Rely on" = what this skill should build its adapter around. Built: adapter exists on this
branch. Verified = confirmed in this research; [KB] = from vendor docs as known, re-check before
building that adapter.

| Vendor | Full config, read-only | Version / model | API (read-only role) | Official MCP | Threat/IPS events | Rely on |
|---|---|---|---|---|---|---|
| Palo Alto PAN-OS | CLI `show config running` (snapshot profile exists) | `show system info` | XML API and REST API; admin role profile with read-only XML/REST; built-in "Superuser (read-only)" [KB] | No (Prisma AIRS MCP is for AI agents) | Threat log CSV export; syslog. Threat IDs map to CVEs through Palo Alto advisories (verified for CVE-2024-3400: IDs 95187, 95189, 95191) | **CLI config + threat CSV. Built.** |
| Fortinet FortiOS | CLI `show` (profile tested on lab v2) | `get system status` | REST `/api/v2/cmdb`, `/api/v2/monitor`; REST API admin bound to a read-only profile and trusted hosts [KB] | No official found | IPS log (type=utm subtype=ips) via syslog or FortiAnalyzer export | **CLI config + IPS log. Built.** |
| Cisco ASA | CLI `show running-config` (profile exists) | `show version` | ASA REST API (end of life on newer platforms [KB]); privilege-level based | No | Syslog. ASA has no IPS of its own; threat-detection 733100 messages are rate alerts | **CLI config. Built (no event parser for 733100 yet).** |
| Cisco FTD / FMC | FTD CLI shows the deployed config, but policy lives in FMC | `show version` | FMC REST API, user role "Security Analyst (Read Only)" [KB] | DevNet "community" FMC server | FMC intrusion event CSV export, eStreamer | **FMC export (API or CSV). Not built. The event parser already reads FMC-style CSV columns.** |
| Juniper SRX | CLI `show configuration \| display set` (profile exists) | `show version` | NETCONF / REST, login class `read-only` | Yes, but it can commit config | `RT_IDP_ATTACK_LOG` syslog | **CLI config. Management checks built; security-policy checks not yet.** |
| Check Point | Not from a gateway CLI; policy is on the management server | Gaia `show version all` | Management Web API (`/web_api/`, `show-access-rulebase`), read-only permission profile [KB] | **Yes (official family)** | Management logs API, or the logs MCP | **Management API or official MCP as the collector. Not built.** |
| SonicWall SonicOS 7 | `show current-config` [KB] | `show status` [KB] | SonicOS API, read-only admin [KB] | No | syslog `sid=` for IPS [KB] | CLI config. Not built. |
| Sophos Firewall (SFOS) | No full CLI dump; XML API `Get` or a backup export [KB] | `system diagnostics show version-info` [KB] | XML API on port 4444, read-only admin profile [KB] | No official found | syslog `log_component="IPS"` [KB] | XML API export. Not built. |
| pfSense / OPNsense | `/conf/config.xml` | `/etc/version`, `opnsense-version` | OPNsense: official REST with per-endpoint key; pfSense: community REST package | No official | Suricata `eve.json` (**parser built**) | config.xml export. Config checks not built. |
| WatchGuard Firebox | `show config` [KB] | `show version` [KB] | WatchGuard Cloud API [KB] | No | syslog | Not built. |

Mid-market vendors not in the request but worth an adapter later: Cisco Meraki MX (Dashboard
API, no CLI), Barracuda CloudGen, Forcepoint, Zyxel.

Route/switch: Cisco IOS-XE, ASA, NX-OS, Junos, Arista EOS and AOS-CX get CVE matching now
(version from the snapshot). IOS-XE and Junos have config checks. EOS, NX-OS and AOS-CX need
parsers and check packs. Extreme, Huawei, Dell, Nokia and Ubiquiti need snapshot profiles
first (owned by network-snapshot).

## Advisory data: what the CVE side relies on

- **CVE.org record API** (no key): the vendor's own affected-version data, plus CISA's
  Vulnrichment answers (automatable, technical impact) that BOD 26-04 points to. Primary source
  for every vendor except Palo Alto.
- **Palo Alto advisory JSON**: used for PAN-OS because both the CVE.org copy and Palo Alto's
  list alone get some hotfix releases wrong (details and test in `research/sources.md`).
- **NVD API 2.0**: only to find CVE IDs per product. Since April 2026 NVD enriches mainly
  KEV and priority software, so its CPE data is a fallback.
- **CISA KEV and FIRST EPSS**: exploitation status and likelihood.
- **Cisco openVuln API**: better for Cisco train/feature mapping, but each user needs an OAuth
  client. A good optional adapter later.

Nothing about the user's network leaves the machine. Queries name a product or a CVE ID.

## What can run as separate sessions

Each item below touches its own files, so it can run in parallel without stepping on the
others.

1. **One session per new firewall adapter**: SonicWall, Sophos, pfSense/OPNsense (config.xml),
   WatchGuard. Each adds a parser, checks with sources, and fixtures. Each needs a matching
   network-snapshot profile, coordinated with whoever owns that skill.
2. **Check Point collector**: read-only Management API exporter, or an evaluation of the
   official MCP as the collector, plus the adapter. Ships as a separate optional plugin if it
   is an MCP server.
3. **Cisco FTD/FMC**: FMC export plus adapter.
4. **Route/switch check packs**: Arista EOS, NX-OS, AOS-CX (parsers exist in no form yet; CVE
   matching already works).
5. **SRX security-policy checks** (any-any, inbound any, NAT) on the existing Junos parser.
6. **Cisco openVuln adapter** for Cisco advisory accuracy.
7. **Lab validation**: a local session with lab v2 reachable, running snapshot then this check
   on the real IOS-XE and FortiGate, and moving those adapters from untested to tested.

The engine, the scoring and the report format are shared and should stay in one session at a
time.

## Decisions for Garrett

1. **Scoring basis.** This uses CISA BOD 26-04 Table 1 as the backbone, with nine written house
   rules (SCORING.md). The alternative was CERT/CC's SSVC deployer table, which is CC BY-NC 4.0
   and so a poor fit for a public MIT repo used by a business. Confirm BOD 26-04 is the method
   you want to teach on the channel.
2. **Default exposure for firewalls whose interfaces can't be parsed: assumed internet-facing.**
   That's conservative (some findings may score high), and it's what BOD 26-04 says to do when
   unsure. The other option is to assume internal and flag it.
