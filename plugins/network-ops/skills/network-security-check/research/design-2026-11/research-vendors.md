# Vendor advisory + lifecycle data sources for a read-only network audit skill

Research date: 2026-11-24. Tags: **[V]** = Verified (primary page/file opened this session), **[U]** = Unverified (search snippet, third party, or inferred).
Firecrawl was used for 3 JS-rendered pages (Juniper EOL table, Arista EOS lifecycle, Fortinet lifecycle portal); everything else used WebFetch/curl.

## Summary table

| Vendor | Best machine format (vendor-authoritative) | Key needed | Severity field | Exposure conditions machine-readable? | EoL source |
|---|---|---|---|---|---|
| Fortinet (FortiOS) | CSAF 2.0 JSON per advisory, discovered via RSS `csaf:link` (no provider-metadata.json); also CVRF 1.2 XML per advisory | No [V] | `cvss_v3.baseSeverity` + severity word in vuln `title`; no separate vendor field [V] | No; free text in `notes` ("Additional info") [V] | support.fortinet.com lifecycle needs FortiCloud login [V]; Fortinet staff community posts + endoflife.date API as fallback |
| Palo Alto (PAN-OS) | CVE JSON 5.0 at `/json/<id>` (vendor calls it "more stable"); CSAF (VEX, says 2.1) at `/csaf/<id>`; beta REST API; RSS | No [V] | CVSS v4 `baseSeverity` + `providerUrgency` (RED/AMBER/...) [V] | Yes as a dedicated field: CVE JSON `configurations` (text, not structured) [V]; CSAF copy lacks it [V] | Public HTML EoL summary, no login [V] |
| Juniper (Junos) | No vendor CSAF/JSON feed found [U-absence]; CVE JSON 5.0 records Juniper publishes as CNA (cveawg API / CVEProject/cvelistV5) [V] | No [V] | CVSS 3.1 + 4.0 with `providerUrgency` [V] | Yes as dedicated `configurations` field (text with config stanza) [V] | Public HTML table support.juniper.net/support/eol/software/junos/ (JS-rendered; Firecrawl) [V] |
| Arista (EOS) | No CSAF/JSON feed found [U-absence]; CVE JSON 5.0 as CNA [V]; advisory HTML + PDF | No | CVSS only (in CVE JSON); advisory page had no severity [V] | Yes as `configurations` field in CVE JSON (text) [V]; HTML has "Required Configuration for Exploitation" section [V] | Lifecycle policy page; train matrix is a JPG image, not data [V] |
| HPE Aruba (AOS-CX / AOS-S) | CSAF 2.0 directory distribution at csaf.arubanetworking.hpe.com (`index.txt`, `changes.csv`, `/YYYY/*.json`); no provider-metadata.json [V] | No [V] | `document.aggregate_severity` (FIRST CVSS qualitative scale) + CVSS 3.1 [V] | No; free text notes/workaround [V] | Not researched in depth (HPE Networking support portal) [U] |
| Cisco Meraki | Via Cisco PSIRT (openVuln API needs free OAuth client; Cisco per-advisory CSAF) [U] | openVuln: yes (free registration) [U] | Cisco SIR [U] | No [U] | Meraki docs EOL pages (mostly hardware) [U] |
| Check Point (Gaia) | No vendor CSAF/JSON found [U-absence]; CVE JSON as CNA is thin (free-text version string, no fix/config fields) [V] | No | CVSS 3.1 in CVE JSON [V] | No [V] | Public HTML "Support Life Cycle Policy" table, no login [V] |
| SonicWall (SonicOS) | No documented feed found; PSIRT site is a JS SPA [V]; CVE JSON as CNA is thin (no metrics, free-text versions) [V] | No | none in CVE JSON (metrics null for CVE-2024-53704) [V] | No [V] | Not researched [U] |

Cross-cutting conclusion: **CVE JSON 5.0 (CVEProject/cvelistV5 on GitHub, or `https://cveawg.mitre.org/api/cve/<CVE>`) is the only single free format that covers all eight vendors as CNAs**, and for PAN, Juniper and Arista it carries vendor-authored `configurations`, `workarounds`, `solutions` and version ranges. Quality varies widely (see per-vendor notes). Vendor CSAF exists only for Fortinet, Palo Alto and HPE Aruba, and none of the three publishes a discoverable `provider-metadata.json` [V for all three probes].

---

## 1. Fortinet (FortiOS)

### Machine-readable feeds
- **RSS** [V]: `https://www.fortiguard.com/rss/ir.xml` 302-redirects to `https://filestore.fortinet.com/fortiguard/rss/ir.xml`. RSS 2.0; per item `title, link, description (CVSSv3 + summary), guid, pubDate, csaf:link, cvrf:link` (namespace `https://fortiguard.fortinet.com/rss/ns/csaf`). No key. The feed is the only index of CSAF URLs found.
- **CSAF 2.0** [V]: per advisory, e.g. `https://filestore.fortinet.com/fortiguard/psirt/csaf_unauthenticated-adjacent-command-execution-via-ha_fg-ir-26-273.json`. URL contains a title slug, so you cannot build it from the FG-IR ID; take it from RSS.
- **No provider-metadata.json / ROLIE** [V]: 404 at `www.fortiguard.com`, `fortiguard.fortinet.com`, `www.fortinet.com` `/.well-known/csaf/provider-metadata.json`. `https://www.fortiguard.com/psirt/csaf/<ID>` returns 422.
- **CVRF 1.2 XML** [V]: `https://www.fortiguard.com/psirt/cvrf/FG-IR-YY-NNN` (ID-addressable). Sample FG-IR-26-098 (FortiManager): every build enumerated as its own FullProductName (30 builds), only "Known Affected", **no Fixed status and Remediation "None"**, and malformed XML (stray `Reference>` text). Do not rely on CVRF.
- Publication: second Tuesday monthly, out-of-cycle for critical (per policy page; [U] from search snippet).

### Sample CSAF: FG-IR-26-273 (FortiOS, CVE-2026-126259, published 2026-11-10) [V]
- **Version expression**: mixed. `product_version` `FortiOS/8.0.0`; `product_version_range` with non-standard syntax `FortiOS/>=7.6.0|<=7.6.7` (not `vers:`), and free text `FortiOS/7.0 all versions`. Parser must handle `>=a|<=b` and "X.Y all versions".
- **Fixed versions**: `known_not_affected` lists `FortiOS-8.0.1, 7.6.8, 7.4.13, 7.2.14` (note hyphen vs space product_id style inconsistency). `vendor_fix` remediation text: "FortiOS 7.6: Upgrade to 7.6.8 or above"; "FortiOS 7.0: Migrate to a fixed release".
- **Conformance bug**: remediation and scores `product_ids: ["FortiOS"]`, which is not a defined product_id. Strict CSAF validators will fail; parse leniently.
- **Severity**: `cvss_v3` 3.1 baseScore 9.0, `baseSeverity: CRITICAL`, vector includes temporal metrics (`E:U/RL:O/RC:C`). Severity also embedded in vuln title "FortiOS - CRITICAL - FG-IR-26-273". No separate vendor severity field.
- **Conditions**: free text in `notes[category=general, title="Additional info"]` (HA segment adjacency, `config system ha` hardening, virtual patch name). Not machine-structured.
- **Workaround**: no `workaround` remediation object; mitigation lives in that note.
- **Fortinet severity scale**: appears to be CVSS v3 qualitative (title word == baseSeverity) [V for this sample; policy wording U].

### End of support (FortiOS)
- Official Product Life Cycle: `https://support.fortinet.com/Information/ProductLifeCycle.aspx` → SPA `support.fortinet.com/support/#/lifecycle` → redirects to FortiCloud SSO login [V via Firecrawl]. **Login required.**
- Fortinet staff community post (bkrishnan, Staff badge, 2026-03-05), CSB-260330-1 [V]: https://community.fortinet.com/fortigate-3/technical-tip-fortios-end-of-support-change-for-fortios-v7-4-and-v7-6-224876
  - 7.4: EoES 11 May 2026 → **11 May 2027**; EoS 11 Nov 2027 → **11 Nov 2028**
  - 7.6: EoES 25 Jul 2027 → **25 Jul 2028**; EoS 25 Jan 2029 → **25 Jan 2030**
- endoflife.date API (third party, community-maintained, free JSON) `https://endoflife.date/api/v1/products/fortios/` [V, values third-party]:

| Train | GA | End of Eng. Support | End of Support |
|---|---|---|---|
| 8.0 | 2026-04-21 | 2029-04-21 | 2030-10-21 |
| 7.6 | 2024-07-25 | 2028-07-25 | 2030-01-25 |
| 7.4 | 2023-05-11 | 2027-05-11 | 2028-11-11 |
| 7.2 | 2022-03-31 | 2025-03-31 | 2026-09-30 |
| 7.0 | 2021-03-30 | 2024-03-30 | 2025-09-30 |

  7.4/7.6 match the Fortinet staff post [V]. 7.0/7.2/8.0 not confirmed on a Fortinet page reachable without login [U]. Search snippets (not opened) claim 7.2 is LTS with Extended EoS 2028-03-31, and a 7.0 FIPS-CC extended-support tip exists (community.fortinet.com ta-p/407617) [U]. 8.0 EoES = GA + 36 months is consistent with Fortinet's stated 36-month engineering-support rule [U].
- Note: as of 2026-11-24, FortiOS 7.2 standard EoS (2026-09-30) has passed unless the LTS extension applies [U].

### MCP
- No official Fortinet MCP server found (no `mcp` repos in github.com/fortinet) [V via GitHub search API]. Community: paoloamato2/fortinet-mcp-server (FortiOS REST), rstierli/fortimanager-mcp, jmpijll/fortimanager-mcp [U, aggregator listings].

## 2. Palo Alto Networks (PAN-OS)

### Machine-readable feeds [V]
- **CVE JSON 5.0**: `https://security.paloaltonetworks.com/json/<CVE-or-PAN-SA-id>`; `/json` lists condensed advisories. API doc calls it "a more stable rendering". No key.
- **Beta REST API**: `/api/v1/products`, `/api/v1/products/PAN-OS/<version>/advisories`, `/api/v1/products/PAN-OS/advisories`; filters `product`, `version`, `severity`, `sort`. Marked "subject to changes". No auth or rate limit stated. Version lookup endpoint is ideal for "which advisories affect 11.1.2-h3".
- **CSAF**: `https://security.paloaltonetworks.com/csaf/<CVE>` returns a CSAF VEX document (reported as CSAF 2.1, `category: csaf_vex`), uses `vers:generic/PAN-OS<10.2.0-h3` ranges. No provider-metadata.json at `/.well-known/csaf/` or `/csaf/` (both 404). Sample CVE-2024-3400 CSAF had **no remediations array and no configuration detail**, and tracking `version 1` vs 15 revisions. Prefer `/json`.
- **RSS**: `https://security.paloaltonetworks.com/rss.xml` [U content].
- Publication: second Wednesday monthly, 09:00 PT [U].

### Sample CVE JSON: CVE-2024-3400 [V]
- **Versions**: `{"version":"10.2","lessThan":"10.2.0-h3","status":"affected","changes":[{at: <fixed build>, status: unaffected}...]}` plus flat `"9.0 All" unaffected`; also `x_affectedList` (flat list of every affected build string, e.g. "PAN-OS 11.1.2-h2"). The flat list is the easiest exact-match source.
- **Fixed**: `changes[].at` builds; `solutions` text.
- **Severity**: `cvssV4_0` baseScore 10, `baseSeverity CRITICAL`, `providerUrgency RED`; CSAF copy also has Automatable, Recovery, vulnerabilityResponseEffort.
- **Workaround**: `workarounds` field (Threat Prevention signature text). `exploits` field states exploitation status.
- **Conditions**: `configurations` field states GlobalProtect gateway/portal must be configured [V]. Text, not structured, but a dedicated field you can surface verbatim.

### Severity scale
- PAN severity = CVSS (v4.0 on new advisories, v3.1 on old) qualitative rating, plus CVSS v4 supplemental metrics: Urgency (`providerUrgency` CLEAR/GREEN/AMBER/RED), Automatable, Recovery, Response Effort [V fields present; definitions U]. PAN scores CVSS-BT (threat metric `E:`), so the score can drop when not exploited [U]. "Exposure" is expressed in `configurations` text, not a field.

### End of life [V]
- `https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary`: public HTML, no login, no CSV/JSON.
  - 10.1: EoL 2024-12-01 (Ext Support+ 2026-03-31)
  - 10.2: EoL 2025-08-27 (Ext Support+ 2027-03-31)
  - 11.0: EoL 2024-11-17
  - 11.1: EoL 2027-05-03 (Ext Support+ 2027-08-31)
  - 11.2: EoL 2027-05-02 (Ext Support+ 2027-08-31)
  - 12.1: EoL 2028-08-28 (Ext Support+ 2029-08-28)
- endoflife.date also has `panos` (HTTP 200) [V exists].

### MCP
- Official PAN MCP servers exist but none for PAN-OS/Strata config or advisories: Cortex MCP Server (open beta), Prisma AIRS MCP, Data Security MCP (2026-11-10 blog) [U, PAN blog search results]; GitHub org has `PaloAltoNetworks/pan-mcp-relay` (AI Runtime Security relay) and `AppSecMCP` [V repo listing].

## 3. Juniper (Junos; HPE)

### Machine-readable feeds
- No Juniper CSAF provider found: `www.juniper.net/.well-known/csaf/provider-metadata.json` 404, `supportportal.juniper.net` 401, `csaf.juniper.net` does not resolve [V probes]. Searches found only third-party CSAF (BSI WID, NCSC-NL) about Juniper [U-absence].
- Advisories (JSA) live on supportportal.juniper.net (Salesforce, JS): HTML scrape would be required.
- **CVE JSON 5.0** as CNA (shortName `juniper`), free, no key: `https://cveawg.mitre.org/api/cve/<CVE>` or the CVEProject/cvelistV5 git repo [V].
- Publication: quarterly, second Wednesday of Jan/Apr/Jul/Oct, plus out-of-cycle [U].

### Sample: CVE-2025-59961 (JSA103150, published 2026-01-15) [V]
- **Versions**: per-train ranges `{"version":"21.4","lessThan":"21.4R3-S12","versionType":"semver"}`; Junos OS and Junos OS Evolved as separate products. Gotchas: `versionType: "semver"` although Junos versions are not semver; values like `"lessThan":"22.2*"` and `"lessThan":"25.2R1-S1, 25.2R2"` (two values in one string). Needs a custom Junos version comparator.
- **Fixed**: `solutions` text lists every fixed release ("21.2R3-S10, 22.4R3-S8, ... and all subsequent releases").
- **Severity**: `cvssV3_1` 5.5 MEDIUM and `cvssV4_0` 6.8 MEDIUM with `providerUrgency GREEN`. Juniper's JSA "Severity" is the CVSS qualitative rating [U].
- **Workaround**: `workarounds` field (CLI to change socket permissions).
- **Conditions**: `configurations` field: "To be affected by this issue, a device must be configured with either:" followed by config stanzas (`forwarding-options dhcp-relay ...`). Text with embedded config paths, so semi-matchable against saved configs.
- `exploits`: SIRT exploitation statement. `source.advisory`: JSA ID.

### End of life [V, Firecrawl]
- `https://support.juniper.net/support/eol/software/junos/`: "Junos OS Dates & Milestones", HTML table, no login (JS-rendered; plain fetch got only a survey popup). Last updated 14 Jul 2026. Columns: Product | FRS | End of Engineering | End of Support | Release Type (EOL/EEOL), plus numbered footnotes with per-platform extensions.
  - 22.4: EoE 2025-12-22, EoS 2026-06-22 (EEOL; PTX extensions to 2028/2029)
  - 23.2: EoE 2028-06-23, EoS 2028-12-23
  - 23.4: EoE 2028-12-26, EoS 2029-06-26
  - 24.2: EoE 2029-07-19, EoS 2030-01-19
  - 24.4: EoE 2029-12-29, EoS 2030-06-29
  - 25.2: EoE 2030-06-30, EoS 2030-12-30
  - 25.4: EoE 2030-12-22, EoS 2031-06-22
  - 26.2: EoE 2031-06-29, EoS 2031-12-29
- No JSON; endoflife.date has no `junos` product (404) [V].

### MCP
- **Official**: `github.com/Juniper/junos-mcp-server` (Juniper org, active, last push 2026-11-02) [V]. Device-facing (PyEZ/SSH), can commit config; not an advisory source. Community: `junos-mcp` on PyPI (shigechika) [U].

## 4. Arista (EOS)

### Machine-readable feeds
- No CSAF or JSON feed found; `www.arista.com/.well-known/csaf/provider-metadata.json` returns 200 text/html (soft 404) [V]. Advisory pages offer a PDF render (`?tmpl=component&format=pdf`) and an RSS/email subscription behind user preferences [V]; public RSS URL not found [U].
- **CVE JSON 5.0** as CNA (shortName `Arista`) [V].

### Samples [V]
- CVE-2025-1259 (EOS gNOI): versions `{"version":"4.33.0","lessThanOrEqual":"4.33.1","versionType":"custom"}` per train (inclusive upper bound = last affected, not first fixed). CVSS 3.1 7.7 HIGH. `configurations`: "the only condition is that OpenConfig must be enabled with a gNOI server" plus `show management api gnmi` output. `workarounds`: gNSI Authz config. `solutions`: upgrade text with fixed list.
- CVE-2024-27892: same structure, CVSS 4.0 present; versions with suffix `4.31.2F` / `4.30.5M`.
- HTML Security Advisory 0226 (2026-11-10, CloudVision appliance BIOS/iDRAC): no severity, no CVSS, affected by SKU; has a "Required Configuration for Exploitation" section ("No configuration exists."). Arista's advisory template consistently carries that section [U beyond these samples].

### End of life [V, Firecrawl]
- `https://www.arista.com/en/support/product-documentation/eos-life-cycle-policy`: support for each major EOS train "up to 36 months" from initial posting; F (feature) / M (maintenance) / support-only phases. **The per-train date matrix is an image** (`EOS-Life-Cycle-Policy.jpg`), not text. Derive dates as first-release + 36 months, or hand-maintain a table. No login. endoflife.date has no `arista-eos` (404) [V].

### MCP
- **Official (beta)**: `github.com/aristanetworks/eos-mcp-server` (Apache-2.0, created 2026-04-23, pushed 2026-11-18; npm `@aristanetworks/eos-mcp-server`). README: "Read-only (non-configuring) MCP server for Arista EOS eAPI"; "not currently supported by Arista TAC". Device-facing, not advisories [V]. Community CloudVision MCPs (networkRob, noredistribution) [U].

## 5. HPE Aruba Networking (AOS-CX / ArubaOS-Switch)

### Machine-readable feeds [V]
- **CSAF 2.0** at `https://csaf.arubanetworking.hpe.com/` (the old `csaf.arubanetworks.com` no longer resolves). Directory-style distribution: `index.txt`, `changes.csv` (path,timestamp; 113 lines), files under `/YYYY/hpe_networking_-_hpesbnwNNNNN.json` (+ `.txt`). **No provider-metadata.json** (404 at `/.well-known/csaf/` and root). No key.
- Product family is in the title, not the filename (e.g. "Multiple Vulnerabilities in HPE Networking AOS-CX"), so a reader must fetch and filter.

### Sample: HPESBNW05134 (AOS-CX, 2026-09-01, 34 vulns) [V]
- **Version expression**: proper CSAF `product_version_range` with `vers:semver/>=10.16.0000|<=10.16.1051` per train, plus `product_version` for fixed builds (10.16.1060 etc.). `product_identification_helper.model_numbers` holds the switch series (free text). product_ids are the raw range strings.
- **Fixed**: `product_status.fixed` = fixed builds; `vendor_fix` lists "AOS-CX 10.16.1060 and above" etc., plus a statement that EoM/EoS software is "presumed to be affected".
- **Severity**: `document.aggregate_severity` = "Critical" with namespace = FIRST CVSS v3.1 qualitative scale; per-vuln `cvss_v3` full object (base/temporal/environmental).
- **Workaround**: `remediations[category=workaround]` (restrict management interfaces to dedicated VLAN / L3 policy). Generic, not config-specific.
- **Conditions**: not structured; in `notes` Details text.
- AOS-Switch has its own advisories (e.g. HPESBNW05156, 2026-10-06) in the same directory [V title].

### End of life
- Not researched; HPE Networking Support Portal software lifecycle pages likely need HPE Passport [U].

## 6. Cisco Meraki (brief)
- Meraki vulns are published through Cisco PSIRT. Cisco openVuln API requires free registration for an OAuth client ID/secret; Cisco also publishes per-advisory CSAF [U, not opened]. Cisco `/.well-known/csaf/provider-metadata.json` 403/404 on two hosts [V probe]. Meraki firmware is cloud-managed, so version-to-advisory matching from saved configs is limited. EOL pages on documentation.meraki.com are mostly hardware [U].

## 7. Check Point (Gaia, brief)
- No vendor CSAF/JSON found (`checkpoint.com/.well-known/csaf/` 404) [V]. Product vulnerabilities are in User Center "sk" articles [U]. CVE JSON as CNA is thin: CVE-2024-24919 version is one free-text sentence ("versions R81.20, R81.10, R81, R80.40 ..."), no solutions/workarounds/configurations fields; CVSS 3.1 present [V].
- **EoL [V]**: `https://www.checkpoint.com/support-services/support-life-cycle-policy/` public HTML: R82.10 GA Dec 2025 → support until Jun 2030; R82 Oct 2024 → Apr 2029; R81.20 Nov 2022 → May 2027; R81.10 Jul 2021 → Mar 2026 (ended).
- **MCP (official)**: `github.com/CheckPointSW/mcp-servers` (Check Point org, active, pushed 2026-11-15) [V]; monorepo incl. Quantum Management, Management Logs, Gaia, Threat Emulation, Reputation, etc. [U list]; mcp.checkpoint.com [U].

## 8. SonicWall (SonicOS, brief)
- PSIRT `https://psirt.global.sonicwall.com/vuln-list` is a JS SPA; guessed `/api/v1/...` and `/rss` paths return the SPA shell (200 text/html), so no API confirmed [V]. No CSAF found.
- CVE JSON as CNA is thin: CVE-2024-53704 has `"version":"7.1.1-7058 and older versions"` free text, **no metrics**, no solutions/workarounds [V].
- EoL not researched [U].

## 9. CSAF aggregators / listers
- **BSI CSAF Lister** `https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json` [V]: category `lister`, 14 providers (Siemens, Red Hat, Huawei, ABB, Schneider, CISA, Nozomi, SICK, BSI itself, ...) + Hitachi Energy publisher. **None of the eight network vendors (nor Cisco) is listed.**
- **BSI CERT-Bund WID** is itself a CSAF trusted provider (`https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json`) and publishes CSAF advisories *about* Fortinet, Juniper, Palo Alto etc. [U, via GCVE mirror and search]. Same for NCSC-NL (`advisories.ncsc.nl/csaf/v2/...`) [U]. These are one-reader multi-vendor CSAF, but **not vendor-authoritative** and lag the vendor; usable as cross-check only.
- **CISA** CSAF provider covers ICS advisories, not these vendors [V listed in lister; scope U].
- gocsaf/csaf (`csaf_aggregator`, `csaf_downloader`) is the reference tooling [U].
- Practical "one reader": **CVEProject/cvelistV5** (CVE JSON 5.0, all eight vendors are CNAs). Pair with vendor CSAF where it exists (Fortinet via RSS, HPE Aruba via changes.csv) and PAN `/json`.

## Design implications (for the skill)
1. Build a per-vendor adapter: Fortinet = RSS → CSAF; PAN = `/json` (CVE 5) or beta API by version; HPE Aruba = `changes.csv` → CSAF; Juniper/Arista/Check Point/SonicWall = CVE JSON 5 filtered by CNA shortName.
2. Parse leniently: Fortinet CSAF has undefined product_ids and non-`vers:` ranges; Juniper stuffs two versions in one `lessThan`; Arista uses inclusive `lessThanOrEqual`; SonicWall/Check Point need free-text parsing or manual curation.
3. "Required configuration" is a dedicated (text) field only for PAN, Juniper, Arista (CVE `configurations`). Surface it verbatim; any config-match logic is our own heuristic.
4. Severity: use CVSS base severity uniformly; additionally carry PAN/Juniper `providerUrgency` and HPE `aggregate_severity` when present.
5. EoL data is HTML-only everywhere (Fortinet behind login; Arista an image). Ship a curated, dated lifecycle table in the repo with source URLs, and optionally cross-check endoflife.date (fortios, panos only).
