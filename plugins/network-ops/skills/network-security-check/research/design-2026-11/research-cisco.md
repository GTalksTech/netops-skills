# Cisco / CISA research for the read-only security audit skill (as of 2026-11-24)

Method: WebSearch + WebFetch (WebFetch reads pages through a summarizing model, so JSON structure was extracted by query, not by raw parse). Firecrawl used twice: Software Checker page (JS-rendered; succeeded) and one community.cisco.com article (login wall; failed). Plain curl to www.cisco.com returns Akamai 403, so a Python fetcher needs browser-like handling or a different path.
Verified = primary page opened. Unverified = search snippet or secondary source only.

## 1. Cisco CSAF 2.0

- Provider metadata: https://www.cisco.com/.well-known/csaf/provider-metadata.json. metadata_version 2.0, publisher "Cisco PSIRT" (vendor), one distribution with `directory_url` https://www.cisco.com/.well-known/csaf/. **No ROLIE feed.** Verified.
- Directory: year folders 2017 to 2026, plus `index.txt` and `changes.csv` (the CSAF directory-based distribution). No .sha256 or .asc files are listed. Verified (https://www.cisco.com/.well-known/csaf/).
- Sample file: https://www.cisco.com/.well-known/csaf/2026/cisco-sa-xe-webui-dos-ptaodaww.json (CVE-2026-20311, IOS XE Web UI DoS, published 2026-08-05, csaf_version 2.0, category csaf_security_advisory). File names are lowercase; tracking id is mixed case (cisco-sa-xe-webui-dos-PtAODAWW). Verified.
  - **Affected versions are enumerated, not ranges.** The tree is vendor "Cisco", then product_family "Cisco IOS XE Software", then product_version train (17.3 ... 17.18, 26.1), then service_pack leaf (e.g. 17.3.1 = CSAFPID-254712, 26.1.1a = CSAFPID-308490). 145 leaves, each with its own product_id. No `vers` or product_version_range, no relationships, no platform/PID, and no CPE or PURL helper. Verified.
  - Data quality: one train node is named "15.15" where 17.15 is expected. Expect data errors and parse defensively. Verified (as extracted).
  - **product_status has `known_affected` only.** There is no `fixed` and no `not_affected`. Verified.
  - **No fixed release versions.** remediations has one `vendor_fix` entry with generic text and a link to software.cisco.com, covering the affected IDs. The "Fixed Software" note points to the Cisco Software Checker rather than listing first-fixed releases. Verified.
  - **SIR is not in a structured field.** There is no aggregate_severity and no threats. SIR appears only as a reference link titled "Security Impact Rating (SIR)" and in note prose. The HTML page shows "Medium". Since SIR follows CVSS bands (see below), derive it from the CVSS score or take `sir` from openVuln. Verified.
  - CVSS: `scores[].cvss_v3` with version 3.1, baseScore 6.3, baseSeverity MEDIUM and vectorString. Verified.
  - **Workarounds** are a document note (category general, title "Workarounds") in prose: "There are no workarounds that address this vulnerability." No `workaround` remediation object exists, even when the note says none. Verified.
  - **The config conditions and show commands are in the CSAF.** The document note "Vulnerable Products" (category general) contains the HTML page's check commands, e.g. `show running-config | include ip http server|secure|active` and `show running-config | include http secure-piv-based-auth`. They are free text, not structured, so the skill must hand-author its config predicates. Verified.
  - Notes in this file: Summary, Vulnerable Products, Products Confirmed Not Vulnerable, Workarounds, Fixed Software, Vulnerability Policy, Exploitation and Public Announcements, Source, and Legal Disclaimer. The vulnerability note is "Affected Product Comprehensiveness: Complete". Verified.
- SIR policy: SIR "is based on the CVSS Base score". Bands are Critical 9.0-10.0, High 7.0-8.9 and Medium 4.0-6.9; PSIRT may adjust for Cisco-specific factors. Low-SIR issues usually go out as bug release-note enclosures, not advisories. CSAF is offered for advisories. https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html Verified.
- Disclosure-model change (July 2026): advisories now publish on a fixed schedule, the 1st and 3rd Wednesday at 16:00 UTC, as platform "hardening releases" (IOS XE, IOS XR, NX-OS, Secure Firewall, ASA). Low-risk bugs get less detailed disclosure. Same-CWE bugs are grouped under an "umbrella" CVE scored at the highest severity. https://sec.cloudapps.cisco.com/security/center/resources/risk-based-disclosure Verified. Impact: advisory-to-bug cardinality changes, and one CVE can cover many bugs.

## 2. Cisco PSIRT openVuln API

- Docs: https://developer.cisco.com/docs/psirt/ (overview: API version 2.0.1, OpenAPI yaml linked, contact openvuln@cisco.com). Verified.
- Auth: register an app at https://apiconsole.cisco.com (My Apps & Keys), app type "Service", grant "Client Credentials". Token URL https://id.cisco.com/oauth2/default/v1/token; tokens last 3600 s. https://developer.cisco.com/docs/psirt/authentication/ Verified.
- Eligibility: a Cisco.com account is required. Docs state no contract requirement and no cost. Unverified: it is widely understood to be free with any Cisco.com ID.
- Rate limits: 5 calls/s, 30/min, 5000/day per app. Over the limit returns HTTP 429 with `X-Mashery-Error-Code: ERR_403_DEVELOPER_OVER_RATE` and Retry-After. https://developer.cisco.com/docs/psirt/browsing-sorting-filterting-and-rate-limits Verified. The FAQ recommends local caching. Verified.
- Base: `https://apix.cisco.com/security/advisories/v2/`. Verified.
- **Version query (current endpoint):** `GET /OSType/{OSType}?version=X`, where OSType is one of `aci, ios, iosxe, nxos, asa, ftd, fmc, fxos`.
  - Optional parameters: `platformAlias` (nxos/asa/ftd/fxos only; values include ASA5500X, ASAV, FPR1000, FPR2100, FPR4100, FPR9000, FWL3100, ISA3000, NEXUS9000...; no 1200/4200/6100 alias listed), plus advisoryId, summaryDetails, productNames, startDate/endDate (added 2025-06-11), pageIndex and pageSize (max 100).
  - Response fields: advisoryId, advisoryTitle, bugIDs, ipsSignatures, cves, cvrfUrl, csafUrl, cvssBaseScore, cwe, firstPublished, lastUpdated, status, version, productNames, publicationUrl, sir, summary.
  - Sources: https://developer.cisco.com/docs/psirt/ostypeostype/ Verified.
- `firstFixed`: the "obtain advisory by software" page shows `firstFixed` (e.g. 17.3.1w, 17.3.2a) in its OSType sample, but the OpenAPI schema omits it. Treat it as present, schema undocumented. https://developer.cisco.com/docs/psirt/obtain-advisory-by-software Verified (conflict noted).
- Other helpers: `/OS_version/OS_data?OSType=` lists the known versions and platforms in the Software Checker. Verified via the same page; the endpoint path comes from search, Unverified.
- Deprecations: Verified via https://developer.cisco.com/docs/psirt/api-changelog
  - The old per-OS endpoints (`/iosxe?version=`, `/ios?version=`) sit under "Sunset Endpoints". Verified (https://developer.cisco.com/docs/psirt/iosxe/).
  - The `/cvrf/` endpoints return 410. CVRF support was to end 2023-12-31, and the changelog says CSAF replaces CVRF.
  - api.cisco.com is being retired: apps registered after 2023-03-01 use apix.cisco.com, and the legacy `security/advisories/` path is sunset in favor of `/v2/`.
  - An SMU field was added 2023-08-22.
  - The changelog has no 2026 entries.

## 3. Cisco Support APIs (lifecycle / upgrade)

- Overview: https://developer.cisco.com/docs/support-apis/introduction-to-cisco-support-apis/ lists Automated Software Distribution, Bug, Case, EoX, Product Information, Service Order Return and Software Suggestion. Verified.
- **Eligibility: contract-gated.** "If you are a Cisco Smart Net Total Care (SNTC) customer, you are entitled to access"; the same applies to PSS partners. https://developer.cisco.com/site/support-apis/ Verified. Community posts add that the Cisco.com profile needs the "API Developer" role under Smart Services. Unverified. **Not usable by an arbitrary public user**, so it must be optional in the skill.
- Auth: OAuth2 client credentials at https://id.cisco.com/oauth2/default/v1/token, 1 h token, Bearer header. https://developer.cisco.com/docs/support-apis/authentication/ Verified. Rate limits are not published there (Software Suggestion lists per-second and daily rate errors).
- EoX v5: base `https://apix.cisco.com/supporttools/eox/rest/5/`. https://developer.cisco.com/docs/support-apis/eox/ Verified.
  - Lookups: `EOXByDates`, `EOXByProductID` (wildcards with at least 3 chars), `EOXBySerialNumber` and `EOXBySWReleaseString`. Up to 20 inputs per request.
  - Fields: EndOfSaleDate, EndOfSWMaintenanceReleases, EndOfSecurityVulSupportDate, LastDateOfSupport and EOXMigrationDetails.
- Software Suggestion v2: base `https://apix.cisco.com/software/suggestion/v2/suggestions/`, JSON only. https://developer.cisco.com/docs/support-apis/software-suggestion/ Verified.
  - Endpoints: `software/productIds/{pids}` and `releases/productIds/{pids}` (max 10 PIDs), `compatible/productId/{basePID}` (params currentRelease, currentImage, supportedFeatures, supportedHardware), plus MDF-ID variants.
  - Fields: isSuggested Y/N, releaseFormat1/2, majorRelease, releaseTrain and releaseLifeCycle.

## 4. Cisco ASA

- **CISA ED 25-03** was issued 2025-09-25 and updated to "V1" on 2026-04-23, which supersedes the original required actions. CVEs: CVE-2025-20333 (RCE) and CVE-2025-20362 (privilege escalation), tied to ArcaneDoor; ROM modification for persistence was seen. https://www.cisa.gov/news-events/directives/ed-25-03-identify-and-mitigate-potential-compromise-cisco-devices Verified.
  - Original scope: ASA hardware, ASA-SM, ASAv, ASA on Firepower 2100/4100/9300, and FTD.
  - Original actions:
    - Core dump and hunt on public-facing ASA by 2025-09-26.
    - **ASA hardware with end of support on or before 2025-09-30 must be permanently disconnected by 2025-09-30.**
    - ASA hardware with end of support on 2026-08-31 must be updated by 2025-09-26, then patched within 48 h of each new release.
    - ASAv and FTD must be updated by 2025-09-26.
    - Inventory due 2025-10-02.
  - V1 adds Firepower 1000/2100/4100/9300 and Secure Firewall 200/1200/3100/4200/6100. V1 actions:
    - Core dumps due 2026-04-24.
    - Updates, including a persistence-specific patch, due 2026-04-24.
    - A **hard power-pull reset by 2026-04-30**: "a reboot is not sufficient to expunge the malware".
    - Inventory due 2026-05-01.
    - Newly found end-of-support ASA must follow **BOD 26-02** (end-of-support edge devices). Not opened. Unverified.
  - Follow-ups: FIRESTARTER malware analysis report AR26-113A, supplemental core-dump instructions, eviction playbook, and a 2025-11-12 note that agencies marked devices "patched" while still running vulnerable versions (minimum-version guidance). Listed on the ED page. Verified (sub-pages not opened).
- **ASA software today.** Newest train is **9.24(x)**: the release-notes list shows the 9.24(x) notes updated 2026-10-28, and no 9.25 notes are listed. https://www.cisco.com/c/en/us/support/security/adaptive-security-appliance-asa-software/products-release-notes-list.html Verified. The sustaining bulletin maps FTD 10.0 to ASA 9.24.1 and FTD 10.5 to ASA 9.25.1, with 9.25 planned. https://www.cisco.com/c/en/us/products/collateral/security/firewalls/bulletin-c25-743178.html Verified.
- **9.24 platforms:** ASA Virtual, Secure Firewall 220, Firepower 1010/1010E/1120/1140/1150, Secure Firewall 1210CE-1250, 3105-3140, Firepower 4112-4145, Secure Firewall 4215/4225/4245, 6160/6170, Firepower 9300 and ISA 3000. https://www.cisco.com/c/en/us/td/docs/security/asa/compatibility/asamatrx.html (dated 2026-03-24) Verified.
- **Last ASA release by platform:** 5506/5506H/5506W/5508/5516-X: 9.16. 5525/5545/5555-X: 9.14. 5512/5515/5585-X and ASASM: 9.12. Firepower 2100: 9.20. Firepower 4110-4150: 9.18. Same page. Verified.
- **ASA 5500-X end of life** (all dates are now past):
  - 5506-X family (EOL13763): end of sale 2021-08-02, end of service contract renewal 2025-10-28, **last date of support 2026-08-31**. https://www.cisco.com/c/en/us/products/collateral/security/asa-5500-series-next-generation-firewalls/eos-eol-notice-c51-744797.html Verified.
  - 5508-X / 5516-X (EOL13762): end of sale 2021-08-02, **last date of support 2026-08-31** (HW). https://www.cisco.com/c/en/us/products/collateral/security/asa-5500-series-next-generation-firewalls/eos-eol-notice-c51-744798.html Verified.
  - 5525-X / 5545-X / 5555-X (EOL13130, amended):
    - End of sale 2020-09-04.
    - End of software maintenance 2021-09-04.
    - End of contract renewal 2024-11-30.
    - **Last date of support 2025-09-30.**
    - https://www.cisco.com/c/en/us/products/collateral/security/asa-firepower-services/eos-eol-notice-c51-743545.html Verified.
  - These dates line up with ED 25-03's two groups (2025-09-30 and 2026-08-31).

## 5. MCP servers for advisories

- No official, Cisco-supported MCP server found. Verified (search plus GitHub).
- `CiscoPSIRT/openvuln-mcp` (https://github.com/CiscoPSIRT/openvuln-mcp) sits in Cisco PSIRT's GitHub org but describes itself as "Community-supported MCP server for the Cisco OpenVuln API". Label it **community, PSIRT-hosted**. Verified (GitHub API).
  - Created 2025-06-20, last push 2026-01-20, about 10 stars.
  - Python 3.13 stdio server; needs openVuln client ID and secret.
  - Tools: advisory by ID, CVE, latest, by severity, by product, and Software Checker queries.
- Community (third-party): glama.ai lists `aldoleiva1/MCP-Svr-OpenVulnAPI` (FastMCP) and a "psirt-exposure" IOS XE config-matching project. Unverified (listing only).
- No official advisory MCP found from Juniper, Fortinet, Palo Alto or Arista in one search. Unverified (absence of evidence).

## 6. Software Checker vs openVuln

- The openVuln docs state "The Cisco PSIRT openVuln API allows users to query the Cisco Software Checker". The OSType and OS_data endpoints are that query path, so the version-to-advisory matching (incl. firstFixed) is the same data source. https://developer.cisco.com/docs/psirt/obtain-advisory-by-software Verified. The docs never explicitly say "identical logic". Unverified beyond that sentence.
- Software Checker covers ASA, FMC, FTD, FXOS, IOS, IOS XE, NX-OS and NX-OS in ACI mode. **No IOS XR** and no interim builds. ASA/FMC/FTD/FXOS data only covers advisories first published from **Jan 2022**; NX-OS and ACI from **July 2019**. It "does not account for enabled or disabled features", so it matches by version only. It also offers "First Fixed" and "Combined First Fixed". https://sec.cloudapps.cisco.com/security/center/softwarechecker.x (via Firecrawl) Verified.
- Implication: version matching (openVuln, Software Checker or CSAF known_affected) gives "potentially affected". Config predicates from the "Vulnerable Products" note are needed to reach "affected". IOS XR needs CSAF or other sources.
