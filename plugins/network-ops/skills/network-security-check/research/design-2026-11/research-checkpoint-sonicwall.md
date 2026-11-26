# Research checkpoint: Check Point, SonicWall, Aruba wireless advisory data and version reads

Date: 2026-11-26. Scope: read-only research for the network-security-check skill (match device versions to vendor advisories). "Verified" means I fetched the source myself this session and saw the fact. "Unverified" means it came from a search summary, a community post I could not open, or my inference.

Correction to the earlier pass: Check Point DOES publish a public, filterable advisory index with CSV export, and its CNA records carry Jumbo Hotfix take numbers in a regular string pattern. The earlier "no machine-readable feed, thin CVE records" conclusion was wrong for 2026 records.

## Check Point

### 1. Where advisories live, and what is public

Security Advisories index. https://support.checkpoint.com/security-advisories is a public page titled "Check Point Security Advisories". On 2026-11-26 it showed 161 advisories, with filters for Check Point Severity, CVSS range, Product and Published date range, an "Export to CSV" button, and a table of Severity, Summary (CVE plus title, linked to the sk article), CVSS, Published, Updated. Newest rows: sk1000364 (CVE-2026-120490, Low 3.8), sk1000362 (CVE-2026-123039, High 7.8), sk1000291 (CVE-2026-107484, High 7.3), sk1000302 (CVE-2026-109618, Critical 9.2), sk1000171 (CVE-2026-93616, Critical 9.8), sk1000117 (CVE-2026-85102, Critical 9.8). Source: https://support.checkpoint.com/security-advisories (Verified, page is JS-rendered so I read it with one Firecrawl scrape, 1 credit). No login was needed to see the list (Verified).

Backing JSON endpoint. The page's public Next.js bundle calls the path /public/api/support-center-mms/api/securityAdvisories/getAllActive through a client whose production base URL is https://iapi-services-ucs.checkpoint.com, and writes the CSV as "SecurityAdvisories.csv". Source: https://support.checkpoint.com/_next/static/chunks/pages/security-advisories-310b7e1151fe070e.js (Verified that the strings exist in the bundle). I did NOT call the endpoint: my request was blocked by the session's permission classifier, so whether it answers without a browser session, and its field names, are Unverified. Same bundle also references /public/api/support-center-mms/api/getPublicSkLink/{sk} (Verified string, behavior Unverified). Product filter values come from each advisory's "products[].name" (Verified from code).

sk articles. Individual advisories are SecureKnowledge pages at https://support.checkpoint.com/results/sk/skNNNNNN; the three I fetched opened without login (Verified). Check Point says general SecureKnowledge access needs no registration, while some advanced content needs a contract (Unverified, CheckMates search summary, https://community.checkpoint.com/t5/General-Topics/RSS-feed-for-checkpoint-com-is-not-working-any-more/m-p/232078).

Alerts and RSS. SupportCenter "My Subscriptions" has "Product Alerts" and "Security Alerts" email sections, alerts go out same day, and Check Point staff said RSS for SupportCenter is not planned (Unverified, CheckMates threads, https://community.checkpoint.com/t5/General-Topics/Replacing-RSS-in-SupportCenter/m-p/221625). This is likely what the owner receives. Major events also get a blog post at https://blog.checkpoint.com/security/ (Unverified, search result).

Structure of three real advisories (all Verified by fetch):

- sk182336, CVE-2024-24919 (https://support.checkpoint.com/results/sk/sk182336). Property table (Solution ID, Date Created 2024-05-26, Last Modified, Products, Versions), then Symptoms and Solution. CVSS 8.6 with vector. Affected: Quantum Security Gateway, Spark, Scalable Platforms, CloudGuard on R81.20, R81.10, R81.10.X, R81 plus EoS versions. Fix: included from R82; recommended JHF R81.20 Take 65, R81.10 Take 150, R81 Take 99; standalone hotfixes for older takes. Mitigations: IPS signature, disable CCCD, change secrets. Checks: Expert mode `vpn cccd status`; SmartConsole script `check-for-CVE-2024-24919.sh`; log query on Mobile Access logins.
- sk1000117, CVE-2026-85102 (https://support.checkpoint.com/results/sk/sk1000117). Created 2026-09-07. CVSS 9.8, no separate vendor severity text on the page (the index shows "Critical"). Affected R81.20, R82, R82.10, Spark R81.10.x and R82.00.x, EoS R80 to R81.10; R82.20 not affected. Fix table per version: LivePatch bundle Take 26, or JHF R82.10 Take 44, R82 Take 126, R81.20 Take 166, R81.10 Take 190; Spark builds 2325 and 4968. Workaround: disable VPN implied rules and allow IKE only from known peers. Checks: Expert mode `cpinfo -y CPupdates`, `cplp list` (expects the CVE listed), `g_all cplp list` on Scalable Platforms, plus a log query.
- sk1000302, CVE-2026-109618 and CVE-2026-109619, PHP in gateway portals (https://support.checkpoint.com/results/sk/sk1000302). Created 2026-10-21. CVSS 9.2. Affected only when specific portal features are on (Mobile Access, SNX, SAML realm, Captive Portal, UserCheck, Zero Phishing). Fixed in JHF R82.20 Take 14, R82.10 Take 52, R82 Take 132, R81.20 Take 174, plus a reboot hotfix. Workaround edits cp-httpd.conf. No "how to check" section.

Pattern: affected versions are always "major version" plus "JHF take" thresholds, sometimes plus a LivePatch take, and exposure often depends on a blade or feature being enabled (Remote Access VPN, Mobile Access, portals).

### 2. Check Point MCP servers

The official repo https://github.com/CheckPointSW/mcp-servers lists 20 servers, including Management, Management Logs, Threat-Prevention, GW CLI, Gaia, Spark Management, CPInfo Analysis, Exposure Management (Argos) and a Documentation Tool (Verified). None is described as an advisory or sk feed (Verified from the README list).

Documentation Tool (`@chkp/documentation-mcp`, package folder packages/documentation-tool). It exposes one tool, `ask-checkpoint-docs`, which takes a free-text question and an optional product enum (s1c default, maas, harmony-sase, customer-support, and others). It requires an Infinity Portal User API Key: CLIENT_ID, SECRET_KEY, and AUTH_URL or REGION. Sources: https://github.com/CheckPointSW/mcp-servers/blob/main/packages/documentation-tool/README.md and src/index.ts (Verified via the GitHub API). It returns a generated answer, not structured advisory records; whether the customer-support product draws on sk articles is Unverified. Not a fit for deterministic version matching.

### 3. Management API: reading gateway version and JHF take

Reference data: the public Management API reference at https://sc1.checkpoint.com/documents/latest/APIs/ is a JS shell that loads data/v2.2/dynamic/apis.json and examples.json (default API version v2.2) (Verified, both files fetched).

- `show-gateways-and-servers` with `details-level full` returns objects with `version` (example "R80"), `operating-system`, `hardware`, `sic-status`, `type` (Verified, example in examples.json).
- `show-simple-gateway` and `show-simple-cluster` return `version` ("Gateway platform version", example "R82.10"), `os-name`, `hardware`, `sic-state` (Verified, apis.json object GatewayCkpReply v2_2 and ClusterReply v2_2).
- No Management API object field named jumbo, hotfix or take exists in apis.json v2.2 (Verified by keyword search: zero hits). So the management object gives major version only.
- Gaia API proxied through management: `gaia-api/v1.2/show-version` with `target` returns `product-version`, `os-build`, `os-kernel-version`, `os-edition` (Verified, examples.json and Gaia API reference data at https://sc1.checkpoint.com/documents/latest/GaiaAPIs/). The only Gaia API field with "jumbo" is `installed-jumbo-take`, and it belongs to ElasticXL member parameters, not a general show command (Verified).
- `show-software-packages-per-targets` with `targets` and `display.installed` exists ("Shows software packages on targets", via CDT/CPUSE) (Verified). Its documented reply schema only lists target name and uid, so whether it reliably lists the installed JHF take is Unverified.
- `run-script` on targets with a script such as `cpinfo -y all` is the community route to the take number, but needs broader permissions than read-only (Unverified, CheckMates search summaries, e.g. https://community.checkpoint.com/t5/API-CLI-Discussion/Version-in-API-including-Jumbo-Hotfixes/m-p/130797, which I could not open: HTTP 403).

Read-only access. `login` accepts `read-only: true` (Verified, apis.json WebApiLoginRequest). An administrator with API key authentication is created in SmartConsole (Authentication Method: API Key, Generate API key, publish), then `mgmt_cli login api-key <key>` (Verified, https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_SecurityManagement_AdminGuide/Topics-SECMG/Configuring_Authentication_through_an_API_Key.htm). Pair it with a "Read Only All" style permission profile (Unverified, not on that page).

Smart-1 Cloud. The admin guide says Settings, then "API & SmartConsole", shows the Management API web request structure (Verified, https://sc1.checkpoint.com/documents/Infinity_Portal/WebAdminGuides/EN/Check-Point-SmartCloud-Admin-Guide/Topics-Smart-1-Cloud/Using-the-Settings.htm), and the permission profile needs "Management API Login" enabled (Unverified, Best Practices page via search summary). URL pattern https://<service-id>.maas.checkpoint.com/<context-or-token>/web_api with API key login is from CheckMates posts (Unverified). Staff say the same Management API commands are supported (Unverified).

### 4. Check Point CVE.org (CNA) records

Counts by NVD publish year for source cve@checkpoint.com: 2024: 4, 2025: 11, 2026: 23; 128 total since 2017 (Verified, NVD API query sourceIdentifier=cve@checkpoint.com, https://services.nvd.nist.gov/rest/json/cves/2.0). Several 2024-numbered IDs were published in 2025.

Record quality (Verified via https://cveawg.mitre.org/api/cve/<id>): 2026 records put JHF thresholds in the free-text version string, for example "R82.10 with Jumbo Hotfix Take 43 or below" (CVE-2026-85102), with one entry per major version, product names like "Quantum Security Gateway" and "Quantum Security Management", CVSS 3.1 or 4.0 metrics, and the sk URL as reference. No `lessThan`/`versionType` ranges and no CPE. Older records are prose (CVE-2024-24919: one sentence listing versions). Not every CVE in a Check Point advisory is Check Point-assigned: the PHP CVEs in sk1000302 did not appear in the Check Point CNA list (Verified by absence in the NVD query).

## SonicWall

### 5. PSIRT advisory data

The PSIRT site https://psirt.global.sonicwall.com is a JS app backed by a public JSON API at https://psirtapi.global.sonicwall.com (Verified, strings in its bundle and live responses):

- RSS: https://psirtapi.global.sonicwall.com/api/v1/feed/rss.xml, 225 items, fields title, link, description, pubDate, cve, advisory_id, last_updated_when, revision_history. No affected or fixed versions in RSS (Verified).
- List: https://psirtapi.global.sonicwall.com/api/v1/vulnsummary/?srch= returns all 225 advisories as JSON with advisory_id, impact, cvss, cvss_vector, cwe, cve, summary, affected_products, vulnerable_products (product family ids), is_workaround_available. No fixed_software in the list (Verified).
- Detail: https://psirtapi.global.sonicwall.com/api/v1/vulndetail/?advisory_id=SNWLID-2026-0014 adds `affected_products`, `fixed_software` and `workaround` as HTML tables, plus `cpe` (empty here) (Verified).
- No CSAF found (Unverified absence; nothing in the bundle or search).

Example SNWLID-2026-0014 (SonicOS multiple CVEs incl. CVE-2026-19868 SAML bypass, possible exploitation): affected Gen7 (TZ 270 to TZ 670, NSa 2700 to 6700, NSsp, NSv 270/470/870) at "7.3.3-7015 and older"; Gen8 (TZ 80, TZ 280 to TZ 680, NSa 2800 to 5800, NSv XS/S/M/L) at "8.2.2-8015 and older"; fixed in 7.3.4-7013 and 8.2.3-8015 (Verified, detail JSON). Note: TZ270 to TZ670 and NSa x700 are Gen 7, not Gen 8.

CVE.org quality: SonicWall CNA records use `product: SonicOS`, `platforms: ["Gen7","Gen8"]`, and strings like "7.3.3-7015 and older versions", `defaultStatus: unknown` (Verified, CVE-2026-19868 and CVE-2024-40766 via cveawg API). NVD counts for PSIRT@sonicwall.com: 2024: 21, 2025: 31, 2026: 49 (Verified, NVD API).

### 6. Reading SonicOS version read-only

- SonicOS API: enabled by default on SonicOS 7, base path /api/sonicos, auth Basic, Digest, CHAP, public key, bearer token; only full admins may use it and only one API session at a time (Verified, https://www.sonicwall.com/support/knowledge-base/introduction-to-sonicos-api/200818060121313/). A read-only admin cannot use it (inference, Unverified). Version endpoint name (e.g. /api/sonicos/version or reporting/system) Unverified; reference at https://sonicos-api.sonicwall.com.
- SSH CLI: `show status` and `show sonicos`/`show system` appear in SonicOS 8 NSv and 7.1 NSv docs (Unverified, search summaries, e.g. https://www.sonicwall.com/support/technical-documentation/docs/sonicos8-nsv_gsg_kvm/Content/Using-cli-safemode/launching-command-line-interface.htm). `show version` on SonicOS 7 is Unverified.
- NSM (cloud): inventory UI shows firmware per device and exports CSV (Unverified, search summary of https://www.sonicwall.com/support/technical-documentation/docs/nsm-administration/Content/topics/Inventory/device-inventory.htm). API auth chain: MySonicWall API key, then generate-cscaccesscode, then POST https://nsm-uswest.sonicwall.com/api/manager/auth/sso for a bearer token valid 8 hours (Unverified, search summary of https://www.sonicwall.com/support/technical-documentation/docs/msw-api_guide/Content/API_Overview/generating-nsm-token-using-msw-api-key.htm). MSW APIs may need enabling by support (Unverified). Inventory endpoint moved to a v2 API on 2026-03-31 (Unverified, NSM SaaS release notes summary).

### 7. Lifecycle

Firmware lifecycle tables per series, e.g. https://www.sonicwall.com/support/product-lifecycle-tables/tz-series/firmware: SonicOS 7.0/7.1 EOS 2025-09-30, 7.3.0 and 7.3.1 EOS 2026-09-30, 7.3.2 General Release EOS 2027-02-23, 7.3.3 no EOS date yet; no 8.x rows on the TZ table (Verified). NSa table at https://www.sonicwall.com/support/product-lifecycle-tables/NSA-Series/Firmware (Unverified contents). Gen 6 is end of support with no further patches (Unverified, https://www.sonicwall.com/support/notices/product-advisory-retire-unsupported-gen-6-firewalls/kA1VN000002iouP0AQ via search).

## Aruba wireless (brief)

HPE Aruba CSAF at https://csaf.arubanetworking.hpe.com/ has year folders plus index.txt and changes.csv at the root; provider-metadata.json returned 404 (Verified). HPESBNW04987 (2026-04-21) covers AOS-8 and AOS-10 Mobility Conductors, Controllers, Gateways with branches like `vers:semver/>=10.3.0.0|<=10.4.1.9` and fixed versions 10.4.1.10, 10.7.2.2 (Verified, https://csaf.arubanetworking.hpe.com/2026/hpe_aruba_networking_-_hpesbnw04987.json). So ArubaOS 8 and AOS 10 are covered with machine-readable ranges. 500-series AP coverage depends on whether the AP runs AOS-10 or Instant AOS-8 (Unverified).

Version reads: controller CLI `show version` on ArubaOS 8 (Unverified, standard command, not fetched). Aruba Central classic API GET /monitoring/v2/aps returns `firmware_version` like "10.3.1.0_82833"; New Central uses /network-monitoring/v1/aps (Unverified, search summary of https://developer.arubanetworks.com and https://arubanetworking.hpe.com/techdocs/new-central/content/api/api-rn/jan-2026-apis.htm).

## Implications

- Check Point is ingestible: poll the public Security Advisories index (CSV export, or the getAllActive JSON once someone confirms it answers outside a browser), then parse CVE.org records for "R<ver> with Jumbo Hotfix Take N or below" strings.
- A Check Point version match needs major version AND JHF take. The Management API gives only major version (`version` field). The take needs `cpinfo -y all`/`cpinfo -y CPupdates` on the gateway, `run-script` (not read-only), or possibly `show-software-packages-per-targets`; plan a CLI collector or an operator-supplied take.
- Model Check Point exposure as conditional: many advisories only bite with Remote Access VPN, Mobile Access or portal blades enabled, and some fixes ship as LivePatch takes (`cplp list`).
- The Documentation MCP is a chat answerer behind Infinity Portal keys; skip it for matching.
- SonicWall is the easiest of the three: public JSON list and detail endpoints plus RSS for change detection, and CNA strings "X.Y.Z-NNNN and older versions" per Gen7/Gen8 platform.
- SonicOS API requires a full admin, which conflicts with read-only; prefer SSH show commands or NSM inventory for version reads, and confirm exact commands on a lab box.
- Use SonicWall lifecycle tables to flag 7.0/7.1 and 7.3.0/7.3.1 (EOS 2026-09-30) and all Gen 6 as unsupported.
- Aruba AOS-8/AOS-10 can reuse the HPE Aruba CSAF parser already planned; version reads via controller `show version` or Central `firmware_version`.
