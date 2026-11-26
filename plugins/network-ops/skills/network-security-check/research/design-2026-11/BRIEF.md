# Design brief: network-security-check v2 (research for the grill session)

Written 2026-11-24 from three research passes (each fact tagged Verified/Unverified, with URLs):
`research-cisco.md`, `research-vendors.md`, `research-scoring-skills.md` in this folder.
Nothing in the skill has changed yet. This brief lists what we now know and what needs deciding.

## What the research changed

| Earlier assumption | What we found | Effect |
|---|---|---|
| Cisco CSAF can be the main free source | Cisco CSAF lists affected versions one by one (145 in a sample) with **no fixed versions**; Cisco's severity rating and the "how to check" show commands are free text | CSAF can confirm "affected", not "upgrade to X". openVuln is needed for first-fixed releases. |
| openVuln is optional polish | openVuln returns advisories per OS type and version from the Software Checker data, with Cisco's rating, CVSS, CVEs, bug IDs; first fixed appears in sample output but not the published schema. Free app credentials (apiconsole.cisco.com), limits 5/s, 30/min, 5000/day. Old per-OS endpoints retiring. | Recommended for Cisco users; skill still works without it. Confirm first-fixed field before relying on it. |
| One CSAF reader covers most vendors | Only Fortinet (not strictly valid), Palo Alto and HPE Aruba publish CSAF; no provider-metadata.json from any of them; Juniper, Arista, Check Point, SonicWall, Meraki: none. BSI's CSAF lister has none of them. | **CVE JSON 5.0 (CVEProject cvelistV5) is the one format that covers every vendor.** Palo Alto, Juniper and Arista fill in configurations, workarounds and solutions there. |
| Add vendor severity on top of CVSS | Cisco's rating is derived from CVSS bands; adding both double counts. Palo Alto and Juniper add CVSS v4 providerUrgency; HPE adds aggregate_severity. | One severity input (the vendor's own CVSS vector when present, else NVD's); vendor rating shown as a label or used as a documented override reason. |
| EPSS v4 | EPSS v5 is live (mid-2026). FIRST: no universal threshold; multiplying EPSS by CVSS "is never a good idea". | EPSS as a tie-breaker inside a priority, version read from the data, not hard-coded. |
| BOD 26-04 table as built | BOD 26-04 is real (2026-06-10, replaces BOD 19-02 and 22-01), four factors confirmed, informed by SSVC, no EPSS. Table 1 is an image. | Re-transcribe Table 1 by hand from the image and test against it. |
| Cisco EoX / Software Suggestion APIs for lifecycle | Both need a Smart Net Total Care contract or partner status. | Optional only; hand-checked lifecycle table stays the default. |
| ASA is dead | ASA software is current (9.24) on Secure Firewall in ASA mode and ASAv. 5525/45/55-X last date of support 2025-09-30; 5506/08/16-X 2026-08-31. CISA ED 25-03 (2025-09-25, updated 2026-04-23) targets ASA/Firepower. | Keep ASA for CVEs and end-of-support (including hardware), no new ASA config work. |
| Official advisory MCP servers | None official. Cisco PSIRT's GitHub has `openvuln-mcp`, labeled community-supported. Juniper, Arista and Check Point have official MCP servers, but for device access, not advisories. | No MCP dependency. Device MCP servers are a possible future collector path (Check Point especially). |
| End-of-life data is scrapable | HTML only everywhere; Fortinet's portal needs login; Arista's matrix is an image; FortiOS 7.0/7.2/8.0 dates only on third-party endoflife.date. | Keep the hand-checked lifecycle table with as-of dates and sources. |

## Constraints we must honor

- **Licensing:** implement scoring from CISA's SSVC guide and BOD text (US government work), not CERT/CC SSVC (CC BY-NC). KEV and CISA Vulnrichment are CC0. CVSS: attribute FIRST and print the vector with the score. The Python `cvss` library is LGPL-3.0: depend on it, do not copy it. Don't use Tenable's names (VPR, ACR, AES) or claim equivalence.
- **Skill structure (Anthropic guidance, Agent Skills spec):** SKILL.md under 500 lines as a table of contents; references one level deep, split by domain (vendor), table of contents when over 100 lines; deterministic work in scripts; script paths via `${CLAUDE_SKILL_DIR}`; at least three evals, run on Haiku, Sonnet and Opus, including an offline case.
- **Secrets:** plugin `userConfig` with `sensitive: true` stores keys in the OS secure store, but those values are not in the Bash environment. A Python script needs the key from an environment variable or the OS keychain (keyring), set by the user in their own terminal.
- **Fetching:** plain HTTP to www.cisco.com gets an Akamai 403; the fetcher needs a proper client (or the API).

## Decisions for the grill session

1. **Priority model.** Research suggests: P-level from the decision table first (exposure, KEV, automatable, total impact), then a 0-100 score that orders findings within a P-level, with NIST SP 800-30 bands as the citable basis. A pure weighted sum can let a KEV-plus-exposed finding rank below a high-CVSS internal one. Which do you want?
2. **Severity input.** One CVSS (vendor's vector preferred) plus the vendor rating as a label and override reason. Agree?
3. **Asset criticality.** Three levels (SSVC Mission Prevalence: Essential, Support, Minimal, or FIPS 199 High/Moderate/Low), set per device in the inventory, default for unset devices?
4. **Applicability states.** Confirmed affected / unconfirmed (with check commands and workaround) / not affected (hidden, counted, listed in an appendix). Where the vendor conditions are free text, extracting them needs a per-vendor parser of CVE JSON 5.0 `configurations` text and Cisco CSAF notes. How far to go per vendor?
5. **Advisory source order per vendor.** Proposal: Cisco openVuln (key) > Cisco CSAF > CVE.org; Palo Alto JSON > CVE.org; HPE Aruba CSAF > CVE.org; everyone else CVE.org (JSON 5.0) with NVD only for CPE matching. Flag disagreements.
6. **Cisco key setup.** Optional `userConfig` plus keyring, with the README saying what the key adds (exact Cisco matching and first fixed). Is "works without, better with" the right message?
7. **Skill layout.** One skill; vendor guidance in `references/vendors/*.md`; vendor code in `scripts/vendors/`; scoring tables in `references/`. Any reason to split now?
8. **Config findings on the same P scale as CVEs?** (So "telnet on the edge" and a KEV CVE rank in one list.)
9. **Evals.** What are the three or more scenarios (clean network, edge device with a KEV CVE, offline run, unconfirmed applicability)?
