# Sources for network-security-check

Backend research file. Every check in `settings/checks.yaml` and every rule in `SCORING.md`
points at a key below. Checked 2026-11-07. Tier 1 = vendor PSIRT, vendor docs, CISA, NIST,
NSA, DISA STIG, FIRST. Tier 2 = practitioner material with method shown. Tier 3 = directional
only, never the only support for a check.

"Verified" means the page was opened in this research and the cited text or ID seen. Lines
marked UNVERIFIED are leads, not support. No check rests on an UNVERIFIED line alone.

STIG IDs are given as the rule version (CISC-ND-..., PANW-AG-..., FNFG-FW-...) because those
stay stable between STIG releases. The V-IDs change. STIG text was read through the
cyber.trackr.live mirror of the DISA XCCDF files.

## Scoring

| Key | Source | Tier | What it supports |
|---|---|---|---|
| cisa-bod-26-04 | CISA BOD 26-04 "Prioritizing Security Updates Based on Risk", 2026-06-10, Appendix A Table 1. https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk | 1 | The whole priority model: four inputs (Publicly Exposed, In the KEV, Automatable, Technical Impact) to a deadline (3 days + forensic triage, 3, 14, 60 days, fix on upgrade). Table 1 transcribed from the image on the page. Supersedes BOD 22-01 and BOD 19-02. US government work, so no license limit. |
| cisa-vulnrichment | CISA ADP "Vulnrichment" container in CVE.org records (`containers.adp[].metrics[].other.type = ssvc`). https://github.com/cisagov/vulnrichment | 1 | Per-CVE Automatable and Technical Impact. BOD 26-04 names it as the source for both. Seen live in CVE-2024-3400 and CVE-2023-20198 records. |
| cisa-ssvc-guide | CISA SSVC Guide. https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf | 1 | Definitions of total vs partial control. Says technical impact is "similar to" the CVSS base score idea of severity. That supports the CVSS-vector fallback. |
| cisa-kev | CISA Known Exploited Vulnerabilities catalog, JSON feed. https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 1 | "In the KEV". Feed version 2026.11.06, 1769 entries when checked. Needs a browser-like User-Agent. |
| first-epss | FIRST EPSS FAQ and API. https://www.first.org/epss/faq , https://api.first.org/epss/ | 1 | EPSS = probability of exploitation activity in the next 30 days. FIRST: "There is no universal threshold". Never multiply EPSS by CVSS. KEV wins over EPSS. That is why EPSS only orders findings inside a band here and never moves a deadline. EPSS is v5 (2026-06-15). |
| first-cvss-v4 | FIRST CVSS v4.0 FAQ. https://www.first.org/cvss/v4-0/faq | 1 | "CVSS-B Base scores are not risk, and should not be used alone for patch prioritization." That is why CVSS is shown, not used as the score. |
| first-cvss-spec | FIRST CVSS v3.1 Specification, 2.1.1 Attack Vector. https://www.first.org/cvss/v3.1/specification-document | 1 | Adjacent: "the attack is limited at the protocol level to a logically adjacent topology", e.g. "the same shared physical ... or logical (e.g., local IP subnet) network". Supports scoring AV:A, AV:L and AV:P CVEs as not publicly exposed. Verified 2026-11-07. |
| ssvc-certcc | CERT/CC SSVC deployer model. https://certcc.github.io/SSVC/howto/deployer_tree/ | 1 | Studied, not copied. Its docs are CC BY-NC 4.0, so its decision table is not reproduced in this MIT repo. BOD 26-04 Table 1 is used instead. |
| nist-sematech-outliers | NIST/SEMATECH e-Handbook of Statistical Methods, 1.3.5.17 "Detection of Outliers". https://www.itl.nist.gov/div898/handbook/eda/section3/eda35h.htm | 1 | Spike test: modified z-score M = 0.6745 (x - median) / MAD, potential outlier when abs(M) > 3.5 (Iglewicz and Hoaglin). |
| nist-800-94 | NIST SP 800-94 "Guide to IDPS", 2.3.2 Anomaly-Based Detection. https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-94.pdf | 1 | Comparing activity to a baseline profile, and the warning that this produces false positives. That is why spikes are scored below confirmed exploitation. |

## Advisory data

| Key | Source | Tier | Notes |
|---|---|---|---|
| cve-org-api | CVE Services record API. https://cveawg.mitre.org/api/cve/{CVE-ID} | 1 | CVE JSON 5 record: the vendor's (CNA) affected versions, CVSS, CISA ADP SSVC and KEV data. Primary version data for every vendor except Palo Alto. |
| nvd-api | NVD CVE API 2.0. https://nvd.nist.gov/developers/vulnerabilities | 1 | Used to find CVE IDs per product (virtualMatchString on the CPE, plus keywordSearch). 5 requests per 30 s without a key. Since 2026-04-15 NVD enriches mainly KEV and priority software (https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth), so CPE data is a fallback here, not the main source. "This product uses data from the NVD API but is not endorsed or certified by the NVD." |
| panw-json | Palo Alto security advisories JSON. https://security.paloaltonetworks.com/json/{CVE-ID} | 1 | CVE JSON 5 plus `x_affectedList`, Palo Alto's list of affected releases. Tested on CVE-2024-3400 on 2026-11-07, against the fixed versions in Palo Alto's advisory (10.2.7-h8, 10.2.8-h3, 10.2.9-h1): (1) CVE.org's copy of the record uses one range per train (10.2.0 to 10.2.9-h1), which flags the fixed 10.2.7-h8 as affected; (2) `x_affectedList` leaves out 10.2.8, which was affected; (3) Palo Alto's own ranges list the first fixed hotfix of each maintenance release, but read strictly per the CVE 5 schema they mark 10.2.7-h3 unaffected. So for PAN-OS a version counts as affected when it is in the list OR when it is older than the fix on its own maintenance release (Palo Alto's ranges read per release). Pinned by `test_panos_cve_2024_3400`. |
| cisco-openvuln | Cisco PSIRT openVuln API, OSType/version lookup. https://developer.cisco.com/docs/psirt/ | 1 | Not used yet: needs an OAuth client per user. Better than CVE ranges for Cisco feature/train mapping. Candidate adapter (see architecture doc). |
| cisco-csaf | Cisco CSAF provider metadata. https://www.cisco.com/.well-known/csaf/provider-metadata.json | 1 | Verified. Not used yet. |
| fortinet-psirt | FortiGuard PSIRT, RSS fortiguard.com/rss/ir.xml, CVRF per advisory. https://www.fortiguard.com/psirt | 1 | Not used: the CVE.org records Fortinet publishes carry clean semver ranges (tested on CVE-2024-21762). |
| cisco-sa-feature-conditions | The "Vulnerable Products" section of each Cisco advisory, read 2026-11-13: cisco-sa-http-code-exec-WmfP3h3O (CVE-2025-20363, IOS-XE only with Remote Access SSL VPN: `crypto ssl policy` without `shutdown`), cisco-sa-ios-xe-cmd-inject-rPJM8BGL (CVE-2025-20334, `ip http server` or `ip http secure-server`), cisco-sa-webui-xss-VWyDgjOU (CVE-2025-20240, HTTP server plus Web Authentication: `ip admission name ... proxy http` or `parameter-map type webauth`), cisco-sa-nbar-dos-LAvwTmeT (CVE-2025-20315, `ip nbar classification tunneled-traffic capwap`), cisco-sa-iosxe-bing-MGHrFAkd (CVE-2026-20263, `netconf beep listener`), cisco-sa-ios-xmcp-thbAr34t (CVE-2026-20301, `service-routing xmcp listen`), cisco-sa-iosxe_infodis-6J847uEB (CVE-2026-20115, Meraki dashboard management). Base https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/ | 1 | Y | Feature keywords and on/off conditions in platforms.yaml (cisco_ios) and vendor_ios.py. A CVE whose feature is off goes to "next upgrade". Gaps: a BEEP listener made with the exec command `bingd device` is not in the config, so it can't be seen. |

## Checks

| Key | Source | Tier | Verified | Supports |
|---|---|---|---|---|
| cisco-sa-iosxe-webui | Cisco advisory cisco-sa-iosxe-webui-privesc-j22SaA4z (CVE-2023-20198, CVE-2023-20273). https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z | 1 | Y | IOS-HTTP-SERVER. Cisco: `no ip http server` and `no ip http secure-server` remove the attack vector. CVE-2023-20198 is in KEV (added 2023-10-16). |
| stig-ios-http | DISA Cisco IOS XE Router NDM STIG V3R7, CISC-ND-000470. https://cyber.trackr.live/api/stig/Cisco_IOS_XE_Router_NDM/3/7/V-215823 | 1 | Y | IOS-HTTP-SERVER. `ip http server` listed among nonsecure services that must be absent. |
| stig-ios-vty-acl | DISA Cisco IOS XE Router NDM STIG V3R7, CISC-ND-000140 (V-215812; Switch NDM V-220523). https://cyber.trackr.live/api/stig/Cisco_IOS_XE_Router_NDM/3/7/V-215812 | 1 | Y | IOS-VTY-ACL and IOS-TELNET. Check text: `line vty` with `access-class ... in` and `transport input ssh`. |
| stig-iosxe-ndm-ssh | DISA Cisco IOS XE Router NDM STIG V3R7, CISC-ND-001200 and CISC-ND-001210. https://cyber.trackr.live/api/stig/Cisco_IOS_XE_Router_NDM/3/7/V-215845 | 1 | Y | IOS-SSH-V1, IOS-TELNET. Check text includes `ip ssh version 2`. |
| stig-ios-rtr-auth | DISA Cisco IOS XE Router RTR STIG V3R5, CISC-RT-000050 (V-216645, CAT II), "enable routing protocol authentication using FIPS 198-1 algorithms" with key lifetimes of 180 days or less. https://cyber.trackr.live/api/stig/Cisco_IOS_XE_Router_RTR/3/5/V-216645 (DISA zip U_Cisco_IOS-XE_Router_Y26M04_STIG.zip) | 1 | Y | IOS-ROUTING-NO-AUTH and IOS-ROUTING-WEAK-AUTH. Check: neighbor authentication enabled for every routing protocol, with a FIPS 198-1 algorithm; MD5 is not FIPS compliant and MD5-only protocols are a permanent finding. Examples use key chains with hmac-sha-256 (OSPF key-chain, BGP TCP-AO). Rationale: a rogue router advertising false routes ("traffic attraction"). Graded: none and clear text (NO-AUTH), MD5 or a key chain with no algorithm (WEAK-AUTH), HMAC-SHA-1/256/384/512 or AES-CMAC (passes). Key lifetime is not graded yet. Read 2026-11-13. |
| cisco-harden-ios | Cisco "Harden IOS Devices" (Document ID 13608): "Routing Protocol Authentication and Verification with Message Digest 5" and "BGP Peer Authentication with MD5". https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html | 1 | Y | IOS-ROUTING-NO-AUTH. Gives the config forms the check recognises: `ip authentication mode eigrp <as> md5` + key chain, `ip ospf message-digest-key` + `area 0 authentication message-digest`, `neighbor <ip> password`. It still shows MD5 as the recommended form; the STIG is the newer, stricter bar, so MD5 is graded weak. Read 2026-11-13. |
| stig-ios-snmp | DISA Cisco IOS XE Router NDM STIG V3R7, CISC-ND-001130 and CISC-ND-001140. https://cyber.trackr.live/api/stig/Cisco_IOS_XE_Router_NDM/3/7/V-215841 | 1 | Y | IOS-SNMP-COMMUNITY. SNMPv3 with authentication and encryption. |
| stig-ios-logging | DISA Cisco IOS XE Router NDM STIG V3R7, CISC-ND-001450. https://cyber.trackr.live/api/stig/Cisco_IOS_XE_Router_NDM/3/7/V-220139 | 1 | Y | IOS-NO-REMOTE-LOG. At least two syslog servers. |
| nsa-nisg | NSA "Network Infrastructure Security Guide". March 2022 edition PP-22-0266 read: 5.5 store passwords with secure algorithms, 6.2 centralized remote log servers, 7.1 disable clear text administration services, 7.8 remove SNMP read-write community strings, 7.11.1 SSH, 7.11.3 SNMP. June 2022 edition (U/OO/118623-22) https://media.defense.gov/2022/Jun/15/2003018261/-1/-1/0/CTR_NSA_NETWORK_INFRASTRUCTURE_SECURITY_GUIDE_20220615.PDF returned 403 from this environment. | 1 | Partial | General hardening support for IOS, ASA and Junos checks. Section numbers are from the March edition and may shift in June. Re-check in a browser before quoting a number in public content. |
| nsa-nisg-segmentation | NSA NISG 2.2 "Group similar network systems". | 1 | Y (heading) | IOS-SEGMENT-ROUTED, FGT-SEGMENT, PAN-SEGMENT. Segmentation against lateral movement. |
| nsa-cisco-password-types | NSA CSI "Cisco Password Types: Best Practices", PP-22-0178, Feb 2022. https://media.defense.gov/2022/Feb/17/2002940795/-1/-1/0/CSI_CISCO_PASSWORD_TYPES_BEST_PRACTICES_20220217.PDF | 1 | N (403 from here; URL and summary from NSA's release) | IOS-PASSWORD-STORAGE, together with nsa-nisg 5.5 (verified heading). Type 8 recommended; type 5 not NIST approved; type 7 reversible. |
| cisco-smart-install | Cisco advisories cisco-sa-20180328-smi2 (CVE-2018-0171, RCE, TCP 4786) and cisco-sa-20180328-smi (fix: `no vstack`). https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2 | 1 | Y | IOS-SMART-INSTALL. CVE-2018-0171 is in KEV. |
| cisa-ta18-106a | CISA alert TA18-106A, Russian state-sponsored actors targeting network infrastructure. https://www.cisa.gov/news-events/alerts/2018/04/16/russian-state-sponsored-cyber-actors-targeting-network-infrastructure-devices | 1 | Y | known_exploited on IOS-SMART-INSTALL and the SNMP checks: lists Smart Install and SNMP-enabled devices as targeted, advises disabling SNMPv1/v2c. Also CVE-2017-6742 (IOS SNMP RCE) in KEV since 2023-04-19. |
| nist-800-41 | NIST SP 800-41r1 "Guidelines on Firewalls and Firewall Policy", section 4 (deny by default) and 5.2.3 (logging). https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41r1.pdf | 1 | Y | Any-any rules, inbound any-service rules, segmentation, logging. 5.2.3 supports logging but does not require logging every allow rule, so the no-log checks carry the lowest weights. |
| stig-panw-alg | DISA Palo Alto Networks ALG STIG V3R4, PANW-AG-000051 (V-228845). https://cyber.trackr.live/api/stig/Palo_Alto_Networks_ALG/3/4/V-228845 | 1 | Y | PAN-ANY-ANY, PAN-INBOUND-ANY-SERVICE. Finding if Source, Destination and Application are all any with action allow, or a rule allows all traffic inbound or outbound. |
| stig-fortigate-fw | DISA Fortinet FortiGate Firewall STIG V1R5, FNFG-FW-000005 (V-234133). https://cyber.trackr.live/api/stig/Fortinet_FortiGate_Firewall/1/5/V-234133 | 1 | Y | FGT-ANY-ANY. Finding if interface any and address all with ACCEPT. |
| cisa-bod-23-02 | CISA BOD 23-02 "Mitigating the Risk from Internet-Exposed Management Interfaces". https://www.cisa.gov/news-events/directives/binding-operational-directive-23-02 | 1 | Y | FGT-MGMT-ON-WAN, PAN-MGMT-ON-UNTRUST, ASA-MGMT-ON-OUTSIDE. Remove networked management interfaces from the internet, or put them behind a separate policy enforcement point. Scope names routers, switches, firewalls and VPN concentrators. |
| panw-mgmt-access | Palo Alto docs, Network > Network Profiles > Interface Mgmt. https://docs.paloaltonetworks.com/ngfw/help/11-1/network/network-network-profiles/network-network-profiles-interface-mgmt | 1 | Y | PAN-MGMT-ON-UNTRUST: "Do not attach an interface management profile that allows Telnet, SSH, HTTP, or HTTPS to an interface that allows access from the internet or from other untrusted zones". |
| panw-best-practice | Palo Alto Best Practices, Internet Gateway, "Create Best Practice Security Profiles". https://docs.paloaltonetworks.com/best-practices/internet-gateway-best-practices/best-practice-internet-gateway-security-policy/create-best-practice-security-profiles | 1 | Y | PAN-INBOUND-NO-PROFILE: "Attach Security profiles to all Security policy rules that allow traffic". |
| fortinet-hardening | Fortinet "Hardening your FortiGate", System administrator best practices (6.4). https://docs.fortinet.com/document/fortigate/6.4.0/hardening-your-fortigate/582009 | 1 | Y (6.4) | FGT-MGMT-ON-WAN: "When possible, don't allow administration access on the external (Internet-facing) interface", "never allow HTTP or Telnet administrative access". FGT-INBOUND-NO-IPS (security profiles on policies). Current-release page not found; 6.4 wording used. |
| fortinet-trusthost | Same Fortinet guide, trusted hosts. Plus Fortinet community note that trusthost still exposes the login page, so local-in policy is the stronger control (tier 2). https://community.fortinet.com/t5/FortiGate/Technical-Tip-Limitations-of-trusted-hosts-and-local-in-policies/ta-p/302262 | 1/2 | Y | FGT-ADMIN-NO-TRUSTHOST. |
| cisa-stopransomware | CISA #StopRansomware Guide, Part 1, internet-facing vulnerabilities and misconfigurations. https://www.cisa.gov/stopransomware/ransomware-guide | 1 | Y (web page) | FGT-VIP-RISKY, PAN-NAT-RISKY, ASA-NAT-RISKY, FGT-INBOUND-ANY-SERVICE: "Do not expose services, such as remote desktop protocol, on the web"; block SMB 445 at the perimeter. known_exploited on the NAT checks rests on this guide naming exposed RDP as a ransomware initial access vector. |
| nist-800-92 | NIST SP 800-92 "Guide to Computer Security Log Management". https://csrc.nist.gov/pubs/sp/800/92/final | 1 | Y (landing page) | No-remote-log and no-log checks. Low weights. |

### KEV entries behind "known_exploited: true" on config checks

Checked against the KEV feed of 2026-11-06. A config check is marked known_exploited only
when attackers are documented abusing that same exposure.

| Check | KEV entries (date added, ransomware use) |
|---|---|
| IOS-HTTP-SERVER | CVE-2023-20198 IOS XE Web UI (2023-10-16) |
| IOS-SMART-INSTALL | CVE-2018-0171 Smart Install RCE (2021-11-03) |
| IOS-SNMP-COMMUNITY, JUNOS-SNMP-COMMUNITY, ASA-SNMP-COMMUNITY | CVE-2017-6742 IOS SNMP RCE (2023-04-19), plus TA18-106A |
| FGT-MGMT-ON-WAN | CVE-2022-40684 admin auth bypass (2022-10-11, Known), CVE-2024-55591 (2025-01-14, Known) |
| PAN-MGMT-ON-UNTRUST | CVE-2024-0012 and CVE-2024-9474 management interface (2024-11-18, Known) |
| ASA-MGMT-ON-OUTSIDE | CVE-2025-20333, CVE-2025-20362 web services (2025-09-25), CVE-2024-20353 (2024-04-24) |
| JUNOS-HTTP | CVE-2023-36845 J-Web (2023-11-13) |

## Not used as support

- CIS Benchmarks and CIS Controls: CIS terms bar redistributing Benchmark text and ask that
  reuse be cleared with CIS legal. No check depends on CIS. Benchmarks can be cited later by
  name and recommendation title only. The CIS Controls 12.2 / 13.4 titles were found only on
  third-party pages (UNVERIFIED), so they are not cited.
- Community MCP servers and blog posts about firewall audits (tier 3): read for ideas only.

## Studied, credited, not copied

- CERT/CC SSVC (decision points and the deployer model) shaped the thinking. BOD 26-04 is the
  table actually used.
- Palo Alto Policy Optimizer, Fortinet policy hit counts, ASA `show access-list` hit counts:
  the runtime way to find unused rules. Not done here because snapshots hold config, not hit
  counts. Listed as follow-up work.
