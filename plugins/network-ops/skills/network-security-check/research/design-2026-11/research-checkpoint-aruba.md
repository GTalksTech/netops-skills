# Research: Check Point (Gaia, SMS/MDS) and HPE Aruba (AOS-CX, ArubaOS-Switch)

Date: 2026-11-26. Read-only web research for the network-security-check skill.

Labels: "Verified" means the page itself was fetched and read in this session. "Unverified" means the fact came from a search-result summary, a community post that could not be opened, or a page only partly read. Quotes are short (under 15 words). Firecrawl was used once, for the CheckMates evaluation-license thread (WebFetch got HTTP 403). No PDFs were read.

## Check Point

### 1. Lab and evaluation licensing

Every new Gaia install (appliance or VM) carries a 15-day Plug-n-Play evaluation license. A factory-defaulted SMB (Spark) appliance gets 30 days. Source: CheckMates how-to by PhoneBoy (Check Point admin), 2018-10-02. https://community.checkpoint.com/t5/General-Topics/How-to-Request-an-Evaluation-License-for-Firewall-and-Endpoint/td-p/40391 (Verified, read via Firecrawl.)

After that, an evaluation license is generated in UserCenter under Product Evaluation (https://usercenter.checkpoint.com/ucapps/prodeval). The same post says these evaluations "expire 30 days from date of generation". The recommended "All-In-One Evaluation" covers Security Management with Multi-Domain, a gateway with all blades (up to 8 cores on open server), unlimited remote access, and Endpoint for 100 users. The license is bound to the management server IP. Same URL as above. (Verified.)

Renewal: the post says to generate a new evaluation at the end of the period, or ask the local Check Point office for a longer-term one. In the same thread, a Check Point MVP (Lari Luoma, 2022-12-21) wrote you "cannot extend EVAL licenses" but need a new one each 30 days, and a Check Point admin (_Val_, 2020-12-29) answered "yes" to whether it can be used for a lab. A reply from Ben Dunkley notes the All-In-One eval includes only a single 8-core gateway license, so a cluster lab needs one eval per gateway. Same URL. (Verified.) In practice that means repeated 30-day generation is the accepted lab path, though no page states an official cap or a formal permission for indefinite reuse. (Unverified that there is no cap.)

Longer lab licenses: a community post says a 1-year lab license can be requested by partners and CCSPs, and EA participants have received 3-month trials. https://community.checkpoint.com/t5/Security-Gateways/Test-License-for-lab-use/m-p/111863 (Unverified, page not opened.) I found no public "Check Point for education", SecureAcademy, or NFR program offering a free renewable lab license for individuals. (Unverified, absence of evidence only.)

An R82 user reports SmartConsole still opens and the config is still editable after the eval expires. https://community.checkpoint.com/t5/General-Topics/License-and-Support-Expired-Behaviors/td-p/220411 (Unverified.) This matters for a read-only scanner: config and version reads may keep working on an expired lab, but this is not confirmed.

### 2. Running Gaia in Cisco CML

A ready-made CML node definition for Gaia exists in the official community repo: `node-definitions/check-point/gaia/gaia.yaml`. https://github.com/CiscoDevNet/cml-community/tree/master/node-definitions/check-point/gaia (Verified.) Its values: id `gaia`, 6144 MB RAM, 4 vCPUs, virtio NIC and disk drivers, 9 interfaces (eth0 to eth8), boot timeout 250 s, cloud-config with a placeholder hostname, no Gaia version stated. https://raw.githubusercontent.com/CiscoDevNet/cml-community/master/node-definitions/check-point/gaia/gaia.yaml (Verified.)

Cisco says community node definitions carry no guarantee for any CML or image version, and you must license third-party images yourself. https://developer.cisco.com/docs/modeling-labs/vm-images-for-cml-labs/ and https://developer.cisco.com/docs/modeling-labs/creating-a-new-node-definition/ (Unverified, from search summaries.)

Images: sk158292 "Cloud Firewall - Private Cloud Deployment Images for VMware and KVM" lists qcow2 (KVM, OpenStack, Nutanix, Proxmox) and OVA images for R81.20, R82 and R82.10 in two types, Gateway Only and Management plus Gateway (All-In-One), and R82.20 images for Management, Multi-Domain Server and Gateway Only. Some images have no preset admin password and need it set at first boot console or via cloud-init (sk179752); others default to admin/admin with a forced change. The page warns the images are vulnerable to CVE-2024-24919 (sk182336), so they ship below current JHF. https://support.checkpoint.com/results/sk/sk158292 (Verified.) Downloads go through the Support Center; whether a free account suffices was not stated. (Unverified.)

Community reports say the KVM qcow2 has a randomized password unless cloud-init sets one, and that R81.20 changed the cloud-init process. https://community.checkpoint.com/t5/Cloud-Firewall/Recommended-patching-process-for-private-cloud-images/td-p/202395 and https://community.checkpoint.com/t5/Firewall-Security-Management/R81-20-SMS-in-Proxmox/td-p/203682 (Unverified.) A Cisco Community thread asked for a Check Point CML YAML in 2023 with no answer visible. https://community.cisco.com/t5/cisco-modeling-labs-discussions/cml-checkpoint-node-image-yaml-file/td-p/4909702 (Unverified, 403.)

Sizing from the R82 Release Notes, open server or VM: Standalone (gateway plus management) needs 4 cores, 8 GB RAM, 110 GB disk minimum (1 TB recommended). Security Management Server 2 cores, 8 GB, 110 GB. Security Gateway 2 cores, 8 GB, 110 GB. Multi-Domain Server 8 cores, 32 GB, 100 GB plus 110 GB per domain. At least 10 GB free in /var/log. https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_RN/Content/Topics-RN/HW-Requirements-Open-Server-VM.htm (Verified.) The CML community YAML's 6 GB is below this 8 GB floor. Supported hypervisors are delegated to the HCL; the R82 Supported Environments page does not name KVM. https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_RN/Content/Topics-RN/Supported-Environments.htm (Verified.)

### 3. Advisory data and version detection

Where Check Point publishes product vulnerabilities:
- The Security Advisories page at support.checkpoint.com/security-advisories, no login, each CVE linking to its sk or the Jumbo HFA documentation, about 170 CVEs since 2021 at launch, no RSS and only basic filtering. https://community.checkpoint.com/t5/General-Topics/New-Security-Advisories-Page/m-p/241145 (Unverified, from search summary; the advisories page itself rendered empty to WebFetch, likely JavaScript.) https://support.checkpoint.com/security-advisories (Verified that it returns only a shell to a non-JS fetch.)
- Per-CVE sk articles (for example sk1000117, sk1000118, sk185169). (Unverified, named in search results.)
- The Jumbo HFA "All Resolved Issues" page per release, which lists CVE fixes with sk references under a per-Take heading. R81.20 example: Take 174, released 12 November 2026, "Resolves CVE-2026-109618 and CVE-2026-109619" (sk1000302). https://sc1.checkpoint.com/documents/Jumbo_HFA/R81.20/All_Resolved_Issues.html (Verified, first 100k of 237k characters read.)
- advisories.checkpoint.com is a different thing: CPAI-numbered IPS protection advisories for third-party CVEs (GeoServer, Apache), not Check Point product flaws, with an email subscription and no feed shown. https://advisories.checkpoint.com/advisories/ (Verified.) Do not use it for product matching.
- No CSAF, JSON, or API feed for Check Point product advisories was found. (Unverified, absence of evidence.)

How affected versions are expressed: major version plus Jumbo Take. Government digests restate them as, for example, R81.20 through Take 166, R82 through Take 126, R82.10 through Take 44. https://cyber.gc.ca/en/alerts-advisories/check-point-security-advisory-av26-933 (Unverified, from search summary.) So the matcher needs (major version, product role: gateway vs management vs log server, installed JHF Take).

Reading the version on the device:
- Gaia clish `show version all` prints Product version, OS build, OS kernel version, OS edition. It does not print the JHF Take. https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/CP_R82.10_Gaia_AdminGuide/Content/Topics-GAG/Gaia-Clish-Expert-Mode.htm (Unverified, from search summary.)
- Clish `show installer packages installed` lists installed packages and hotfixes (CPUSE). https://sc1.checkpoint.com/documents/CPUSE/Content/Topics/View-Installed-Packages.htm (Unverified, from search summary.)
- Expert mode `cpinfo -y all` shows lines such as `HOTFIX_R80_30_JUMBO_HF_MAIN Take: 155`; `cpstat os -f updates` also reports the Take. https://community.checkpoint.com/t5/API-CLI-Discussion/Version-in-API-including-Jumbo-Hotfixes/td-p/130797 (Unverified, 403.) `fw ver` gives the major version and build. (Unverified, not checked this session.)
- Management API `show-gateways-and-servers` returns the major version but not the Take; the community workaround is `run-script` with cpinfo. sk184851 describes SmartConsole showing the JHF as empty or N/A. https://community.checkpoint.com/t5/API-CLI-Discussion/Query-gateway-version-amp-take/m-p/280077 and https://support.checkpoint.com/results/sk/sk184851 (Unverified.) Note `run-script` executes on the target, which is not strictly read-only from a policy view.

### 4. Read-only access

Management API: the predefined "Read Only All" permission profile gives read with no write; API access also needs the "Management API Login" permission; an administrator can use API Key authentication and log in with `mgmt_cli login api-key ...`. https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_SecurityManagement_AdminGuide/Topics-SECMG/Configuring_Authentication_through_an_API_Key.htm and https://sc1.checkpoint.com/documents/R82.20/WebAdminGuides/EN/CP_R82.20_SecurityManagement_AdminGuide/Content/Topics-SECMG/Assigning-Permission-Profiles-to-Administrators.htm (Unverified, from search summaries.) There is no API-only profile, so that admin can also open SmartConsole. (Unverified.)

Gaia clish RBA: roles are built with `add rba role <name> domain-type System readonly-features <list>`; read-only users can run show commands but not set, add, or delete. R82.20 has a predefined `monitorRole` with read-only access to all features. https://sc1.checkpoint.com/documents/R82.20/WebAdminGuides/EN/CP_R82.20_Gaia_AdminGuide/Content/Topics-GAG/Roles-Gaia-Clish.htm (Unverified, from search summary.) Whether `show version all` needs a specific feature was not found. (Unverified.) One user reports a read-only Gaia login cannot run scripts or gaia_api commands. https://community.checkpoint.com/t5/API-CLI-Discussion/Read-Only-account-for-Gaia-API/td-p/63508 (Unverified.)

Expert mode: needed for `cpinfo -y all` and `cpstat`, which are the reliable JHF Take sources on the device. Expert mode is root-equivalent, which conflicts with least privilege. (Unverified as a hard rule; inferred from the sources above.)

Logs: the Management API `show-logs` needs log indexing, returns at most 100 records per call, and staff point to Log Exporter (sk122323) for bulk. https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_LoggingAndMonitoring_AdminGuide/Content/Topics-LMG/API-for-Logs.htm and https://community.checkpoint.com/t5/API-CLI-Discussion/API-show-logs/td-p/129384 (Unverified.)

Official MCP servers (CheckPointSW/mcp-servers, TypeScript monorepo, 20 packages), relevant ones: `@chkp/quantum-management-mcp` (policies, objects, topology), `@chkp/management-logs-mcp` (connection and audit logs), `@chkp/threat-prevention-mcp` (TP policies, IPS updates, IOC feeds), `@chkp/https-inspection-mcp`, `@chkp/quantum-gw-cli-mcp` (gateway diagnostics), `@chkp/quantum-gaia-mcp` (Gaia network and interface config), `@chkp/cpinfo-analysis-mcp`, `@chkp/policy-insights-mcp`, `@chkp/documentation-mcp`. The README does not label any server read-only; auth is per-package. https://github.com/CheckPointSW/mcp-servers (Verified.) Read-only scope therefore comes from the admin's permission profile, not the MCP server. (Inferred.)

### 5. Supported releases and end of support

Check Point Support Life Cycle Policy, Security Gateway and Management table: R81.10 support until March 2026 (now ended), R81.20 until May 2027, R82 until April 2029, R82.10 until June 2030, R82.20 (GA September 2026) until September 2030. R80.40 ended April 2024, R81 October 2024. https://www.checkpoint.com/support-services/support-life-cycle-policy/ (Verified.) Older cached English copies showed R81.20 to November 2026 and R82 to October 2028, so the page changes and should be re-read, not hardcoded. (Unverified for the older copies.)

## HPE Aruba

### 6. CSAF coverage

https://csaf.arubanetworking.hpe.com/ is a plain directory listing with year folders 2003 to 2026, plus `index.txt` and `changes.csv` (both last modified 2026-11-25 19:55 per the listing). (Verified.) The standard `/.well-known/csaf/provider-metadata.json` returned 404. (Verified.) `index.txt` lists 115 JSON files from 2022 to 2026; names move from `hpe_aruba_networking_-_2022-001.json` to `hpe_aruba_networking_-_hpesbnw04888.json` to `hpe_networking_-_hpesbnw05134.json` in 2026, and one 2025 ID appears twice with different case. https://csaf.arubanetworking.hpe.com/index.txt (Verified.) Pre-2022 years appear to hold text advisories only. (Unverified.)

AOS-CX example, hpesbnw05134 (2026-09-01, CSAF, "Multiple Vulnerabilities in HPE Networking AOS-CX"): affected as `product_version_range` with `vers:semver/>=10.17.0000|<=10.17.1021`, fixed as `product_version` "AOS-CX 10.17.1030"; branches 10.18, 10.17, 10.16, 10.13, 10.10. The product name differs within one file ("HPE Networking AOS-CX" vs "HPE Aruba Networking AOS-CX"). https://csaf.arubanetworking.hpe.com/2026/hpe_networking_-_hpesbnw05134.json (Verified, first 100k of 167k characters.)

ArubaOS-Switch example, ARUBA-PSA-2023-013 (CSAF 2.0), product "ArubaOS-S Switch", models listed as a single string covering 2530 through 5400R. Ranges keep the train prefix inside the semver string, for example `vers:semver/>=KB/WC/YA/YB/YC.16.11.0000|<=KB/WC/YA/YB/YC.16.11.0012`, plus open ranges such as `>=16.05.0000|<=16.05.9999` for unfixed branches, and fixed `KB/WC/YA/YB/YC.16.11.0013`. Some entries have mismatched bounds and a name typo ("Aruba OS-S Switch"). https://csaf.arubanetworking.hpe.com/2023/hpe_aruba_networking_-_2023-013.json (Verified.) The text twin says unlisted branches "will not receive fixes" and lists only supported branches in Resolution. https://csaf.arubanetworking.hpe.com/2023/hpe_aruba_networking_-_2023-013.txt (Verified.)

A 2026 AOS-S bulletin reportedly covers nine flaws with 16.11.0031 and below affected, fixed in 16.11.0032. https://securityonline.info/hpe-aos-switch-vulnerabilities/ (Unverified, secondary news.) So AOS-S is still covered in 2026.

### 7. Reading version and config, and read-only roles

AOS-CX: `show version` shows a Build ID such as `ArubaOS-CX:FL.10.06.0010:...` and the active image; `show images` shows per-slot version and date. https://cray-hpe.github.io/docs-csm/en-14/operations/network/management_network/firmware/update_management_network_firmware (Unverified, third-party HPE Cray doc from search summary.) The platform prefix (FL, GL, PL and so on) must be stripped before matching the CSAF numeric `10.17.1021` form. (Inferred.)

AOS-CX roles, from the REST API reference v10.08: operators are privilege level 1 with all "show" CLI commands except sensitive ones and all REST GET requests; auditors are level 19 limited to security logs (show and GET for security logs only); administrators are level 15 with full CLI, bash, and all REST methods. Custom user groups have no REST access. https://developer.arubanetworks.com/aoscx/v10.08/reference/get_system-user-groups-name (Verified.) An older v10.04 page summary described auditors differently (all show commands and all GETs). https://developer.arubanetworks.com/aoscx/v10.04/reference/user_group (Unverified.) Conclusion: use operators for REST and SSH reads; auditors is the wrong group for config reads in 10.08.

AOS-CX least-privilege SSH: Qualys documents a custom `user-group` with explicit `permit cli command` rules for `show version`, `show running-config`, `show running-config all`, `show ssh server`, `show tls`, `show ntp status`, `show aaa authentication`, and others. https://docs.qualys.com/en/vm/latest/authentication/unix/privilege_level_for_arubaos_cx.htm (Verified.) A community thread says a `show .*` rule broke `show running-config` until rules were fixed, and that RADIUS cannot do command authorization. https://airheads.hpe.com/discussion/radius-account-with-operators-level-on-arubaos-cx-6200f-switches (Unverified.)

ArubaOS-Switch: Qualys shows a scan user via `aaa authentication local-user <name> group <group> password ...` and `aaa authorization group <group> <seq> match-command <cmd> permit`, needing `show running-config` and `show version`. https://docs.qualys.com/en/vmdr/latest/authentication/unix/privilege_level_for_arubaos_switch.htm (Verified.) Whether the built-in operator level can run `show running-config` is unclear; community posts report it cannot. https://community.hpe.com/t5/hpe-aruba-networking-provision/hp-2920-advance-operator-user/m-p/6844737 (Unverified.) `show flash` lists primary and secondary image versions and Boot ROM; `show version` shows the running image and boot slot. https://community.arubanetworks.com/community-home/digestviewer/viewthread?MID=27711 (Unverified.)

### 8. Running Aruba in CML

AOS-CX Switch Simulator: an OVA from HPE for learning only, with 10 ports (1 management, 9 data). Download needs an HPE/Aruba support portal account; one 2024 reply says personal downloads without a corporate account are not possible. https://airheads.hpe.com/discussion/simulator-download and https://community.arubanetworks.com/discussion/downloading-the-aruba-aos-cx-switch-simulator (Unverified.) The welcome post (2021-04-14) does not list hypervisors or mention CML. https://community.networking.hpe.com/discussion/start-here-welcome-to-the-aruba-aos-cx-switch-simulator (Verified.) EVE-NG has an official how-to that extracts the VMDK from the OVA and converts to qcow2; users report needing e1000 NICs; defaults about 2 vCPU and 4 GB. https://www.eve-ng.net/index.php/documentation/howtos/howto-add-aruba-cx-switch/ (Unverified.) Latest simulator mentioned in threads is 10.15.1030. (Unverified.)

CML: the cml-community repo has an `hpe` folder for the HPE VSR1000 router only (2 vCPU, 4096 MB), no AOS-CX definition. https://github.com/CiscoDevNet/cml-community/tree/master/node-definitions/hpe (Verified.) Since EVE-NG (also KVM/QEMU) runs the converted image, a custom CML node definition should be feasible, but nobody has published one. (Unverified, inference.)

ArubaOS-Switch: no virtual image. An Airheads reply says there is no ArubaOS virtualisation work for GNS3 or EVE-NG; only AOS-CX has a simulator. https://community.arubanetworks.com/discussion/aruba-switching-simulation-platform (Unverified, undated community statement.) A 5412R zl2 lab needs real hardware or captured outputs.

### 9. End of support

HPE Networking End of Life policy: End of Engineering Support is generally 5 years after End of Sale, and HPE may shorten or extend it. No per-product tables on that page; it links to https://www.hpe.com/us/en/networking/eos/index.aspx. https://support.hpe.com/docs/display/public/hpe-networking-eos/information.html (Verified.)

AOS-CX software: releases are SSR (short) or LSR (long). The 10.17 release notes say SSR support is initial release plus 1 year, with End of Maintenance equal to End of Support. https://arubanetworking.hpe.com/techdocs/AOS-CX/Consolidated_RNs/HTML-6000/Content/10_17/overview-1017x.htm (Unverified, 403 to fetch.) 10.10 and 10.13 are LSRs. https://arubanetworking.hpe.com/techdocs/AOS-CX/Consolidated_RNs/HTML-10000/Content/matrix.htm (Unverified.) No single AOS-CX lifecycle date table was found. The CSAF fixed-branch list (10.18, 10.17, 10.16, 10.13, 10.10 in Sept 2026) is a practical proxy for "branches still fixed". (Verified as data, inference as proxy.)

ArubaOS-Switch 16.11: no published end-of-support date found; release notes call 16.11 fully supported, and 16.11.0032 is a 2026 security fix. https://arubanetworking.hpe.com/techdocs/AOS-Switch-RN/Content/16.11RN/16.11_Release_Overview.htm (Unverified.) Advisories mark older trains (16.09 and below) as not receiving fixes. (Verified via 2023-013 text above.)

5400R zl2 hardware (J9850A 5406R, J9851A 5412R): no official End of Sale notice found. A community reply says the series was not declared end of sale; HPE's October 2024 warranty quick reference lists 5400R zl2 parts as active. https://community.hpe.com/t5/aruba-provision-based/switch-information/td-p/6970223 and https://asp-documents.arubanetworks.com/portals/0/el/warranty-coverage-quick-reference.pdf (Unverified; the PDF was not read.)

## Implications

1. Check Point lab in CML is feasible: start from the cml-community `gaia.yaml`, raise RAM to 8 GB (16 GB for a standalone), use the sk158292 All-In-One qcow2, set the password via cloud-init or console, then apply a 30-day All-In-One eval regenerated each month. Budget one eval per extra gateway.
2. The sk158292 images ship below current JHF (CVE-2024-24919 warning), which is useful: the lab will naturally show findings before patching.
3. Check Point matching key is (major version, role, JHF Take). `show version all` and the Management API do not give the Take. Plan for clish `show installer packages installed` first, and treat expert-mode `cpinfo -y all` as an opt-in elevated collector.
4. No machine-readable Check Point product advisory feed was found. The skill needs a curated local table built from sk articles and the per-release "All Resolved Issues" pages (CVE to fixed Take), with a refresh step. Do not use advisories.checkpoint.com (IPS protections).
5. For management, use a "Read Only All" admin with API Key auth plus "Management API Login". Avoid `run-script` in read-only mode since it executes on gateways.
6. The official Check Point MCP servers do not enforce read-only themselves; if the skill uses them, scope comes from the admin profile. Logs are a later phase (100 records per call).
7. Load lifecycle dates live from the Check Point lifecycle page; R81.10 is already out of support (March 2026) and R81.20 ends May 2027.
8. Aruba CSAF is real and usable but needs a normalizer: no provider-metadata, inconsistent product names, AOS-S train prefixes embedded in semver ranges (KB/WC/YA/YB/YC.16.11.0012), some bad bounds, case-duplicate files. Parse `index.txt`, then split train prefix from the numeric version before comparing. Pre-2022 advisories are text only.
9. AOS-CX: strip the platform prefix (FL., GL., etc.) from `show version` before matching CSAF numeric ranges. Use the operators group (REST GET plus non-sensitive show) or a custom SSH user-group; note custom groups lose REST, and auditors cannot read config in 10.08.
10. AOS-S: use a local user with an `aaa authorization group` permitting `show running-config`, `show version`, `show flash`. Collect both flash slots to flag a vulnerable secondary image.
11. AOS-CX can be labbed via a self-built CML node definition from the simulator OVA (convert VMDK to qcow2, e1000 NICs), subject to getting the download. ArubaOS-Switch cannot be virtualised; test with recorded command outputs from the real 5412R zl2.
12. Aruba end-of-support is weakly published. Use the CSAF "fixed branches" list as the support proxy, and report 5400R zl2 and AOS-S 16.11 lifecycle as "unknown, verify with HPE" rather than inventing dates.
