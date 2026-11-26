# Research: vulnerability scoring inputs + skill authoring (as of 2026-11-24)

Tags: **[V]** = Verified (I opened the primary page/file). **[U]** = Unverified (secondary source, search summary, or inference).
Tools: WebSearch + WebFetch, plus curl/pdftotext for PDFs and GitHub license files. Firecrawl was not needed.

---

## Part A: vulnerability prioritization

### 1. Tenable VPR, ACR, AES

- [V] VPR ranges from 0.1 to 10.0, with Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9 and Critical 9.0-10.0. A higher value means a higher likelihood of exploit. https://docs.tenable.com/security-center/Content/RiskMetrics.htm
- [V] Security Center lists seven VPR "key drivers":
  - Vulnerability Age (days since NVD published it)
  - CVSSv3 Impact Score (the NVD score, or a Tenable-predicted one)
  - Exploit Code Maturity (High, Functional, PoC, Unproven)
  - Product Coverage (Low to Very High)
  - Threat Sources (shows "No recorded events" when nothing happened in the past 28 days)
  - Threat Intensity (Very Low to Very High)
  - Threat Recency (0-180 days)

  The drivers are global and are not customized per organization. Same URL.
- [V] The newer Vulnerability Management driver list adds exploitProbability, onCisaKev, malware-observation intensity and recency, in-the-news intensity, recency and sources, targetedIndustries/Regions, exploitChain and vprPercentile. VPR is updated daily, and CVE-less findings get no VPR. https://docs.tenable.com/vulnerability-management/Content/Explore/Findings/RiskMetrics.htm
- [U] Tenable's formula and model weights are not published. Secondary sources describe VPR as a machine-learning prediction. Tenable's page does not say so.
- [V] VPR gives "equal weighting" to the threat score and the impact score (from CVSS). https://docs.tenable.com/quick-reference/scoring-explained/Content/VM.htm
- [V] ACR is an integer from 1 to 10, where higher means more critical. For VM assets it is now "based on the Global Asset Profile classification and subclassification". Same URL.
- [V] AES runs from 0 to 1000. Tenable computes it "by weighing the VPR values of active weaknesses and the ACR". Same URL.
- [U] Search summaries say ACR drivers include device type, device capability and internet exposure. They also say AES combines a "vulnerability density" with ACR, possibly as a geometric mean (that detail comes from a Tenable identity-exposure blog post). I could not confirm this on the VM page.
- What we can learn without copying anything proprietary:
  - Split the score into threat (exploitation evidence) and impact (CVSS/technical severity), then weight it by asset criticality.
  - Show the "key drivers" behind each score, which helps people trust it.
  - Let users override criticality, and say that a manual value wins.
  - Do not reuse Tenable's names (VPR, ACR, AES), its exact ranges as a brand, or any of its weights.

### 2. CISA SSVC

- [V] CISA's SSVC page: SEI/CERT built SSVC in 2019 with CISA, and CISA made its own decision tree in 2020. https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
- [V] The guide was published in November 2022 (cisa-ssvc-guide 508c.pdf, linked from that page). Its decision points and values:
  - **Exploitation:** None, Public PoC, or Active ("Shared, observable, and reliable evidence" of in-the-wild use).
  - **Technical Impact:** Partial or Total. Total means total control of the component, or total disclosure of all information on the system. Leaked credentials that give total control also count as Total. DoS counts as Partial.
  - **Automatable:** Yes or No. Can an attacker reliably automate kill-chain steps 1-4 (reconnaissance, weaponization, delivery, exploitation)?
  - **Mission Prevalence:** Minimal, Support, or Essential.
  - **Public Well-Being Impact:** Minimal, Material, or Irreversible.
  - Mission Prevalence and Public Well-Being combine into **Mission & Well-being:** Low, Medium, or High (the guide's Table 8). Any Essential, or any Irreversible, gives High. [V for the structure. The PDF table layout extracted poorly, so check the cells against the PDF.]
- [V] Outcomes:
  - **Track:** remediate within standard timelines.
  - **Track\*:** closer monitoring, still standard timelines.
  - **Attend:** supervisory-level attention, remediate sooner than standard.
  - **Act:** leadership attention, remediate as soon as possible.
- [V] The guide's Table 9 is a 36-row table (3 exploitation × 2 automatable × 2 impact × 3 mission/well-being). Examples I reconstructed from the PDF text:
  - Exploitation none, Automatable no, Partial, Low: Track.
  - Active, Total, High: Act.
  - PoC, Automatable yes, Total, High: Attend.

  [The rows are V, but the column alignment in the extracted text was garbled. Re-read the PDF or the CISA calculator before encoding the table.] https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf
- License:
  - [V] The CISA SSVC page carries no license statement. The CISA linking policy says "It is a public domain website". https://www.cisa.gov/linking-policy
  - [U] The guide is US Government work, so 17 USC 105 likely applies (not copyrighted in the US). The guide PDF itself shows no copyright line in the extracted text.
  - [V] CERT/CC SSVC repo (github.com/CERTCC/SSVC): the LICENSE says different directories have different licenses. The documentation/material is **CC BY-NC 4.0** (© Carnegie Mellon University). Software files are under an **MIT (SEI)-style** license. GitHub reports NOASSERTION. https://raw.githubusercontent.com/CERTCC/SSVC/main/LICENSE
  - Practical rule: implement from the **CISA** guide (public domain), not from the CERT/CC docs (non-commercial). Do not copy CERT/CC deployer tables.
- [V] **CISA Vulnrichment** (github.com/cisagov/vulnrichment) is **CC0-1.0**. It publishes SSVC Exploitation, Automatable and Technical Impact per CVE as ADP data. BOD 26-04 says Vulnrichment uses SSVC's definitions for automatability and technical impact (from the BOD page). This makes it a free, license-clean source for two of our inputs.
- [V] The KEV catalog data (github.com/cisagov/kev-data) is **CC0 1.0**. The license text also says use does not authorize the CISA logo or DHS seal and implies no endorsement.

### 3. CVSS v4.0

Source for the facts below, unless noted: [V] https://www.first.org/cvss/v4.0/specification-document

- **Threat metric: Exploit Maturity (E)**
  - Attacked (A), POC (P), Unreported (U), Not Defined (X).
  - X is scored as Attacked (worst case).
  - Higher maturity gives a higher score.
- **Environmental metrics**
  - Security Requirements CR, IR, AR: High, Medium, Low, or X (X is treated as High).
  - Modified Base metrics (MAV, MAC, MAT, MPR, MUI, MVC/MVI/MVA, MSC/MSI/MSA) override the Base values.
  - MSI and MSA may take the value Safety.
- **Supplemental metrics** never change the score. They are:
  - Safety (S)
  - Automatable (AU): No or Yes, using the same kill-chain framing as SSVC
  - Recovery (R): Automatic, User, or Irrecoverable
  - Value Density (V): Diffuse or Concentrated
  - Vulnerability Response Effort (RE): Low, Moderate, or High
  - Provider Urgency (U): Clear, Green, Amber, or Red
- **Nomenclature:** CVSS-B, CVSS-BT, CVSS-BE and CVSS-BTE. Label a score with the groups actually used. NVD usually publishes CVSS-B.
- **Qualitative scale:** None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0. Use of the labels is optional.
- **Terms**
  - FIRST owns CVSS and licenses it free to the public.
  - Users must give attribution and state that FIRST owns CVSS and that it is used by permission.
  - Anyone publishing scores must include both the score and the vector string.
  - The site footer says "All Rights Reserved".
- [V] User guide: Base scores "should not be used alone to assess risk". CVSS-BTE "much closer to 'Risk'". It suggests feeding threat intel such as KEV into E, but does not mention EPSS. https://www.first.org/cvss/v4.0/user-guide
- **Libraries**
  - [V] The CVSS v4 calculator repo (FIRSTdotorg/cvss-v4-calculator, which resolves to RedHatProductSecurity/cvss-v4-calculator) is BSD-2-Clause.
  - [V] The `cvss` Python library (RedHatProductSecurity/cvss) is LGPL-3.0. Depending on it is fine for MIT, but do not vendor or copy its code into an MIT repo.

### 4. EPSS

- [V] EPSS is a model that estimates the probability a CVE is exploited in the wild in the next 30 days. It gives a 0-1 probability plus a percentile, published daily via CSV and API (api.first.org). It is run by the FIRST EPSS SIG, with scores generated by Empirical Security. https://www.first.org/epss/
- [V] The API works today: CVE-2023-20198 returned epss 0.99781, percentile 0.99956, dated 2026-11-23. Response header: "access":"public".
- **Versions**
  - [U] v4 was released 2025-03-17 (Empirical Security post, per search).
  - [V] **EPSS v5 is now released.** Empirical Security's "EPSS V5 Is Here" claims a "23% improvement" over v4, scores all 318k+ CVEs and refines calibration. The article is dated June 15 (year not shown). A press release in search results says May 13, 2026 [U]. https://research.empiricalsecurity.com/research/epss-v5-is-here
  - Implication: do not hard-code "EPSS v4". Read the model-version comment in the CSV header and record it in output.
- [V] FAQ points (https://www.first.org/epss/faq):
  - "There is no universal threshold". The commonly cited 0.10 has no special authority. Pick a threshold from capacity and risk tolerance, using the coverage, efficiency and effort framework.
  - EPSS "does not know what assets your organization runs".
  - Multiplying EPSS by CVSS "is never a good idea". The two are empirically uncorrelated.
  - "Attribution is requested when EPSS data is used in publications or products". The full terms are on a Copyright page that returned 404 for me.
- [V] Probability vs percentile article: lead with the probability and show the percentile, for example "15.3% (92nd)". EPSS deliberately does not bin scores, and hard cutoffs treat near-identical scores differently. https://www.first.org/epss/articles/prob_percentile_bins
- [U] Older usage-agreement text (third-party mirrors, 2022 archive): free public use, and attribution requested, for example "See EPSS at https://www.first.org/epss".

### 5. CISA BOD 26-04

Page: [V] https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk

- [V] "BOD 26-04: Prioritizing Security Updates Based on Risk", issued **2026-06-10**. It supersedes and revokes BOD 19-02 and BOD 22-01. It is listed on https://www.cisa.gov/news-events/directives.
- [V] **This is the source of the four-factor table.** Each factor is binary:
  - Is the asset publicly exposed?
  - Is the CVE in KEV?
  - Automatable?
  - Technical impact Total vs Partial ("total control over the behavior of the software")?

  The page says Table 1 is "informed by the SSVC system". It does not mention EPSS.
- [V] Phases:
  - **I**, immediate: update policies, monitor KEV, automate CDM reporting, continue Cyber Hygiene scanning.
  - **II**, 60 days (about 2026-08-09): update processes.
  - **III**, 180 days (about 2026-12-07): remediate per Table 1, tag internet-reachable assets, include private IPs in CDM.
- [V] Timing rules:
  - The clock starts at the earlier of two events: the CVE's KEV addition, or the agency's own detection.
  - Rows marked "& forensic triage" require remediation within 3 days plus triage.
  - "Fix on system upgrade" means remediation at the next major upgrade or rebuild.
  - Removing an asset from the internet can lengthen its timeline, and a new KEV addition shortens it.
- [V] Implementation guidance (https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk):
  - "Publicly exposed" means accessible to unauthenticated or untrusted entities via a public network.
  - When exposure data is missing, CISA treats an asset as public if it has a publicly routable IP, has asset type "network", or runs software CISA considers generally public-facing. This matters for network devices.
  - "Total" means arbitrary code, full-privilege accounts or credentials. DoS is Partial.
  - A reliable public PoC that achieves remote code execution counts as Automatable.
  - It gives a six-step, 72-hour forensic-triage timeline (recommended).
- [U] **Table 1 is an image, and I could not read the row-level cells.** Secondary sources (Tenable FAQ, CSA research note of 2026-08-20) agree on 16 combinations mapped to 5 tiers:
  - 3 days + forensic triage: KEV and Total, regardless of exposure or automatability.
  - 3 days: some high-risk non-KEV combinations, for example exposed, automatable and Total.
  - 14 days: most other KEV combinations and some high-risk non-KEV ones.
  - 60 days: lower-risk combinations.
  - Fix on system upgrade: none of the four factors apply.

  CSA's sample put roughly 60% of vulns in the deferral tier. **Before encoding the table, transcribe Table 1 from the image yourself.** https://www.tenable.com/blog/cisa-bod-26-04-FAQ-vulnerability-remediation-impact ; https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/08/CSA_research_note_cisa-bod-26-04-risk-based-vulnerability-remediation_20260820-csa-styled.pdf
- [V] Related: BOD 26-02 "Mitigating Risk From End-of-Support Edge Devices" and ED 26-03 (Cisco SD-WAN) are both on the directives list. Both are relevant to network-device findings.

### 6. P1-P4 mapping and combining vendor severity with CVSS

- [V] **Cisco** Security Impact Rating: "The SIR is based on the CVSS Base score". It maps Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, and Informational (no CVE). PSIRT may adjust the SIR and reserves the right to deviate. Cisco publishes the Base score (and sometimes Temporal) and asks customers to compute Environmental. https://sec.cloudapps.cisco.com/security/center/resources/security_vulnerability_policy.html
  - Implication: Cisco SIR and CVSS are highly correlated, almost the same signal. Adding both is **double counting**.
- [V] **Red Hat** uses a four-point severity (Low, Moderate, Important, Critical) that is separate from CVSS, and it "does not solely use the CVSS rating". Reasons include product context, compiler hardening, SELinux and default config. Red Hat recommends its own CVSS over NVD's, and does not re-rate a flaw when an exploit appears. https://access.redhat.com/security/updates/classification
  - Implication: vendor severity sometimes carries product-specific context that NVD lacks. Prefer the vendor's CVSS/vector for that product over NVD's.
- [U] Juniper publishes CVSS 4.0 alongside 3.1 in its JSAs (seen in CVE records). I did not find primary methodology pages for Fortinet or Palo Alto Networks.
- [V] FIRST EPSS FAQ: do not multiply EPSS by CVSS (see Q4).
- [V] NIST SP 800-40r4 (April 2022) prioritizes patches by risk reduction ("a low-risk vulnerability on a small number of low-importance assets" gets lower priority). It defines **maintenance groups**: assets with similar characteristics, outage tolerance and "level of impact ... if compromised", each with its own maintenance plan. It cites KEV as helpful for prioritization. https://csrc.nist.gov/pubs/sp/800/40/r4/final (PDF: nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-40r4.pdf)
- [U] P1-P4 practice: there is no tier-1 standard that defines P1-P4 for vulnerabilities. The closest authorities are SSVC's four outcomes (Track, Track\*, Attend, Act) and BOD 26-04's five deadline tiers. A defensible mapping:
  - P1 = Act / 3-day tiers
  - P2 = Attend / 14 days
  - P3 = Track\* / 60 days
  - P4 = Track / next upgrade

  This is my inference, not a published standard.
- Double-counting warnings:
  - [V] EPSS: do not multiply by CVSS.
  - [V] Cisco SIR is derived from CVSS Base.
  - [V] CVSS-BT Exploit Maturity already encodes exploitation evidence (KEV-type intel), so adding KEV again on top of a BT score double counts.
  - [V] SSVC Technical Impact is "similar to the CVSS base score's concept of 'severity'".
  - [V] CVSS Supplemental AU equals SSVC Automatable, the same concept.

### 7. Asset criticality (tier-1 sources)

- [V] NIST CSF 2.0 (CSWP 29, 2024-02-26), **ID.AM-05**: "Assets are prioritized based on classification, criticality, resources, and impact on the mission". https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
- [V] NIST SP 800-30 Rev. 1 (2012-09, still final) maps qualitative and semi-quantitative values as follows. Table I-2 combines likelihood × impact into a risk level. https://csrc.nist.gov/pubs/sp/800/30/r1/final

  | Qualitative | 0-100 range | 0-10 value |
  | :- | :- | :- |
  | Very High | 96-100 | 10 |
  | High | 80-95 | 8 |
  | Moderate | 21-79 | 5 |
  | Low | 5-20 | 2 |
  | Very Low | 0-4 | 0 |

  This is a public-domain basis for a 0-100 score with bands.
- [V] SP 800-30 points to SP 800-60 and FIPS 199 for criticality and sensitivity (Low, Moderate, High impact per CIA).
- [V] SSVC Mission Prevalence (Minimal, Support, Essential) is a simple, defensible, public-domain criticality scale (see Q2).
- [V] SP 800-40r4 maintenance groups capture criticality in practice (see Q6).
- [V] CVSS v4 Environmental CR, IR and AR (High, Medium, Low) are FIRST's way to express asset criticality inside CVSS.

### Implications for our design (Part A)

1. Anchor the priority on the **BOD 26-04 / SSVC decision logic**: exposure, KEV, automatable, total impact. Both are US Government work. Implement from the CISA guide and the BOD text. Do not copy the CERT/CC (CC BY-NC) material. Transcribe BOD Table 1 manually from the image and cite it.
2. Use **CC0 sources** for the inputs:
   - KEV (cisagov/kev-data) for exploitation.
   - Vulnrichment for SSVC Exploitation, Automatable and Technical Impact per CVE.

   Use EPSS (free, attribution requested) as a tie-breaker or secondary signal, not a multiplier. Record the EPSS model version from the CSV header, since v5 is now live.
3. Use **one severity input**: the vendor's CVSS vector when present, else NVD's. Treat Cisco SIR as a label, not an extra weight. Use Red Hat-style vendor severity only as an override reason, which avoids double counting.
4. Treat **exposure** as a feature-level fact for network devices, for example management plane on a public IP, or a VPN/web UI enabled on an outside interface. Note that BOD's fallback treats "network" asset type as public when data is missing.
5. **Criticality:** a 3-level scale (Essential, Support, Minimal, matching SSVC Mission Prevalence) or the FIPS 199 High/Moderate/Low. Allow a user override. Optionally map it to CVSS CR, IR and AR.
6. Build the 0-100 score with **SP 800-30's semi-quantitative bands** (96-100, 80-95, 21-79, 5-20, 0-4) so the numbers have a citable basis.
   - Derive the P-level from the decision table first.
   - Let the score only order findings within a P-level. This avoids a weighted sum overriding a KEV+Total case.
7. Always print the score's drivers, à la Tenable, and the CVSS vector (a FIRST term of use). Add a "CVSS is owned by FIRST, used by permission" attribution line, plus an EPSS attribution line.
8. Do not use Tenable names (VPR, ACR, AES) or claim equivalence with them.

---

## Part B: skill authoring

### 8. Skills docs, spec and plugins

**Spec** [V] https://agentskills.io/specification

- Required fields:
  - `name`: 1-64 characters, lowercase a-z, 0-9 and hyphens, no leading, trailing or double hyphen, and **must match the parent directory**.
  - `description`: 1-1024 characters, saying what the skill does and when to use it.
- Optional fields:
  - `license`
  - `compatibility`: up to 500 characters
  - `metadata`: string-to-string map
  - `allowed-tools`: space-separated, experimental
- Directory layout: `scripts/`, `references/`, `assets/`.
- Progressive disclosure: metadata is about 100 tokens, the body should stay under 5000 tokens and under 500 lines, and resources load on demand. File references should be one level deep.
- Validate with `skills-ref validate`.

**Governance** [V] https://www.anthropic.com/news/donating-agent-skills-to-the-agentic-ai-foundation

- Anthropic donated the standard to AAIF (Linux Foundation) on 2026-10-22, including the name, logo, GitHub org and agentskills.io.
- Lead maintainers are David Soria Parra and Mahesh Murag.
- The roadmap includes versioned releases and security guidance for skill authors.

**Claude Code frontmatter beyond the spec** [V] https://code.claude.com/docs/en/skills

- `when_to_use`, `argument-hint`, `arguments`
- `disable-model-invocation`: true means the user must invoke it
- `user-invocable`: false hides it from the / menu
- `allowed-tools`: pre-approved for the invoking turn
- `disallowed-tools`
- `model`, `effort`
- `context: fork`, with `agent` (subagent type) and `background`: the default is true, and false waits for the result
- `hooks`
- `paths` (glob activation)
- `shell`: bash or powershell for injected commands
- Claude Code accepts `metadata`, `license` and `compatibility` but ignores them.
- Unknown fields are silently ignored.

**Claude Code behavior** [V] same URL

- `description` plus `when_to_use` is capped at 1,536 characters in the listing. Put the key use case first. The overall listing budget is about 1% of the context window.
- Substitutions:
  - `$ARGUMENTS`, `$N` and `$name`
  - `${CLAUDE_SKILL_DIR}` (use it for script paths)
  - `${CLAUDE_PLUGIN_ROOT}` and `${CLAUDE_PLUGIN_DATA}` (plugin skills only)
- Dynamic context: ``!`cmd` `` runs a command before the skill loads. A failing command aborts the invocation; add `|| true`.
- After compaction only the start of a skill may be kept, so put critical rules at the top.
- Rules that must always hold belong in hooks, not skill text.

**Locations and precedence** [V] same URL

- Precedence: enterprise beats personal, which beats project.
- **Plugin skills are namespaced `/plugin-name:skill-name`** and never collide with local skills.
- Nested `.claude/skills/` folders are discovered when files in them are touched (monorepo).

**Plugin layout** [V] https://code.claude.com/docs/en/plugins-reference

- `.claude-plugin/plugin.json` is optional. Only `name` is required, in kebab-case.
- Every component is namespaced under the plugin name, for example `deploy-tools:reviewer`.
- `skills/<name>/SKILL.md` is the default. A `skills` key **adds** to that scan.
- Other components: `.mcp.json`, `hooks/hooks.json`, `agents/` and `bin/`. Files in `bin/` go on the Bash PATH, but claude.ai and Cowork won't install a plugin that has `bin/`.
- A `CLAUDE.md` at the plugin root is **not** loaded.
- `claude plugin validate [--strict]` checks the plugin.
- Name rules: `claude-` and `anthropic-` prefixes are errors. "claude" as a whole word is a warning.
- Other manifest fields: `engines`, `dependencies`, `network.hosts`.

**MCP naming in Claude Code** [V] https://code.claude.com/docs/en/mcp

- Tools from a plugin-bundled server are named `mcp__plugin_<plugin>_<server>__<tool>`. User or project servers are `mcp__<server>__<tool>`.
- Use the full name in `allowed-tools`, permissions, subagent `tools` and hook matchers.
- Note: the platform best-practices page instead says "fully qualified" `ServerName:tool_name`. In Claude Code, the callable name is the `mcp__...` form.

**Best practices** [V] https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices

- **Writing**
  - Be concise ("Claude is already very smart").
  - Write the description in **third person**. Gerund names are preferred.
  - Match degrees of freedom to how fragile the task is.
  - Keep the body under 500 lines.
- **Reference files**
  - Organize them by **domain** (`reference/finance.md` …).
  - Put a **table of contents in any reference file over 100 lines**.
  - Keep references **one level deep** from SKILL.md, because nested reads may be partial (`head -100`).
- **Workflows**
  - Use checklists and feedback loops (validate, fix, repeat).
  - Use plan, validate, execute with a verifiable intermediate file for batch or destructive operations.
- **Scripts**
  - **"Solve, don't defer"**: handle errors in the script.
  - No "voodoo constants". Document each value.
  - Say whether Claude should *run* or *read* a script.
  - List the packages needed and don't assume they are installed.
  - Use forward slashes only.
- **MCP**: use fully qualified tool names.
- **Evals**
  - **Build evaluations first.**
  - Write **three scenarios** for the gaps, measure a baseline without the skill, then write minimal instructions.
  - The checklist asks for "At least three evaluations" and testing "with Haiku, Sonnet, and Opus" (Haiku: is there enough guidance? Opus: is it over-explaining?).
  - Iterate Claude A / Claude B: one instance writes, a fresh one tests.
  - Avoid time-sensitive text, or put it in an "old patterns" section.
  - Use consistent terminology.

**Eval tooling**

- [V] skill-creator writes `evals/evals.json`. It runs with-skill vs baseline subagents, grades each run to `grading.json`, aggregates `benchmark.json` (pass rate, time, tokens), offers blind A/B and a review viewer, and tunes the description with about 20 should-trigger and should-not-trigger queries. Sources: Claude Code skills page, and the local skill-creator SKILL.md at C:\Users\bud8c\.claude\plugins\marketplaces\claude-plugins-official\plugins\skill-creator\skills\skill-creator\SKILL.md
- [V] `claude plugin eval` (https://code.claude.com/docs/en/plugin-evals):
  - Cases live in `evals/<case>/prompt.md` plus `graders/`.
  - Grader types: regex, tool_used (for example `tool_used: Skill` to check the skill fired), tool_order, file_exists, llm, baseline.
  - It compares against a no-plugin baseline, and `--model` pins the model in CI.
  - **Mock MCP servers** go in `evals/mocks/<server>/<tool>.md`, which is useful for testing with and without the optional MCP.
  - Its files are incompatible with skill-creator's evals.json.

**Splitting and subagents**

- [V] Reference content (conventions) runs inline. Task skills with side effects get `disable-model-invocation: true`.
- [V] Split when you approach 500 lines.
- [V] `context: fork` runs a skill in a subagent without conversation history. Guideline-only skills return nothing useful there.
- [V] The skills+MCP blog (2025-12-19) says to "Let MCP handle connectivity", while skills handle sequencing and workflow, and one skill can coordinate several MCP servers. https://claude.com/blog/extending-claude-capabilities-with-skills-mcp-servers

**Optional MCP / API missing**

- [U] No official doc defines how a skill should degrade.
- [V] The Claude Code MCP page says that with tool search on, Claude is told which server failed and why.
- The best pattern (inference, consistent with "solve, don't defer"):
  - The skill checks whether the tool or API is available.
  - When it isn't, the skill falls back to offline data or a reduced mode.
  - The output states which enrichment was skipped.
  - Scripts exit cleanly with a clear message instead of a traceback.
  - Test this with `claude plugin eval` mocks.

### 9. Secrets for skills and plugins

- [V] Plugin `userConfig` options can set `sensitive: true`. Claude Code then masks the input and stores the value in the platform's secure credential store, not settings.json. Non-sensitive values go under `pluginConfigs` in settings.json. https://code.claude.com/docs/en/plugins-reference
- [V] How values are exposed:
  - `${user_config.KEY}` is substituted in MCP and LSP config and exec-form hook args.
  - **In skill and agent content, sensitive values become a placeholder**, so secrets never enter the prompt.
  - `CLAUDE_PLUGIN_OPTION_<KEY>` is exported to hook processes.
  - The `${CLAUDE_PLUGIN_*}` variables are **not** in the Bash tool environment.
  - Shell-form hooks, monitors and `headersHelper` reject `${user_config.*}`.
  - Validate warns about literal credentials in headers.
- [V] `.mcp.json` supports `${VAR}` and `${VAR:-default}`. MCP OAuth tokens are stored securely. `--client-secret` goes to the system keychain (macOS) or a credentials file. https://code.claude.com/docs/en/mcp
- [U] I found no Agent Skills spec guidance on secrets yet. The AAIF roadmap mentions future "security guidance".

### Implications for our design (Part B)

1. Keep every network-ops skill spec-clean: `name` equals the directory name, the description is third person, at most 1024 characters, and leads with the trigger. Claude Code-only keys are fine because other agents ignore them.
2. Use `${CLAUDE_SKILL_DIR}/scripts/...` for script paths. Make scripts handle missing inputs or APIs themselves ("solve, don't defer"), document their constants, and use stdlib where possible.
3. Put scoring data (the BOD table, CVSS-to-band mapping, attribution text) in `references/`, split by domain, each with a TOC if over 100 lines and linked directly from SKILL.md.
4. Make API keys (for example NVD, or a vendor PSIRT API) plugin `userConfig` options with `sensitive: true`. Pass them to MCP servers via `${user_config.KEY}` or to hooks via `CLAUDE_PLUGIN_OPTION_*`. Never read them into skill text.
   - Because sensitive values aren't in the Bash env, a script that needs a key should read it from a user-set environment variable or an OS keychain. Otherwise run it as an MCP server or hook.
   - KEV, EPSS and Vulnrichment need no key.
5. Optional enrichment (EPSS, NVD, MCP): define an explicit offline mode, use cached or bundled KEV, and print "EPSS: unavailable, skipped". Refer to MCP tools by their full `mcp__plugin_<plugin>_<server>__<tool>` name.
6. Evals:
   - At least three scenarios per skill, including an offline/no-MCP case via mocks.
   - Run on Haiku, Sonnet and Opus.
   - Use a `tool_used: Skill` trigger grader, plus regex graders for the P-level and the score band.
   - Pin `--model` in CI.
   - Pick either skill-creator's evals.json or `claude plugin eval`; they do not read each other's files.
