# Credential design research: secrets lookup and device authentication for read-only network automation

Date: 2026-11-26. Scope: light market research, read-only. Method: WebSearch and WebFetch. One page (the NSA guide PDF) returned HTTP 403 to WebFetch and was read with Firecrawl instead (that scrape cost 64 credits because the PDF bills per page).

Labels used below:
- Verified: I read the primary page (vendor doc, RFC, government doc) in this session.
- Unverified: seen only in a search-result summary, a secondary source, a forum, or not confirmed against the primary page. Treat as a lead, not a fact.

Tier 3 sources (forums, community posts) are labeled as such.

## 1. Agent identity and secrets products for AI agents

The market in late 2026 splits into three groups: (a) secrets vaults that added agent features, (b) identity providers that made agents a first-class identity type, and (c) agent access gateways that broker credentials so the agent never holds them. Only group (a) reliably hands an SSH password or API token to a local Python script today. Groups (b) and (c) are built around OAuth tokens for SaaS and MCP servers, not SSH to a router.

### 1Password
- Markets an "Agent Identity Toolkit" covering short-lived credentials and workload identity for agents. https://1password.com/solutions/ai-agent-identity (Unverified, search summary of vendor page)
- Announced "Unified Access" on 2026-03-17, extending one platform to humans, agents and machine identities. https://1password.com/blog/introducing-1password-unified-access (Unverified, search summary)
- Service accounts plus SDKs are the documented path for agentic access; an MCP gateway integration injects secrets at runtime. https://1password.com/blog/service-accounts-sdks-agentic-ai (Unverified, search summary)
- Can it hand a secret to a local Python script: yes, through the `op` CLI with a service account token (see section 2) or the Python SDK. https://www.1password.dev/service-accounts/use-with-1password-cli/ (Verified)

### Bitwarden
- Agent Access SDK, announced 2026-03-24: an Apache 2.0 open protocol for agents to request credentials with end-to-end encryption and human approval. Status is early alpha; the vendor says to test only with sample data. https://bitwarden.com/blog/introducing-agent-access-sdk/ (Verified)
- Delivery model: the agent sends an encrypted request, the human approves in the CLI, and a `run` subcommand injects the credential as environment variables into a child process. https://bitwarden.com/blog/introducing-agent-access-sdk/ (Verified)
- Bitwarden Secrets Manager (`bws`) covers scripts and CI; a separate MCP server lets assistants manage the vault. https://bitwarden.com/blog/how-bitwarden-helps-secure-agentic-ai-access-to-your-credentials.md (Unverified, search summary)
- Local Python script: yes via `bw` or `bws` (section 2); via Agent Access SDK only as env vars of a child process, and only in alpha.

### HashiCorp Vault
- No agent- or MCP-specific SSH feature found. The relevant building block is the SSH secrets engine in signed-certificate mode; dynamic SSH keys were removed as of Vault 1.13. https://www.hashicorp.com/blog/secure-ssh-access-at-scale-with-hashicorp-vault-and-boundary (Unverified, search summary)
- Closest non-human pattern: Ansible Automation Platform authenticates to Vault with AppRole, then asks the SSH engine to sign a client public key. https://www.hashicorp.com/en/blog/managing-ansible-automation-platform-aap-credentials-at-scale-with-vault (Unverified, search summary)
- Caveat for network gear: Vault signs OpenSSH-format certificates. Cisco IOS XE uses X.509v3 certificates per RFC 6187, not OpenSSH certificates (see section 4), so Vault SSH certs fit Arista and Linux-based NOSes better than IOS.
- Local Python script: yes, `vault kv get -field=...` or the `hvac` library (section 2).

### CyberArk
- "Secure AI Agents" solution reported generally available in November 2025, with agent discovery (AWS Bedrock, Copilot Studio) and an AI Agent Gateway using zero standing privileges. https://www.helpnetsecurity.com/2025/11/04/cyberark-secure-ai-agents-solution-2/ and https://www.cyberark.com/resources/all-blog-posts/cyberark-secure-ai-agents (Unverified, search summaries)
- For scripts, the classic path is Conjur (now branded Secrets Manager, Self-Hosted) via CLI, Summon, or SDK (section 2). https://www.cyberark.com/products/secrets-manager-self-hosted/ (Unverified)

### Okta
- "Okta for AI Agents" reported generally available 2026-04-30, giving agents a first-class identity; agent-to-agent delegation and an Agent Gateway were announced as coming. https://www.okta.com/newsroom/press-releases/showcase-2026/ and https://www.okta.com/blog/ai/okta-for-ai-agents-general-availability/ (Unverified, search summaries)
- Not a secrets store for SSH passwords; it issues and governs OAuth-style identities.

### Microsoft Entra Agent ID
- Identity framework for agents; each agent identity is a special service principal; supports OAuth 2.0, MCP and A2A; reuses Conditional Access and governance; requires a human sponsor. https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id (Unverified, search summary; Microsoft pages disagree on preview versus GA and on licensing)
- Not a secrets store. For an SSH password, an Entra-identified agent would read Azure Key Vault.

### Aembit
- "IAM for Agentic AI": an MCP Identity Gateway (beta 2026-02-24) sits between agents and MCP servers, enforces policy per tool call and swaps the agent token for the target credential so the agent never holds it. https://docs.aembit.io/changelog/entry/2026-02-24-mcp-identity-gateway-enters-beta-with-mcp-server-and-component-copying (Unverified, search summary)
- Vendor blog reports GA. https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/ (Unverified)
- Local Python SSH to a router: not a fit; designed for brokered HTTP/API access.

### Astrix Security (now Cisco)
- Discovery and governance of non-human identities, AI agents and MCP servers (API keys, service accounts, OAuth tokens). Cisco announced intent to acquire on 2026-05-04 (reported about $400M) and its blog states the acquisition completed on 2026-06-29; folding into Duo, Secure Access, Identity Intelligence and Splunk. https://blogs.cisco.com/news/cisco-announces-intent-to-acquire-astrix-security (Unverified, search summary)
- Posture and inventory tool, not a credential source for a script.

### Others noted in passing
- CrowdStrike announced acquiring SGNL (runtime access enforcement) in January 2026 for about $740M. https://www.securityweek.com/cisco-moves-to-acquire-astrix-security-to-tackle-non-human-identity-risks/ (Unverified)

### Emerging open standards
- IETF draft "AI Agent Authentication and Authorization" (draft-klrc-aiagent-auth, authors include Kasselman, Campbell, Parecki) profiles existing standards: agent equals workload, gets one WIMSE identifier which may be a SPIFFE ID, plus OAuth 2.0 for delegation. It was replaced by WIMSE working group draft draft-ietf-wimse-aims-00 (September 2026, Informational). https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/ and https://datatracker.ietf.org/doc/html/draft-ietf-wimse-aims (Unverified, search summary; Internet-Drafts are work in progress)
- Practical takeaway: standards converge on SPIFFE/WIMSE workload identity plus OAuth token exchange. None of it reaches SSH on network devices; routers still take a password, an SSH key, or an X.509/OpenSSH cert.

## 2. Vault and password manager CLIs a script can call

| Tool | Read one secret | Unattended auth |
|---|---|---|
| 1Password `op` | `op read op://<vault>/<item>/<field>` | Set `OP_SERVICE_ACCOUNT_TOKEN`; CLI 2.18.0 or later; no sign-in prompt |
| Bitwarden `bw` (password manager) | `bw get password <item_id>` | `BW_CLIENTID`/`BW_CLIENTSECRET` then `bw login --apikey`, then `bw unlock --passwordenv BW_PASSWORD --raw` to get `BW_SESSION` |
| Bitwarden Secrets Manager `bws` | `bws secret get <SECRET_ID>` (JSON default) | Set `BWS_ACCESS_TOKEN` (machine account access token) |
| HashiCorp Vault | `vault kv get -mount=secret -field=password <path>` | `VAULT_ADDR` plus a token from AppRole, cert, cloud or JWT auth |
| CyberArk Conjur | Ruby-era CLI: `conjur variable value <id>`; Go CLI v8: `conjur variable get -i <id>` | Host identity with API key, e.g. `CONJUR_AUTHN_LOGIN=host/...` and `CONJUR_AUTHN_API_KEY` |
| Keeper Secrets Manager `ksm` | `ksm secret get -u <RECORD_UID> -f password` or `ksm secret notation keeper://<UID>/field/password` | `KSM_CONFIG` (base64 or JSON config) means no profile init needed |
| Delinea Secret Server `tss` | `tss secret -s <id> -f password` | One-time `tss init --url ... -r <rule> -k <onboarding key>`; server checks rule and source IP |
| Delinea DevOps Secrets Vault `dsv` | `dsv secret read --path <path>` (add `--filter` for one field) | Client credentials configured in the CLI profile |
| KeePassXC | `keepassxc-cli show -q -a password --key-file <keyx> --no-password <db.kdbx> <entry>` | Key file only, no master password; or password on stdin |

Sources and status for each row:
- 1Password `op read` syntax: https://www.1password.dev/cli/reference/commands/read/ (Verified). Service account env var, 2.18.0 minimum, rate limits (`op item get` costs 3 reads; `OP_CONNECT_*` vars take precedence if set): https://www.1password.dev/service-accounts/use-with-1password-cli/ (Verified)
- Bitwarden `bw` unattended flow: https://bitwarden.com/help/cli/ (Verified). Note the doc says API-key login does not decrypt the vault, so an unlock with the master password is still required. For truly unattended use this means storing the master password somewhere, which is why `bws` is the better fit for machines.
- Bitwarden `bws`: https://bitwarden.com/help/secrets-manager-cli/ (Verified)
- Vault `kv get -field`: https://developer.hashicorp.com/vault/docs/commands/kv/get (Verified)
- Conjur: `variable value` form from the Ruby gem docs https://www.rubydoc.info/gems/conjur-cli (Unverified, search summary). The v8 `variable get -i` form is from my own knowledge and was NOT confirmed in any page this session (Unverified). Env var names from Java client and Summon docs https://github.com/cyberark/summon-conjur (Unverified).
- Keeper `ksm secret get`: https://docs.keeper.io/en/keeperpam/secrets-manager/secrets-manager-command-line-interface/secret-command (Verified). `KSM_CONFIG`: https://docs.keeper.io/keeperpam/secrets-manager/secrets-manager-command-line-interface/profile-command (Unverified, search summary)
- Delinea `tss`: https://docs.delinea.com/online-help/secret-server/api-scripting/sdk-devops/sdk-cli/index.htm (Unverified, search summary)
- Delinea `dsv`: https://docs.delinea.com/online-help/devops-secrets-vault/usage/cli-ref/secret.htm (Unverified, search summary)
- KeePassXC flags `-a`, `-k/--key-file`, `--no-password`, `-q`: https://man.archlinux.org/man/keepassxc-cli.1 (Unverified, search summary; the combined command was not tested)
- OS keychain fallback: Python `keyring` library reads macOS Keychain, Windows Credential Locker, freedesktop Secret Service and KWallet via `keyring.get_password(service, username)`, returning None if absent. https://pypi.org/project/keyring/ (Unverified, search summary). Note: on macOS any script run by the same Python can read items keyring created, without a prompt (same source, Unverified).

Common pattern: every tool can print exactly one secret to stdout given an identifier, and every tool takes its unattended credential from an environment variable or a one-time local config. That is the integration seam.

## 3. TACACS+ versus RADIUS for device administration

### Standards status
- RFC 8907 (TACACS+), September 2020, category Informational (not Standards Track), updated by RFC 9887. https://www.rfc-editor.org/info/rfc8907 (Verified)
- RFC 8907 itself describes TACACS+ as widely deployed but mainly used for device administration. https://www.rfc-editor.org/rfc/rfc8907.html (Unverified, search summary)
- RFC 9887, "TACACS+ over TLS 1.3", Proposed Standard, published 2025-12-09; adds TLS 1.3 authentication and encryption, drops the legacy obfuscation, assigns a new default port, certificates primary and external PSK optional. https://www.rfc-editor.org/info/rfc9887 (Unverified, search summary of the RFC Editor page)
- First shipping implementation found: Cisco ISE 3.4 patch 2 with Nexus 9000 on NX-OS 10.6(1)F; TLS 1.3 is not on by default in ISE 3.4.x; default port TCP 6049. Doc first released 2025-09-11, revised 2026-02-19. https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/224882-configure-tacacs-over-tls-1-3-on-a.html (Verified)

### Vendor guidance on when to use which
- Cisco: TACACS+ separates authentication, authorization and accounting; RADIUS combines authn and authz and cannot do per-command authorization. https://www.cisco.com/c/en/us/support/docs/security-vpn/remote-authentication-dial-user-service-radius/13838-10.html (Unverified, search summary)
- Cisco ISE: Device Admin service must be enabled per PSN; command authorization uses Command Sets (wildcard or regex). https://community.cisco.com/t5/security-knowledge-base/ise-what-we-need-to-know-about-tacacs/ta-p/5276243 (Unverified, tier 3 community knowledge base)
- Aruba ClearPass: supports TACACS+ enforcement profiles; system-defined profiles cannot be edited so custom ones are needed; default admin roles include a read-only admin. https://arubanetworking.hpe.com/techdocs/ClearPass/6.11/PolicyManager/Content/CPPM_UserGuide/Enforce/EPTACACS.htm (Unverified, search summary)
- Open source: tac_plus-ng by Marc Huber (event-driven-servers) is the actively developed free daemon; the older Shrubbery tac_plus is described as no longer actively developed. https://projects.pro-bono-publico.de/event-driven-servers/doc/tac_plus-ng.html (Unverified, search summary)

### Prevalence by organization size
- No survey with adoption percentages was found (Gartner, EMA, NetBrain searches returned nothing quantitative). Unverified gap.
- Duo describes the usual split: RADIUS for wireless and VPN, TACACS+ for device administration, most organizations running more than one. https://duo.com/learn/authentication-authorization-accounting (Unverified, search summary)
- Vendor blogs (tier 3) say RADIUS is simpler and suits SMB, and local AAA is common in small networks and branches. https://www.fs.com/blog/radius-vs-tacacs-whats-the-difference-2910.html (Unverified, tier 3)
- A 2014 NANOG thread (tier 3) suggested per-command authorization is used by a much smaller share than basic TACACS+ login and accounting. https://seclists.org/nanog/2014/Dec/607 (Unverified, tier 3, old)
- Reasoned estimate (my inference, not sourced): home lab and small SMB mostly local accounts; mid-market often RADIUS via NPS or the existing NAC, or TACACS+ if they own ISE/ClearPass; enterprise and service providers mostly TACACS+ with accounting, command authorization less often.

## 4. How automation accounts authenticate to network gear, and best practice

### Government guidance
- NSA Network Infrastructure Security Guide (June 2022), read via Firecrawl because WebFetch got 403: https://media.defense.gov/2022/Jun/15/2003018261/-1/-1/0/CTR_NSA_NETWORK_INFRASTRUCTURE_SECURITY_GUIDE_20220615.PDF (Verified)
  - Section 4.1: use centralized AAA, at least two servers, same protocol throughout, encrypted transport when supported.
  - Sections 4.2 and 5.1: local admin accounts only as backup when all AAA servers are down; emergency use only.
  - Section 5.1: disable shared or group admin accounts; one unique account per administrator.
  - Sections 4.3 and 4.5: authorize exec, commands, config and console; least privilege, accounts at privilege 1 or 0 by default.
  - Section 5.4: store passwords with the strongest algorithm; Type 8 (PBKDF2-SHA256) recommended.
  - The guide does not discuss service or automation accounts, nor SSH key or certificate login.
- DISA Network Device Management SRG V-202051: exactly one local account as the account of last resort, credentials sealed in a safe; Cisco example `aaa authentication login default group tacacs+ local`. https://trial.stigviewer.com/stigs/network_device_management_security_requirements_guide/2025-09-10/finding/V-202051 (Unverified, search summary of a third-party STIG viewer)
- Implication: a local automation account on every device conflicts with the STIG one-local-account rule. In STIG-bound shops the automation user must come from AAA (TACACS+ or RADIUS), not local.

### Vendor guidance on read-only roles
- Cisco IOS/IOS XE: a low-privilege user sees only the config lines at or below its level; `privilege exec level <n> show running-config view full` (IOS XE) lets a lower level see the full config. https://cisco.com/c/en/us/support/docs/routers/asr-1000-series-aggregation-services-routers/212149-Configure-IOS-XE-to-display-full-show-ru.html (Unverified, search summary). Forum reports (tier 3) say behavior varies by platform. https://community.cisco.com/t5/switching/login-read-only/m-p/3735085 (Unverified, tier 3)
- Juniper Junos: predefined `read-only` class gives view only and disables SCP/SFTP; predefined classes cannot be modified, so build a custom class; a community thread reports NETCONF show RPCs needed more than `operator`. https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-login-class.html (Unverified, search summary) and https://community.juniper.net/discussion/minimum-permissions-needed-for-show-commands-over-netconf (Unverified, tier 3)
- CIS Juniper benchmark items: set a login class for every user and avoid predefined classes; map remote AAA users to a remote login class. https://www.tenable.com/audits/items/CIS_Juniper_OS_v2.1.0_L1.audit:6d4a0105e3fa75dad704af693ff33ce1 (Unverified)

### Key and certificate options
- Cisco IOS XE supports SSH user authentication with X.509v3 certificates per RFC 6187 (needs an RFC 6187 client; plain OpenSSH and Paramiko do not speak it); username from the cert can be checked against TACACS+. https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-shell-ssh/223290-configuring-certificate-authentication.html (Unverified, search summary)
- Arista EOS supports OpenSSH certificates from 4.22.1F, with authorized principals. https://arista.com/en/support/toi/tag/ssh (Unverified, search summary)
- Junos OpenSSH certificate support: not confirmed this session (Unverified gap).
- Plain SSH public keys on local users are widely supported (IOS `ip ssh pubkey-chain`, Junos `ssh-ed25519` under the user, EOS `sshkey`), from general knowledge, not checked this session (Unverified). Note a key on a local user is still a local account under STIG rules, and TACACS+ normally does not authorize key-authenticated sessions on IOS unless AAA authorization is configured for them.

### API tokens
- Controllers and firewalls (Palo Alto, FortiGate, Meraki, Mist) use per-admin API keys bound to an admin role; read-only admin roles exist on all of them (general knowledge, Unverified this session). These are bearer secrets, so they fit the same vault lookup as SSH passwords.

## 5. Implications and recommendation

### Credential lookup design (least integration work, widest coverage)
Do not integrate any vendor SDK. Every product above reduces to "run a command, read one secret from stdout" or "read an environment variable". Design three resolution layers, tried in order per credential field:

1. Environment variable reference, e.g. `password: env:NETOPS_RO_PASSWORD`. Covers CI, `op run`, `bws run`, Bitwarden Agent Access `run`, Summon, Vault Agent templates, Kubernetes secrets. Zero integration code.
2. Command reference, e.g. `password: cmd:op read op://Network/netops-ro/password`. One generic runner (no shell, argv list, timeout, strip trailing newline, never log stdout) covers op, bw, bws, vault, conjur, ksm, tss, dsv, keepassxc-cli, `pass`, and anything an org invents. Ship documented one-line examples per tool from the table in section 2 rather than per-tool code.
3. OS keychain reference via Python `keyring`, e.g. `password: keyring:netops/netops-ro`. Best default for home labbers on Windows and macOS with no vault. Optional dependency.

Plus an interactive prompt (getpass) as last resort when a TTY exists, and never a plaintext password in the inventory as a recommended path (allow it with a loud warning for labs).

Rationale: env and cmd together cover essentially every vault, PAM and password manager with no vendor code to maintain, and they match how the agent-identity products deliver secrets today (env injection into a child process). Agent-identity platforms (Entra Agent ID, Okta, Aembit, Astrix) do not deliver SSH credentials to routers yet, so do not design for them now; the env layer already accepts whatever a future broker injects.

Guardrails to document: secrets never in argv of the SSH client, never in logs or reports, masked in error output; cache per run in memory only; one lookup per credential, not per device.

### Recommended read-only automation account (what to document)
1. A dedicated, named automation identity (for example `svc-netops-ro`), never a shared human admin account and never the account of last resort. One identity per tool, per NSA 5.1 and the Junos hardening guidance.
2. Where AAA exists, define it centrally: TACACS+ with command authorization restricted to `show`, `display`, `get` style commands plus accounting, or RADIUS returning a read-only role (Cisco priv level, Juniper class, Arista role, Aruba read-only role). Keep the device's single local account for break-glass only, per DISA V-202051.
3. Where no AAA exists (home lab, small SMB), a local read-only user per device: IOS XE privilege level with `show running-config view full`, Junos custom login class with view permissions, EOS role network-operator style. Document that this is the exception path and conflicts with STIG.
4. Prefer SSH key authentication for the local path; note IOS X.509 certificates need an RFC 6187 client and OpenSSH certificates fit Arista and Linux-based NOSes.
5. Store the credential in whatever vault the org already uses and reference it through the env/cmd/keyring layers; rotate on a schedule.
6. Per-vendor read-only role snippets (IOS XE, NX-OS, Junos, EOS, AOS-CX, FortiGate, PAN-OS, ASA) should each be lab-tested before publishing; most role details in this note are Unverified.

### Open gaps worth a follow-up
- Conjur v8 CLI read syntax.
- Junos OpenSSH certificate support and minimum version.
- Quantitative TACACS+ versus RADIUS adoption by organization size (none found).
- NX-OS, AOS-CX, FortiGate and PAN-OS read-only role names and whether they allow full config view.
