# How network-security-check scores a finding

Every finding (a CVE on a device, a configuration problem, or a firewall event) gets one
**security impact score from 0 to 100** and a **deadline**. The deadline does the real work.
The number only sorts findings that share a deadline.

## The short version

1. Answer four yes/no questions about the finding.
2. Look the answers up in CISA's table (below). That gives the deadline.
3. The deadline sets the score band. EPSS (for CVEs) or the check's weight (for everything
   else) places the finding inside the band.

## Why this method

- **CVSS alone is not risk.** FIRST, who publish CVSS, say the base score "should not be used
  alone for patch prioritization". A CVSS 9.8 bug on an internal switch nobody can reach
  matters less than a CVSS 7.2 bug being exploited on your internet-facing firewall.
- **CISA already published a risk table for this.** BOD 26-04 (June 2026) replaced the old
  "patch everything in KEV in two weeks" rule with a table built from four questions. It is
  written for federal agencies, but the questions fit any network. It is US government work,
  so it can be reused freely.
- **One method for every finding.** CVEs, misconfigurations and events all answer the same
  four questions, so a 70 means the same thing in each section of the report.

## The four questions

| Question | For a CVE | For a config finding | For an event finding |
|---|---|---|---|
| **Publicly exposed?** Can an untrusted host on the internet reach the vulnerable thing? | If the advisory names a feature (web UI, SSL VPN, GlobalProtect, AnyConnect, J-Web, management interface), is that feature on an internet-facing interface in this config? If it names none: does the device face the internet? | Is the misconfigured service reachable from an internet-facing interface? | Did the events come from a public address? |
| **Known exploited?** | In CISA KEV, or the vendor's advisory reports exploitation, or your own IPS logs show attempts at it | The check cites documented attacks on this exact weakness (listed per check in `research/sources.md`), and the instance is exposed | The signature is tied to a KEV CVE |
| **Automatable?** Can an attacker script every step? | CISA's answer for that CVE (Vulnrichment). If CISA has none yet: network attack, no privileges, no user interaction in the CVSS vector | Set per check in `settings/checks.yaml`, with its source | Yes (it's traffic hitting your firewall) |
| **Total control?** Does the attacker end up controlling the device, or what it guards? | CISA's answer (Vulnrichment). If none: CVSS confidentiality AND integrity impact both High | Set per check | The tied CVE's answer, else yes only when the signature is critical |

**Attack vector overrides exposure.** If the CVE's CVSS vector says Adjacent, Local or Physical,
the CVE is scored as not publicly exposed, whatever the device faces. In CVSS, Adjacent means the
attack can't cross a routed boundary, and Local or Physical need access to the device itself
(FIRST CVSS specification, Attack Vector).

"Internet-facing" comes from the config: a public IP on the interface, a FortiOS `role wan`,
or an interface or zone named like untrust/outside/wan/internet. You can override any device
in the inventory with `exposure: public` or `exposure: internal`. If the check can't read
a firewall's interfaces, it assumes the firewall faces the internet for its CVEs, the same way
BOD 26-04 says "if one method finds it exposed, the answer is yes". It also stops trusting that
config for feature checks, so no CVE gets marked "feature off" from a config it couldn't read.
Interfaces in a management VRF or a management-only interface never count as internet-facing.

## CISA BOD 26-04, Table 1

| Exposed | Known exploited | Automatable | Impact | Deadline | Score band |
|---|---|---|---|---|---|
| Yes | Yes | Yes | Total | 3 days + check for compromise | 90-100 |
| Yes | Yes | No | Total | 3 days + check for compromise | 90-100 |
| No | Yes | Yes | Total | 3 days + check for compromise | 90-100 |
| Yes | Yes | Yes | Partial | 3 days | 80-89 |
| Yes | No | Yes | Total | 3 days | 80-89 |
| Yes | Yes | No | Partial | 14 days | 60-79 |
| Yes | No | Yes | Partial | 14 days | 60-79 |
| Yes | No | No | Total | 14 days | 60-79 |
| No | Yes | Yes | Partial | 14 days | 60-79 |
| No | Yes | No | Total | 14 days | 60-79 |
| No | Yes | No | Partial | 14 days | 60-79 |
| Yes | No | No | Partial | 60 days | 35-59 |
| No | No | Yes | Total | 60 days | 35-59 |
| No | No | Yes | Partial | 60 days | 35-59 |
| No | No | No | Total | Next planned upgrade | 0-34 |
| No | No | No | Partial | Next planned upgrade | 0-34 |

Source: CISA BOD 26-04 Appendix A, Table 1, transcribed 2026-11-07. The bands never overlap,
so a higher score always means a shorter deadline.

The lowest band is worded by finding type. A CVE says "Fix at the next planned upgrade", as in
the table. A config or event finding has no upgrade to wait for, so it says "Fix in the next
maintenance window". Same band, same score.

## Position inside the band

- **CVEs:** the EPSS percentile (FIRST's estimate of how likely exploitation is in the next 30
  days, ranked against all CVEs). FIRST says there is no universal EPSS threshold and EPSS
  should never be multiplied by CVSS, so EPSS only orders findings here. It never moves one
  into a different deadline.
- **Config findings:** the check's `weight` in `settings/checks.yaml`, a judgment call that
  orders checks with the same deadline (an any-any rule above a missing log setting).
- **Events:** volume.

## House rules (our judgment, not CISA's)

These are the places the method goes beyond its sources. Each is written down so you can
disagree with it. They are in the code as named constants or caps.

1. **Vendor-confirmed exploitation counts as known exploited**, even before CISA adds the CVE
   to KEV. FIRST: "confirmed and recent exploitation evidence should take precedence".
2. **Attacks in your own IPS logs count as known exploited** for the CVE they target.
3. **Affected feature looks off: next planned upgrade.** When the advisory names a feature (SD-WAN
   mode, DHCP snooping, GlobalProtect, SSL VPN...) and the config shows it is off, the device is
   most likely not exploitable. The feature match comes from advisory wording, so the finding is
   kept (marked "feature off" with the reason) instead of dropped, and goes to the "next upgrade"
   band. Confirm against the vendor advisory if it matters.
4. **Config findings never get "+ check for compromise" (capped at 3 days).** A misconfiguration
   is not evidence that someone got in.
5. **Config exploitation evidence only counts when the instance is exposed.** The attacks cited
   for, say, an open web UI or SNMP community were made from the internet. The same setting on
   an internal-only switch is scored as not known exploited.
6. **Event spikes where every event was blocked are capped at 60 days.** The control worked.
   What remains is to look at the target and confirm nothing else got through.
7. **Spike test:** modified z-score above 3.5 (NIST/SEMATECH e-Handbook 1.3.5.17). We add: at
   least 8 hours of history, at least 20 events in the hour, and when the baseline is flat
   (MAD = 0, common for rare signatures) the hour must be at least 5 times (median + 1).
8. **Stale IPS signatures:** older than 30 days on the day the snapshot was taken. FortiGuard publishes IPS updates daily, so 30
   days means updates have stopped, not that they are slow.
9. **No CISA answer and no CVSS vector: assume the worst** (automatable, total control), and say
   so in the finding.
10. **End of support (LIFECYCLE-EOS) is scored as automatable with total control, not known
    exploited, and capped at 3 days like any config finding.** Past the vendor's last security
    fix date, every future CVE on the device stays open, and network OS CVEs that end up in KEV
    are mostly remote code execution or auth bypass. CISA BOD 26-02 orders edge devices off
    end-of-support software "immediately" and reports widespread campaigns against them, but
    names no single exploit, so known exploited stays no. Result: an internet-facing device gets
    3 days (score 80-89), which matches "immediately"; an internal device gets 60 days. No lower
    cap: a "next upgrade" deadline would contradict the directive. The security end date is the
    vendor's end of vulnerability support (Cisco), end of engineering (Juniper, Fortinet: no
    more releases means no more fixes) or end of Extended Support+ (Palo Alto). LIFECYCLE-SOON
    (end within 12 months, the BOD 26-02 planning window) is always the lowest band. Dates live
    in `settings/lifecycle.yaml`, each with its vendor page; a train not in the table reports
    n/a, and a table older than 180 days adds a report note. Hardware end of life is not checked.

## Passes, not applicable, not visible

Every config check reports a result per device: pass, fail, n/a (it doesn't apply: no routing,
no vty lines, no VIPs) or not-visible (the config section it needs is missing, for example the
admin list under a FortiOS read-only profile). Only fails are scored. The others are listed per
device in the JSON report so a quiet check can be told apart from one that never ran. For
PAN-OS, ASA and Junos a pass only means the search found nothing.

## Accepted risk

A finding the owner decides to accept goes in `exceptions.yaml` in the snapshot repo (check,
device or "*", reason, expiry date, owner). It moves to the report's "Accepted risk" section
with its reason and expiry and leaves the deadline counts. Its score is unchanged. An expired
waiver stops applying and the report says so. Only config findings can be waived: a CVE is
cleared by patching, an event by blocking. Basis: NIST SP 800-53 Rev. 5 CA-5 (plan of action
and milestones) and RA-7 (risk response).

## Reading a finding

Each finding in the JSON report carries `inputs` (the four answers) and `why` (where each
answer came from), so you can always see why something scored the way it did. If an answer
is wrong for your network, fix the input (inventory `exposure:`, a segment name in
`settings/segments.yaml`), not the score.
