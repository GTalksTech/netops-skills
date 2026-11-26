# Network ops

Skills that read a network's devices (never change them unless a person approves) and report on
their state, health and security.

## Security

**Vulnerability scan**:
A check of the software each device runs against published vendor advisories and end-of-support
dates, producing a ranked patch and replacement list.
_Avoid_: Security check, CVE review, scanner

**Hardening audit**:
A check of each device's configuration against published secure-configuration guidance, producing
a ranked list of config changes.
_Avoid_: Misconfiguration scan, compliance check, security check

**Affected**:
A CVE matches the device's version and its vulnerable condition is confirmed in the device's saved output.
_Avoid_: Vulnerable, hit

**Unconfirmed**:
A CVE matches the device's version, but the saved output cannot show whether its vulnerable condition holds.
_Avoid_: Possible, maybe affected

**Not affected**:
A CVE was considered and ruled out, either because the version is outside the affected range or because its condition is off.
_Avoid_: False positive, clean

**Proof**:
The evidence shown with every affected, unconfirmed or not-affected call: the version or config lines that decided it, plus links to the CVE and the vendor advisory.
_Avoid_: Reason, justification

**Severity**:
How bad a vulnerability is in the vendor's product, taken from the vendor's own rating when it publishes one, otherwise from the CVE's CVSS score.
_Avoid_: Score, risk, priority

**Priority**:
How urgently a finding must be fixed on this network, P1 to P4, decided by fixed rules on exposure and active exploitation and shifted at most one level by asset criticality.
_Avoid_: Severity, risk score, rank

**Actively exploited**:
Attackers are known to be using the vulnerability anywhere in the world, per CISA's KEV list or the vendor.
_Avoid_: Exploitable, weaponized, in the wild (as a bare term)

**Targeted**:
This network's own logs show attempts against a vulnerability that a device here is affected by.
_Avoid_: Attacked, exploited, hit

**Asset criticality**:
How much the business depends on a device: essential, support or minimal.
_Avoid_: Importance, tier, role

**Untagged device**:
A device whose asset criticality or internet exposure is not known yet; it is reported, never silently guessed.
_Avoid_: Unknown device, default device

**Coverage gap**:
Something a run needed but could not get (a device it could not reach, a command the account may not run, a missing API key, a condition no saved output shows), reported with the change that would close it next time.
_Avoid_: Error, limitation, blind spot

**Device facts**:
What a device's saved configuration and show output reveal about it that both a vulnerability scan
and a hardening audit rely on: which interfaces face the internet and which features are turned on.
_Avoid_: Parsed config, device state
