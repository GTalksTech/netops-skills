# NetOps Skills

AI skills that let network engineers run real workflows against their own networks, and the community that tests and extends them.

## Language

### Devices and coverage

**Platform**:
One network operating system family that a skill drives the same way, such as Cisco IOS-XE, Cisco NX-OS or Arista EOS.
_Avoid_: Vendor (one vendor ships several platforms), device type, OS

**Vendor**:
The company that makes a platform. Used only loosely ("multi-vendor"), never as the unit of support.

**Platform profile**:
The description of how a skill talks to one platform: its commands and how to read their output.
_Avoid_: Vendor profile, driver, platform file

**Profile status**:
How much real-world proof a platform profile has, held separately for each skill: **untested**, **lab-tested** or **tested**. Snapshot can be tested on Junos while health check on Junos is still untested.

**Untested**:
Written from vendor docs; never run on a device.

**Lab-tested**:
Run successfully on a virtual image of the platform (CML, containerlab, vendor VM), by the maintainer or a contributor.

**Tested**:
Run successfully on real hardware of the platform.

### Topology

**Device role**:
A device's job in the network design: provider (a device the organization doesn't run, such as the ISP router), edge, firewall, core, distribution or access. It also tells every skill whether a device is a firewall. Set in the inventory, or guessed from the device name and reported as a guess.
_Avoid_: Tier, layer, asset criticality (how much the business depends on a device is a different thing)

**Neighbor link**:
A connection between two interfaces that a device reports through CDP or LLDP.
_Avoid_: CDP link, discovered link

**Subnet link**:
A connection inferred because two interfaces share a point-to-point subnet, including tunnels; shown apart from neighbor links, never as their equal.
_Avoid_: Inferred link, IP link, L3 link

**Unlinked device**:
An inventory device with no neighbor link or subnet link found; it is still drawn and reported, never dropped.
_Avoid_: Orphan, missing device

**Unknown neighbor**:
A device that a neighbor link reports but the inventory does not list.
_Avoid_: Unmanaged device, rogue device

### Intent and state

These follow the Network Automation Forum (NAF) framework's Intent and Observability blocks.

**Network intent**:
What the network should look like: configuration and operational expectations, as the engineers designed them (NAF: the intended or desired state).
_Avoid_: Desired config, golden config (a golden config is one device's slice of intent)

**Network state**:
What the network looks like right now, as the devices report it (NAF: the actual state). network-snapshot collects it and keeps it in the snapshot repo.
_Avoid_: Current config, live data

**Source of truth**:
Where network intent is kept and served through an API, such as NetBox; it may combine several data sources (NAF's Intent block). The skills never act as one.
_Avoid_: Inventory, CMDB (as a synonym)

**Drift**:
A difference between network intent and network state, found by comparing the two.
_Avoid_: Config change (a change can be intended)

**Inventory**:
The skills' working copy of part of network intent: the devices to connect to (`inventory.yaml`) and their device tags. Where a source of truth exists, the inventory is filled from it, never kept by hand in both places.
_Avoid_: Source of truth, device database

**Device tag**:
A piece of intent about a device that no show command can reveal: device role, asset criticality, exposure. A skill may suggest one; only the engineer's approval writes it.
_Avoid_: Label, attribute, per-skill setting

### Skills

**Read-only skill**:
A skill that only reads from devices and can never change their config.

**Write skill**:
A skill that changes device config. Today only network-push.
_Avoid_: Push skill (as a category)

### Snapshots

**Snapshot**:
One run that reads every targeted device and records what it shows, committed to the snapshot repo as one change.
_Avoid_: Backup, capture

**Committed output**:
The config and stable show output a snapshot keeps in git, cleaned of clocks, timers and counters so a quiet network shows no change.
_Avoid_: Config backup (it holds more than config)

**Device state**:
Tables that change on their own (ARP, MAC table, DHCP bindings, protocol detail), collected on every snapshot and kept for this run and the one before, never committed.
_Avoid_: Health (health is how well the device is running, collected only on request)

**Health output**:
Raw counters and measurements (CPU, errors, logs) collected only when a health check asks, kept for this run and the one before.

**Host table**:
One row per end host a snapshot saw, joining ARP, MAC table, neighbor and DHCP data, each row naming the sources that showed it.
_Avoid_: Inventory, discovery, CMDB

**Edge port**:
The switch port where a host's MAC address is learned that is not a link to another network device.
_Avoid_: Access port (a config mode, not a finding)

**No data**:
A command the device accepted that had nothing to show (no IPv6 in that VRF, BGP not running).
_Avoid_: Error, unsupported

### Contributing

**Test report**:
A contributor's account of running a skill on a platform, with evidence attached.
_Avoid_: Vendor report, bug report (a bug report is narrower: something broke)

**Evidence**:
Redacted output from a real run in a lab or on a real network. Required for any test report or status change; AI may write the words, never the evidence.

**Contributor**:
Anyone whose issue, test report or pull request lands in the project, whether or not they wrote code.

### Security

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
A CVE matches the device's version, but the saved output cannot show whether its vulnerable condition holds, or the platform's condition checks are not proven yet (version match only, such as PAN-OS today). What the saved output suggests is then shown as a **lead**, never as the call.
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

**Upgrade target**:
The one release a device should move to: the earliest named fixed release that clears every affected CVE on it, never older than the running release, and not on a train known to be past its end of security support where another fixes them.
_Avoid_: Recommended version, fixed version (a fixed release belongs to one CVE)

**End of security support**:
The vendor's date after which a release train gets no more security fixes; a device past it cannot be patched in place and must move to a supported release or be replaced.
_Avoid_: End of life, EOL, end of sale

**Asset criticality**:
How much the business depends on a device: essential, support or minimal.
_Avoid_: Importance, tier, role

**Accepted risk**:
An affected CVE on a device that the owner decided to live with for now, written down with a reason and a required expiry date; it leaves the priority counts but stays listed in its own report section until it expires.
_Avoid_: Waiver (for CVEs), exception (as the report term), suppression, false positive

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
