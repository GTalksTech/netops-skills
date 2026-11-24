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

### Skills

**Read-only skill**:
A skill that only reads from devices and can never change their config.

**Write skill**:
A skill that changes device config. Today only network-push.
_Avoid_: Push skill (as a category)

### Contributing

**Test report**:
A contributor's account of running a skill on a platform, with evidence attached.
_Avoid_: Vendor report, bug report (a bug report is narrower: something broke)

**Evidence**:
Redacted output from a real run in a lab or on a real network. Required for any test report or status change; AI may write the words, never the evidence.

**Contributor**:
Anyone whose issue, test report or pull request lands in the project, whether or not they wrote code.
