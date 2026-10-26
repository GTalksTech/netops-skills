# Network changes

Every change is one file, `changes/YYYY-MM-DD-<short-name>.md`, in four parts:

1. Pre-check: run the network health check and save the result.
2. Change: the exact commands, device by device, in the order they get pushed.
3. Post-check: the same health check, compared with the pre-check.
4. Rollback: complete enough to run on its own, without reading part 2.

Write the plan and stop. Nothing gets pushed until I say "go." Pushes use the admin
account; everything else stays read-only.

## Adding a VLAN to the HQ campus

- Create the VLAN on the six HQ switches that switch traffic: both distribution and
  all four access. VTP is transparent, so nothing propagates on its own. The core has
  only routed ports: no VLAN there.
- Trunks: `switchport trunk allowed vlan add <id>`, on every trunk end, including the
  link between the two distribution switches. Never `allowed vlan <id>` without
  `add`: that replaces the list and drops every other VLAN on the trunk.
- Gateway: an SVI on both distribution switches with HSRP version 2. hq-dist-sw-01 is
  active (priority 110), hq-dist-sw-02 standby (90), both with `preempt delay minimum
  60`. No `track`: the lab switch image has no object tracking. dist-01 is already the spanning-tree root for new
  VLANs, so the gateway and the root stay on the same switch.
- Routing: add the new subnet to OSPF area 0 on both distribution switches, or it is
  never advertised.
- fw-01 needs nothing: its internal-10 object (10.0.0.0/8) already covers new subnets.
