# The inventory is a working copy of intent, with one set of device tags for every skill

Following the Network Automation Forum framework, network intent (what the network should look like)
belongs in a source of truth such as NetBox, and network state (what it looks like now) is what
network-snapshot collects into the snapshot repo. `inventory.yaml` is neither: it is the skills'
small working copy of part of intent, the devices to connect to plus the device tags no show command
can reveal (device role, asset criticality, exposure). When a source of truth is connected, the
inventory is filled from it rather than kept by hand in two places. Skills read state from the
snapshot repo and tags from the inventory; they may suggest a tag, but only the engineer's approval
writes one, through one shared tag writer in `lib/`.

Every skill reads the same tags. Device role (edge, firewall, core, distribution, access) replaces
the old per-platform `kind` override: `kind` is now derived from role (role firewall means kind
firewall), so a device is described once, not once per skill.

We rejected making the inventory a hand-kept intent YAML (engineers want a system with an API and a
UI, and two places for intent drift apart) and letting skills write discoveries into it
automatically (a wrong guess would become "truth" for every other skill).
