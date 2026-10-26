# AGENTS.md: lab v2 workspace

Instructions for any coding agent working in this folder (Claude Code, Codex, and
others that read AGENTS.md). Keep this file short: under 200 lines. Rules for one
kind of job live next to that job, not here.
Before writing in `changes/` or `reviews/`, read that folder's AGENTS.md.

Every rule has a date and the mistake behind it. When an agent gets something
wrong twice, add a rule the same day, in the same shape. When a rule stops
earning its place, delete it.

## The network

- Lab v2: an HQ campus (edge router, FortiGate fw-01, core, two distribution
  switches, four access switches), a branch over GRE, and a simulated ISP.
- The device list is `~/network-snapshots/inventory.yaml`. Never connect to a
  device that is not on it.
- Credentials come from the OS credential store (service `netops-skills`).
  Never write them into a file, a commit or the chat.
- Know the current state before answering: take a network snapshot first, then
  work from it. Go to a device only when the snapshot is stale or missing.

## Known lab exceptions

Real choices for a lab. Note them, but do not report them as problems:
console with no login, no OSPF / HSRP / BGP authentication, no HSRP uplink tracking
(the lab switch image has no object tracking), SNMP v2c, public lab passwords. The lab image logs `%CRYPTO-0-SELF_TEST_FAILURE ... Bypassed` at every boot:
that is the lab image, not a fault. isp-rtr-01 plays the internet: it is outside the HQ
and branch review.

## Rules

- 2026-10-13 | Read-only by default.
  Use the read-only account and show commands. Changes follow `changes/AGENTS.md`
  and wait for my approval.
  Mistake it prevents: an agent "fixing" a device it was asked to look at.

- 2026-10-13 | Plan first for any job with several steps that changes something.
  Explore, write the plan, wait for "go," then do it. A quick question can go straight through.
  Mistake it prevents: guessing at a multi-step job instead of planning it.

- 2026-10-23 | On Cisco IOS, read config with `show running-config view full`.
  Plain `show running-config` comes back nearly empty for the read-only account.
  Mistake it prevents: reporting a device as having no config.

- 2026-10-23 | Ask before resetting or re-importing the lab.
  A reset rebuilds every device and takes about 30 minutes.
  Mistake it prevents: a reset that knocked out a snapshot test running in
  another session.

- 2026-10-13 | Cite the evidence.
  Every claim about a device names the command or snapshot file it came from.
  Mistake it prevents: a confident answer about a line that is not there.
