---
name: network-push
description: Use when an approved change plan is ready to go onto network devices: pushing config to a switch, router or firewall, applying a change file, or saving config after a post-check. Previews each device's commands, pushes one device at a time with the change account, stops on errors and logs what was sent.
---

# Network push

The only way config goes onto a device. One script, `scripts/push.py`, three actions:

- `preview DEVICE FILE`: prints the device and the exact commands. Sends nothing.
- `push DEVICE FILE`: sends that one file to that one device with the change account
  (default `admin`, password from the OS credential store). Stops on the first device
  error and logs everything it sent to `push-log.md` next to the file.
- `save DEVICE [DEVICE ...]`: saves the running config. Only after the post-check passes.
- `batch DEVICE=FILE [DEVICE=FILE ...]`: several devices under ONE approval, pushed in the
  order given, stopping at the first failure. The script allows only interface description
  lines in a batch and refuses the whole batch otherwise. Add `--preview` to see it first.

It uses the network-snapshot skill's inventory, vendor profiles and credential store. Run it
the same way you run `snapshot.py` (same Python). Pushes work on tested profiles only
(`cisco_ios` today); anything else is refused.

## Rules

- Only push from an approved change plan. If there is no plan, or the user hasn't approved
  it, stop and say so.
- Low-risk, cosmetic changes (interface descriptions only) go in one `batch`, so the user
  approves them once. Everything else is one device per `push` command, in the order the plan
  sets, so every impactful push is its own approval. Never loop devices in one command or
  write your own push script.
- Keep descriptions and other changes in separate files, so the descriptions can batch.
- Before every push or batch, run `preview` (or `batch ... --preview`) and show the commands in
  your message. The user approves right under them.
- Write each device's commands to its own file in the change folder (for example
  `changes/2026-10-30-vlan40/hq-dist-sw-01.txt`). The files and `push-log.md` are the record
  of what was sent.
- If a push fails, stop. Lines sent before the error are on the device. Re-read the device
  (a snapshot of that device) before you suggest anything, and offer the plan's rollback.
- The script refuses destructive lines and a trunk `allowed vlan <list>` without `add`. Never
  work around a refusal; fix the command file.
- Save only when the post-check passes, with one `save` listing every device touched. A
  rollback ends with a save too.

## Setup

The change account's password goes into the OS credential store once:
`python <this skill>/scripts/push.py --set-credential admin`
