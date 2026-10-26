# Lab workspace

The instructions files from the G Talks Tech lab-v2 build, exactly as used on camera.
Start Claude Code in this folder and your sessions follow the same rules mine do.

- `AGENTS.md`: the short main file. Every rule has a date and the mistake it prevents.
- `.claude/rules/network-changes.md`: loads only when Claude works in `changes/`.
- `reviews/AGENTS.md`: loads only when Claude works in `reviews/`.

## Use it

1. Copy this folder to wherever you run Claude Code against your lab.
2. Edit "The network" and "Known lab exceptions" in `AGENTS.md` to match your lab.
   The device list path and credential service match the network-ops plugin's setup.
3. Start Claude Code in that folder. With no CLAUDE.md there, Claude Code v2.1.277
   or later reads AGENTS.md on its own. Codex and other agents that support
   AGENTS.md read it too.

Already have a CLAUDE.md? Then Claude Code reads your CLAUDE.md and skips AGENTS.md.
Put `@AGENTS.md` on the first line of your CLAUDE.md to pull it in. A `CLAUDE.local.md`
counts as a CLAUDE.md for this check.

Source: Claude Code memory docs, https://code.claude.com/docs/en/memory (checked 2026-10-13).
