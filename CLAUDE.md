## Branches and sessions

Work that is not merged to main lives on its feature branch until Garrett reviews it. A new
session that continues that work must start from that branch (the repo folder, or a worktree
based on that branch), never from main or another session's `.claude/worktrees/` folder. If
setup files or expected work seem missing, check `git branch --show-current` and the open
feature branches before suggesting setup or a merge. (Learned 2026-11-26: a session started in a
stale worktree based on main and asked to re-run setup.)

## Agent skills

### Issue tracker

Issues and specs live in this repo's GitHub Issues (gh CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

The five default triage labels, used as-is. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
