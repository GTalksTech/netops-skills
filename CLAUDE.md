## Branches and sessions

Work that is not merged to main lives on its feature branch until Garrett reviews it. A new
session that continues that work must start from that branch (the repo folder, or a worktree
based on that branch), never from main or another session's `.claude/worktrees/` folder. If
setup files or expected work seem missing, check `git branch --show-current` and the open
feature branches before suggesting setup or a merge. (Learned 2026-11-26: a session started in a
stale worktree based on main and asked to re-run setup.)

## Versions

Bump only the last number (0.3.1 to 0.3.2) for a fix or a small feature. A middle-number bump
(0.3 to 0.4) is Garrett's call, never Claude's. (Learned 2026-11-28: a small first-run setting
was shipped as 0.4.0.)

## GitHub account

All GitHub work in this repo (push, gh issues/PRs/comments, commit author) uses the GTalksTech
account, never gmasters428. Before any gh write, check `gh api user --jq .login` says GTalksTech;
on this desktop `.claude/settings.local.json` sets `GH_CONFIG_DIR` to a GTalksTech-only gh config.
(Learned 2026-11-27: gh ran as gmasters428, which has read-only access, so ticket claims and
closes failed.)

## Agent skills

### Issue tracker

Issues and specs live in this repo's GitHub Issues (gh CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

The five default triage labels, used as-is. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
