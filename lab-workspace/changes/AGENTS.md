# Network changes

Every change is one file, `changes/YYYY-MM-DD-<short-name>.md`, in four parts:

1. Pre-check: run the network health check and save the result.
2. Change: the exact commands, device by device, in the order they get pushed.
3. Post-check: the same health check, compared with the pre-check.
4. Rollback: complete enough to run on its own, without reading part 2.

Write the plan and stop. End your reply with the plan file's path and: "Review the plan.
When you approve it, say 'approved' and I'll push it." Nothing gets
pushed until I say approved. Pushes use the admin account; everything else stays read-only.
Push only with the network-push skill, never a script of your own. It puts every switch
command in the approval prompt itself, stops on an error, and records what it sent in the
change folder. Interface descriptions go in one batch approval; every other change is one
device per approval, in the order the plan sets. Save config only after the post-check
passes; a rollback saves too.
Interface descriptions say what the config makes true (role, peer, circuit, HSRP group),
never state that can change on its own (HSRP active or standby, up or down).

## Runbooks

Standard changes have a runbook in `changes/runbooks/`, one file per change type.
Before planning a change, check that folder. If a runbook matches, follow it and say
in the plan which runbook you used. If none matches, plan from the network snapshot
and say that no runbook covered it.
