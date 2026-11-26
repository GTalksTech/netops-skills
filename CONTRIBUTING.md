# Contributing

Contributions of any size and skill level are welcome. You don't have to write code to help.

## Ways to help

**Test a skill on your gear.** This is the most useful thing you can do. Most platforms are
written from vendor docs and have never run on a real device. Run a skill in your lab or
network, then open a [test report](https://github.com/GTalksTech/netops-skills/issues/new?template=1-test-report.yml).
"It just worked" counts. Looking for a place to start? Pick an issue labeled
[`good first issue`](https://github.com/GTalksTech/netops-skills/labels/good%20first%20issue).

**Report a bug** or **suggest a skill** from the [new issue page](https://github.com/GTalksTech/netops-skills/issues/new/choose).

**Ask a question or show what you built** in [Discussions](https://github.com/GTalksTech/netops-skills/discussions).

**Send a pull request.** Fixes, profile tweaks and docs can go straight to a PR. For a new
skill or a big rework, open an issue or discussion first so your time isn't wasted on something
that can't merge.

## Platform status

Each platform has a status for each skill:

| Status | Means |
|---|---|
| untested | Written from vendor docs, never run on a device |
| lab-tested | Ran on a virtual image (CML, containerlab, a vendor VM) |
| tested | Ran on real hardware |

A test report with evidence is how a platform moves up. If you tested it, your GitHub handle
goes in the profile as `tested_by`.

## The one rule: real evidence

Use AI to write your issue or PR, that's fine and encouraged. The output you paste has to come
from a real run, in a lab or on a real network. Redact hostnames, IPs, usernames and secrets
before you paste.

## network-push

network-push changes device config, so its code is written by the maintainer. Bugs and ideas for
it are very welcome as issues.

## What to expect

I read every issue and PR within a week. If something doesn't fit the project, I'll say why.
Everyone here follows the [Code of Conduct](CODE_OF_CONDUCT.md).

Thanks for helping make these skills work on more networks.
