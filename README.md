# NetOps Skills

AI skills for network engineers. Install once with Claude Code, then run real workflows against your network.

Built and maintained by [Garrett Masters](https://gtalkstech.com) of **G Talks Tech · The AI-Augmented Engineer**.

## Install

Add the marketplace once, then install the plugin:

```
/plugin marketplace add GTalksTech/netops-skills
/plugin install network-ops@netops-skills
```

## What's inside

**network-ops**, one plugin with every skill. New skills arrive as plugin updates.

| Skill | What it does |
|---|---|
| network-snapshot | Read-only snapshot of every device (configs and key state), saved to git, with Claude explaining what changed since last time. Cisco IOS/IOS-XE and FortiGate tested; six more vendors included and marked untested. |
| network-health-check | Is the network healthy right now. Coming soon. |

Setup, vendors and read-only account steps: [plugins/network-ops/README.md](plugins/network-ops/README.md).

## Related

Scripts, prompt packs, and lab templates live in [netops-toolkit](https://github.com/GTalksTech/netops-toolkit).
