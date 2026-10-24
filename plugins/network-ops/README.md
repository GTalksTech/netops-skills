# network-ops

AI skills for network engineers from G Talks Tech, in one Claude Code plugin. Install it once and
you get every skill, including the ones that ship with future videos.

| Skill | What it does |
|---|---|
| network-snapshot | Read-only snapshot of every device, saved to git, with what changed since last time |
| network-health-check | Is the network healthy right now (coming soon) |

## network-snapshot

A skill that takes a read-only snapshot of your network, saves it to git, and tells
you in plain words what changed since last time: failures first, then reboots, then every real
change, device by device.

It logs in over SSH with a read-only account, runs a fixed list of show commands for each vendor,
throws away the lines that change on their own (clocks, timers, counters), and commits the result.
Run it twice in a row on a quiet network and the second run shows no changes. So when something
shows up, it really changed.

Video: VIDEO_URL_PLACEHOLDER (Claude Code for network engineers). Built and tested on the
G Talks Tech lab v2 (Cisco IOS-XE campus, branch and ISP routers, plus a FortiGate).

## Install

In Claude Code:

```
/plugin marketplace add GTalksTech/netops-skills
/plugin install network-ops@netops-skills
```

Then Python 3.9 or newer with the packages in `skills/network-snapshot/requirements.txt`
(`pip install -r requirements.txt`), and git on your PATH.

## Set up (once)

1. **A read-only account on every device.** See the table below. The skill never configures
   anything, but a read-only account means it can't, even by mistake.
2. **An inventory.** Copy `skills/network-snapshot/inventory.example.yaml` to
   `~/network-snapshots/inventory.yaml` and list your devices: name, IP or hostname, site, and
   device type. Or just ask Claude to build it from your device list.
3. **Passwords, into your OS credential store** (Windows Credential Manager, macOS Keychain, or
   Linux Secret Service). Run this yourself, once per username:

   ```
   python skills/network-snapshot/scripts/snapshot.py --set-credential <username>
   ```

   Passwords never go in a file, a command line or the chat. If two device groups share a username
   but not a password, give each a `credential:` name in the inventory and store each one.

## Use

Ask Claude: "take a network snapshot", "snapshot the branch1 site", "what changed on the network
since yesterday?" Or run a snapshot before a change window and another after it, and ask Claude
what changed between the two.

Snapshots live in `~/network-snapshots`, one folder per site and device, one file per command,
one git commit per run. It's a normal git repo, so `git log` is your change history.

## Vendors

| Vendor | Profile | Status |
|---|---|---|
| Cisco IOS / IOS-XE | `cisco_ios` | Tested (lab v2, eleven devices) |
| Fortinet FortiGate | `fortinet` | Tested (lab v2, FortiOS 8.0.1) |
| Cisco NX-OS | `cisco_nxos` | Untested: written from Cisco docs |
| Cisco ASA | `cisco_asa` | Untested: written from Cisco docs |
| Arista EOS | `arista_eos` | Untested: written from Arista docs |
| Juniper Junos | `juniper_junos` | Untested: written from Juniper docs |
| HPE Aruba AOS-CX | `aruba_aoscx` | Untested: written from HPE Aruba docs |
| Palo Alto PAN-OS | `paloalto_panos` | Untested: written from Palo Alto docs |

Untested means the commands come from the vendor's documentation but haven't run against a real
device yet. If a command gets rejected or a line changes on every run, the profile needs a fix,
and pull requests are welcome.

**Add a vendor** by adding one file to `skills/network-snapshot/platforms/`, named after its
Netmiko device type. No Python changes. Every command in a profile has to start with `show`,
`get` or `display`, or the script refuses to load it.

## Read-only accounts, by vendor

Lab examples. Use your own names and strong passwords, or your TACACS/RADIUS read-only role.

**Cisco IOS / IOS-XE** (tested): a privilege 5 user that can still read the full config.

```
aaa new-model
aaa authentication login default local
aaa authorization exec default local
username netops-ro privilege 5 secret <password>
privilege exec level 5 show running-config view full
privilege exec level 5 show startup-config
privilege exec level 5 show spanning-tree inconsistentports
privilege exec level 5 show spanning-tree blockedports
```

Plain `show running-config` comes back empty at privilege 5, which is why the profile uses
`show running-config view full`. The other three lines open up commands that privilege 5 can't
run by default (tested on IOS-XE 17.16). Hardware commands (`show environment all`,
`show power inline`, `show platform resources`, transceivers, stacks, licenses) only answer on
physical devices. On virtual ones they're listed as unsupported, which is expected.

**Fortinet FortiGate** (tested): a read-only admin profile plus an SSH admin that uses it. SSH
must be allowed on the management interface (`set allowaccess ping https ssh`). Custom profiles
start with every CLI permission off, so a read-only admin can log in but can't run `show` or
`get` until you turn on `cli-get` and `cli-show`. Leave `cli-config`, `cli-exec` and
`cli-diagnose` off. If the name is already taken by a REST API user, pick another name: FortiOS
won't let an admin and an API user share one.

```
config system accprofile
    edit "read-only"
        set cli-get enable
        set cli-show enable
        set secfabgrp read
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
        set vpngrp read
        set utmgrp read
        set wanoptgrp read
        set wifi read
    next
end
config system admin
    edit "netops-ro"
        set accprofile "read-only"
        set vdom "root"
        set trusthost1 <your-mgmt-subnet> <mask>
        set password <password>
    next
end
```

**Untested vendors**, built-in read-only roles:
- Cisco NX-OS: role `network-operator`.
- Arista EOS: role `network-operator`.
- Juniper Junos: login class `read-only`.
- HPE Aruba AOS-CX: group `operators`.
- Palo Alto PAN-OS: admin role "Superuser (read-only)".
- Cisco ASA: a user at a privilege level that has the show commands in the profile (ASA command
  authorization).

## Safety

- Show commands only. The script checks every profile command before it runs anything.
- Passwords stay in the OS credential store.
- The snapshot repo holds full device configs. Keep it private, and don't push it anywhere public.

## License

MIT.
