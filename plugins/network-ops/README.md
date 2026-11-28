# network-ops

AI skills for network engineers from G Talks Tech, in one Claude Code plugin. Install it once and
you get every skill, including the ones that ship with future videos.

| Skill | What it does |
|---|---|
| network-snapshot | Read-only snapshot of every device, saved to git, with what changed since last time, plus ARP, MAC and DHCP tables and a host table of where each address sits |
| network-push | Puts an approved change on the network: shows every switch command in the approval prompt, pushes one device at a time (descriptions can batch) with a separate change account, stops on errors, logs what it sent |
| network-health-check | Is the network healthy right now: whole network, one site or one device. Read-only; findings worst first with evidence and fix, then what checked out healthy |
| network-diagram | Editable draw.io diagram from your snapshots and/or a spreadsheet of links: physical, subnet and VLAN pages, including the firewalls and tunnels CDP/LLDP can't see. Read-only; kept in git next to the snapshots |

## network-snapshot

A skill that takes a read-only snapshot of your network, saves it to git, and tells
you in plain words what changed since last time: failures first, then reboots, then every real
change, device by device.

It logs in over SSH with a read-only account, runs a fixed list of show commands for each vendor,
throws away the lines that change on their own (clocks, timers, counters), and commits the result.
Run it twice in a row on a quiet network and the second run shows no changes. So when something
shows up, it really changed.

Each run collects three things:

- **Committed output**, in git: config plus stable structure. On Cisco that now includes every
  VRF's routes and routing protocols (not just the global table), BGP in every address family,
  full `show ip interface`, OSPF interface detail, spanning tree per VLAN, LACP and UDLD partners
  and more. On FortiGate, every interface, VRRP, managed FortiSwitches and FortiAPs.
- **Device state**, kept out of git: ARP per VRF, MAC tables, DHCP bindings, BGP and OSPF detail,
  NAT, multicast. This run and the previous one sit in `.snapshot/state/`. `--no-state` skips it;
  `--full` adds the heavy ones (full OSPF database, crypto SAs).
- **A host table**, `.snapshot/hosts.csv`: ARP, MAC tables, CDP/LLDP and DHCP joined into one row
  per address, with the switch port where it was learned and the tables that showed it. A host seen
  only on uplinks is marked as such; nothing is guessed. Each run lists the hosts new and gone
  since the last one.

Commands for features a device's config doesn't use are skipped, so routers don't run switch
commands. On the lab (eleven IOL devices and a FortiGate-VM, eight in parallel) a full run takes
about 50 seconds. Real hardware with large tables is slower.

What it still can't see: devices you don't give it, hosts that were quiet long enough to age out
of ARP and MAC tables, what sits behind an unmanaged switch, cabling and anything physical, and on
FortiGate anything behind `diagnose` or `execute` (LLDP, the device list, DHCP leases, SD-WAN
state), plus FortiGates with VDOMs on. There is no size limit yet for very large route or MAC
tables. The full list is in `skills/network-snapshot/references/coverage.md`.

Which commands to run, and how to read ARP, MAC and neighbor tables, drew on what SuzieQ, Cisco
Genie, NAPALM, ntc-templates and IP Fabric publish about their own collection. No code or
templates were copied; the research is in [docs/snapshot-state-research.md](../../docs/snapshot-state-research.md).

**Upgrading from 0.2:** the first run after the upgrade shows `show ip route`, `show vrf` and
`show ip bgp summary` replaced by their all-VRF forms, new files added, and timers written as `--`.
That's the upgrade, not your network. The run after it is quiet again.

Video: https://youtu.be/njerxFIa974 (How to Use Claude Code as a Network Engineer). Built and tested on the
G Talks Tech lab v2 (Cisco IOS-XE campus, branch and ISP routers, plus a FortiGate).

## network-diagram

Draws your network from the show output network-snapshot already saved: one draw.io file with a
page per layer (Physical L1, Subnets L3, VLANs L2), opened in app.diagrams.net with nothing to
install. Links come from CDP and LLDP, from two interfaces sharing a /30 or /31 (that's how a
firewall or a GRE tunnel shows up when it doesn't speak CDP/LLDP: drawn dashed, so you can see what
discovery missed), and from a spreadsheet you give it (`device, port, port, device`). Run it after
the daily snapshot and the diagram in git is never older than the last snapshot.

```
python skills/network-diagram/scripts/diagram.py run          # uses your snapshot repo
python skills/network-diagram/scripts/diagram.py run --links links.csv --out ./diagram   # spreadsheet only
python skills/network-diagram/scripts/diagram.py run --open   # then show it
```

`--open` shows the finished diagram: in draw.io Desktop if it's installed, else in your browser at
app.diagrams.net, with the diagram packed into the link after `#` (browsers never send that part
to the server, so the diagram stays on your machine). A diagram too big for a link isn't opened:
use File > Open from > Device, or install draw.io Desktop. Nothing opens without `--open`; the
skill asks first, and scheduled runs never use it.

Devices are placed by their **role** (`provider`, `edge`, `firewall`, `core`, `distribution`,
`access`): an optional `role:` in `inventory.yaml`, else guessed from the name and listed for you
to confirm. The same role tag is shared by every network-ops skill (docs/adr/0002).

## network-health-check

Answers one question: is the network healthy right now? Ask "health check the network", "is
hq healthy?" or "is hq-dist-sw-02 ok?". It runs the snapshot engine with `--health` (same
read-only account, same setup) and checks, in the order an engineer would look:

1. Every device reachable
2. Hardware: the device's own alarms, power supplies, fans, temperature
3. Redundancy: firewall HA, stacks, vPC / MLAG / VSX / VLT, supervisor failover
4. Reboots and crashes, with the reload reason
5. Routing: OSPF, BGP, EIGRP neighbors, adjacencies that reset recently, IP SLA, the default route
6. HSRP / VRRP active and standby, and whether the active switch is the spanning-tree root
7. Interfaces that should be up but are down, and err-disabled ports with the reason
8. Port-channel members
9. Interface errors and drops that are growing (not old totals)
10. Uplinks and the internet link near capacity
11. Link flaps
12. Spanning tree: inconsistent ports and recent topology changes (blocked ports on redundant
    uplinks are normal and never flagged)
13. Optic light levels against the optic's own thresholds
14. CPU, memory, session tables and storage
15. Errors in the logs, grouped, with known noise left out
16. NTP
17. Unsaved config and debugging left on

Error counters are judged by growth: each run keeps the previous run's raw output, so the report
says "409 new CRC errors in 43 minutes", not "CRC is non-zero". The first run only has totals and
says so.

The report lists findings first, worst first, each with the device, the evidence (command and
file) and the fix, then one line per check that came back healthy (with the numbers), then what
it could not check and why. A command the device refuses is never counted as healthy. It goes in
your workspace's `reviews/` folder, one file per run, and each run is compared with the one
before. Why each check is in, and its sources: [docs/health-check-research.md](../../docs/health-check-research.md).

Vendor coverage: every profile has health commands. Cisco IOS/IOS-XE and FortiGate are lab-tested.
FortiGate can't report interface errors, load, NTP sync or logs, because those need `diagnose`
or `execute`, which a read-only account can't run. The other profiles are untested: they were
written from vendor documentation, and anything that doesn't parse is listed as not checked.

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
2. **A snapshot repo.** One git repo per network holds its snapshots, kept outside your project
   folders: the network outlives any project, and its configs are too sensitive for a project
   repo that may be public. The first time you run a skill, Claude asks where to keep it
   (`~/network-snapshots` is a good choice) and saves your answer. Or set it yourself:

   ```
   python skills/network-snapshot/scripts/snapshot.py --set-repo ~/network-snapshots
   ```

   Every skill and every scheduled run uses it from then on, and each run prints
   `Snapshot repo: <path> (network: <name>)` so you always know where the files went. Move it
   later with `--set-repo PATH --replace`. More than one network: add `--network NAME` when you
   set each one, then pick one per run with `--network NAME`, or put a `.netops.yaml` holding
   `network: NAME` in a project folder (it holds no data, so it's safe to commit). The settings
   live in `%APPDATA%\netops\config.yaml` on Windows and `~/.config/netops/config.yaml`
   elsewhere (`NETOPS_CONFIG` overrides). Upgrading from 0.3 with snapshots in
   `~/network-snapshots`: the first run finds them, saves that folder and says so.
3. **An inventory.** Copy `skills/network-snapshot/inventory.example.yaml` to
   `inventory.yaml` in your snapshot repo and list your devices: name, IP or hostname, site, and
   device type. Or just ask Claude to build it from your device list.
4. **Passwords.** The simplest home is your OS credential store (Windows Credential Manager,
   macOS Keychain, or Linux Secret Service). Run this yourself, once per username:

   ```
   python skills/network-snapshot/scripts/snapshot.py --set-credential <username>
   ```

   Already use a vault or password manager, or running in CI? See [Credentials](#credentials).
   Passwords never go in the inventory, a command line or the chat. If two device groups share a
   username but not a password, give each a `credential:` name in the inventory and store each one.

## Credentials

Every network-ops skill gets a password the same way (`lib/credentials`). For each credential name
(the device's `username`, or its `credential:` name) it tries, in order:

1. **An environment variable**, `NETOPS_SECRET_<NAME>`: the name in capitals, anything other than
   a letter or digit as `_`. `svc-netops-ro` reads `NETOPS_SECRET_SVC_NETOPS_RO`. For CI secrets,
   and for wrappers that inject secrets into a child process (`op run`, `bws run`, Vault Agent).
2. **A command you configure** in the inventory, whose output is the password. Any vault or
   password manager CLI works; `{name}` becomes the credential name.
3. **The OS credential store**, service `netops-skills`, where `--set-credential` saves it.

A method that has nothing for a name passes to the next one. If none has it, that device fails
with a message listing what was tried; the run carries on with the rest. Each name is looked up
once per run and kept in memory only. No secret is printed, logged or written to a report, and
the error for a failed command never includes what it printed.

```yaml
# inventory.yaml
credentials:
  command: bw get password {name}    # or a list: ["C:/Tools/vault.exe", "read", "{name}"]
  timeout: 30                        # seconds, default 30
```

The command runs with no shell and no keyboard input, so a CLI that would stop to ask for a
password fails instead of hanging. Write paths with `/`, or use the list form. Anyone who can edit
the inventory can choose this command, so keep the inventory as private as the snapshots.

**Worked example: Bitwarden.** Save each password as a login item named after its credential
(for example `svc-netops-ro`). Then, once per terminal session, in your own terminal:

```
bw login                      # once per machine; or BW_CLIENTID / BW_CLIENTSECRET + bw login --apikey
bw unlock --raw               # asks for your master password, prints a session key
```

Set `BW_SESSION` to that key (`export BW_SESSION=...`, or `$env:BW_SESSION = "..."` in
PowerShell), add the `credentials:` block above, and run the skill from the same terminal.
`bw get password {name}` reads the item with that name. If more than one item matches, `bw`
fails rather than guess: rename one, or give that device a `credential:` holding the item id. Other CLIs drop in the same way, for example
`op read op://Network/{name}/password` (1Password) or
`vault kv get -mount=secret -field=password netops/{name}` (HashiCorp Vault).

## Use

Ask Claude: "take a network snapshot", "snapshot the branch1 site", "what changed on the network
since yesterday?" Or run a snapshot before a change window and another after it, and ask Claude
what changed between the two.

Snapshots live in the snapshot repo you chose on first use (the `Snapshot repo:` line of every
run names it), one folder per site and device, one file per command, one git commit per run.
It's a normal git repo, so `git log` is your change history. A scheduled run should name its
network or folder (`--network NAME` or `--repo PATH`), so changing your default later can't move
it.

## Vendors

| Vendor | Profile | Status |
|---|---|---|
| Cisco IOS / IOS-XE | `cisco_ios` | Lab-tested (CML lab v2, eleven IOL devices) |
| Fortinet FortiGate | `fortinet` | Lab-tested (FortiGate-VM 8.0.1) |
| Cisco NX-OS | `cisco_nxos` | Untested: written from Cisco docs |
| Cisco ASA | `cisco_asa` | Untested: written from Cisco docs |
| Arista EOS | `arista_eos` | Untested: written from Arista docs |
| Juniper Junos | `juniper_junos` | Untested: written from Juniper docs |
| HPE Aruba AOS-CX | `aruba_aoscx` | Untested: written from HPE Aruba docs |
| Palo Alto PAN-OS | `paloalto_panos` | Untested: written from Palo Alto docs |
| Huawei VRP | `huawei_vrp` | Untested: written from Huawei docs |
| Extreme EXOS | `extreme_exos` | Untested: written from Extreme docs |
| Dell EMC OS10 | `dell_os10` | Untested: written from Dell docs |
| HPE ArubaOS-Switch | `hp_procurve` | Untested: written from HPE Aruba docs |
| Nokia SR OS | `nokia_sros` | Untested: written from Nokia docs |

Untested means the commands come from the vendor's documentation but haven't run on a device yet.
Lab-tested means they ran on a virtual image (CML, containerlab, a vendor VM). Tested means real
hardware. If you run a skill on any of these, a [test report](../../CONTRIBUTING.md) moves the
platform up, and "it just worked" counts.

**Add a vendor** by adding one file to `skills/network-snapshot/platforms/`, named after its
Netmiko device type. No Python changes. Every command in a profile has to start with `show`,
`get` or `display`, or the script refuses to load it. The keys (committed, state and health
commands, per-VRF commands, `when:` conditions, masks) are in
`skills/network-snapshot/references/profiles.md`.

## Read-only accounts, by vendor

Give the skills their own account, used by nothing else: a dedicated read-only automation
identity such as `svc-netops-ro`, never a person's account, a shared admin, or the device's
break-glass local account.

- **TACACS+, where you have it:** define the account on the TACACS+ server with command
  authorization that allows only `show`, `display` and `get` style commands, plus command
  accounting, so every command the skills run is logged centrally.
- **RADIUS otherwise:** return a read-only role for the account (Cisco privilege level, Juniper
  class, Arista role, Aruba read-only role). RADIUS can't authorize per command, so the role is the
  limit.
- **Local, with no AAA (home lab, small sites):** a local read-only user per device, as below.
  STIG-bound networks allow one local account (break-glass), so there the account has to come
  from AAA.

Keep its password in a vault ([Credentials](#credentials)) and rotate it on your usual schedule.

Lab examples. Use your own names and strong passwords, or your TACACS/RADIUS read-only role.

**Cisco IOS / IOS-XE** (lab-tested): a privilege 5 user that can still read the full config.

```
aaa new-model
aaa authentication login default local
aaa authorization exec default local
username netops-ro privilege 5 secret <password>
privilege exec level 5 show running-config view full
privilege exec level 5 show startup-config
privilege exec level 5 show spanning-tree inconsistentports
privilege exec level 5 show spanning-tree blockedports
privilege exec level 5 show logging
```

For the full health check, a privilege 5 account also needs the health commands lowered to its
level (each `show ...` in the `health_commands` list of `platforms/cisco_ios.yaml`), or it gets
"% Invalid input" for them and the report lists them as not checked. The quickest way is
`privilege exec all level 5 show`, which lowers every `show` command.

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

The console must print output without paging. Most FortiGates already do; if yours pages (the
skill refuses it and says so), set it once from an admin session:

```
config system console
    set output standard
end
```

The skill never makes this change itself. The SSH library it uses (Netmiko) would quietly do it
on login and put it back on logout; the skill turns that off and refuses instead, because a
read-only tool should not write config. FortiGates with VDOMs on are refused for the same reason
(reading the setting needs `config global`); VDOM support isn't built yet.

**Untested vendors**, built-in read-only roles:
- Cisco NX-OS: role `network-operator`.
- Arista EOS: role `network-operator`.
- Juniper Junos: login class `read-only`.
- HPE Aruba AOS-CX: group `operators`.
- Palo Alto PAN-OS: admin role "Superuser (read-only)".
- Huawei VRP: a level 1 (monitoring) user; `display` commands are available in user view.
- Extreme EXOS: a user-level (non-admin) account.
- Dell OS10: role `netoperator`.
- HPE ArubaOS-Switch: the operator account.
- Nokia SR OS: a user profile that allows `show` only.
- Cisco ASA: a user at a privilege level that has the show commands in the profile (ASA command
  authorization).

## Safety

- Snapshot: show commands only. The script checks every profile command before it runs anything,
  and checks again every command it builds from device output (a VRF name must be plain letters,
  digits and `_.:-` before it goes into a command). It never sends `diagnose`, `execute`, `config`
  or a pipe that writes a file, and it refuses a FortiGate it can't read without changing config.
- The host table and device state stay in the snapshot repo's `.snapshot/` folder, which is not
  committed. They list every address on your network, so keep them as private as the configs.
- Push: one device per run, with a separate change account (`push.py --set-credential admin`), only on
  tested profiles (`cisco_ios` today). It refuses destructive commands and a trunk `allowed vlan <list>`
  without `add`, and saves config only when you ask (after your post-check).
- Passwords come from an environment variable, your vault's CLI or the OS credential store, and
  are never printed, logged or written to a report.
- The snapshot repo holds full device configs. Keep it private, and don't push it anywhere public.

## License

MIT.
