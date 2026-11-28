# network-ops shared library

Code that more than one network-ops skill uses lives here once, not copied into each skill
(ADR 0001, `docs/adr/0001-split-security-skills-share-plugin-code.md`). Skills ship together in
this plugin, so a skill's scripts can rely on this folder being next to `skills/`.

## Layout

One Python package per job, each a folder directly under `lib/`:

| Package | What it does | Used by |
|---|---|---|
| `devicefacts/` | Device facts from saved snapshot files (and, for FTD, saved FMC device records): version, model, internet-facing interfaces, features on / off / unknown, each with the lines that prove it | network-snapshot (host table), network-diagram (role and kind) |
| `credentials/` | A device password by credential name: environment variable, then the inventory's command, then the OS credential store | network-snapshot, network-push |
| `snapshotfiles/` | `slug(cmd)`: the file network-snapshot saves a show command's output to (`show running-config` → `show-running-config.txt`) | network-snapshot, network-diagram |
| `devicetags/` | The device tags every skill reads from the inventory (role, criticality, exposure; ADR 0002): role guessing, `kind` derived from role, and the approved-only tag writer | network-diagram, devicefacts |
| `topology/` | Devices and links from saved show output: CDP/LLDP neighbor links, subnet and tunnel links, port-channels, VLANs, trunks, spreadsheet links | network-diagram |
| `devicefacts/tables.py` | Rows from host and link tables: ARP, MAC table, trunks, CDP/LLDP, DHCP snooping and server bindings, FortiGate ARP and interface addresses; `norm_mac`, `short_if` | hosttable |
| `hosttable/` | The host table: those rows joined into one row per address (ip, mac, vrf, vlan, device, port, kind, sources, note), CSV in and out, new and gone since the last run | network-snapshot |

Rules for a new package:

- Its own folder with an `__init__.py` that says, in its header, what it does and how to call it.
- Settings it owns (YAML) sit inside its folder; skill-specific settings stay in the skill.
- Tests in `lib/tests/test_<package>.py`, run by `py -m pytest plugins` from the repo root.
- Only Python 3.9+ and `pyyaml` (`credentials` also uses `keyring`, already a snapshot
  dependency). Read-only unless the package's job is to write.

## Importing from a skill

A skill script puts `lib/` on the import path, then imports the package. Each skill that uses the
library does it with the same three-line module, `scripts/pluginlib.py`:

```python
import pluginlib  # noqa: F401  (puts plugins/network-ops/lib on sys.path)
import devicefacts
```

## devicefacts

```python
platforms = devicefacts.load_platforms()            # devicefacts/platforms.yaml
rec = devicefacts.read_device(entry, repo, platforms)
```

`entry` is one inventory entry (`name`, `site`, `device_type`, optional `kind` and
`exposure: public|internal`); `repo` is the network-snapshot repo. The device's files are read
from `<repo>/<site>/<name>/`. A skill may merge its own per-platform settings into `platforms`
(network-vuln-scan adds its CVE settings); each entry needs `vendor`, `kind`, `version` and
`config`.

The record:

| Field | Meaning |
|---|---|
| `version`, `model` | Read from the show output named in `platforms.yaml` |
| `version_evidence`, `model_evidence` | `<file>: <the line read>` |
| `os`, `os_evidence` | Which OS the device runs where one platform covers two (`cisco_ios`: `IOS XE` or `IOS`), from the `os:` rules in `platforms.yaml`; `None` elsewhere |
| `internet_facing`, `exposure_reason` | Whether the device faces the internet, and why (inventory override, interfaces, or an assumption for firewalls and unparsed configs) |
| `internet_interfaces` | `[{name, why, evidence}]`: each internet-facing interface or zone and its config lines |
| `interface_ips` | Every interface address (used to match event targets to a device) |
| `features` | `{name: {state, internet, where, evidence, detail}}` |
| `hostname`, `vendor`, `kind`, `notes` | `notes` lists what could not be read and why |
| `_parsed` | `{text, facts, dev}`: the parsed config, for a caller that runs config checks on the same facts. Drop it before saving the record |

A feature's `state` is `on`, `off` or `unknown`:

- `on` and `off` carry the lines that decided them in `evidence` (secrets masked), or, when a
  feature is off because no line turns it on, a `detail` that says which line is missing.
- `unknown` means the saved output cannot show it: a missing `vstack` line on a Catalyst
  switch, a nearly empty config, a config that parsed to no interfaces. Its `internet` is
  `None`. A caller must never treat it as off.

Readers: `ios.py` (IOS, IOS-XE), `asa.py`, `fortios.py`, `panos.py`, `junos.py`; each has
`read(text, dev) -> facts` and a `FEATURES` tuple. Text parsers are in `parsers.py`, address
and naming rules in `net.py` and `naming.yaml` (the interface names that mean "internet" or
"segment": edit for your naming), secret masking in `mask.py`.

### FTD through FMC (`devicefacts.fmc`)

Cisco FTD is managed through its Firewall Management Center, so its facts do not come from a
snapshot folder. The inventory lists each FMC under `fmc:` (next to `devices:`, which
network-snapshot reads; it ignores `fmc:`):

```python
entries, problems = devicefacts.fmc.entries(inventory)     # [{name, host, site, username, ...}], [why left out]
recs = devicefacts.fmc.read(entry, saved, platforms, inventory.get("defaults"))
tags_entry = devicefacts.fmc.ftd_entry(entry, rec["name"], inventory.get("defaults"))
```

`saved` is that FMC's device records as network-vuln-scan saved them from FMC's read-only REST
API (`skills/network-vuln-scan/scripts/fmc_api.py`, to `<out>/fmc/<fmc name>.json`):
`{fmc, collected, server_version, domains, tls, devices: [{id, name, domain, sw_version, model,
model_number, ftd_mode}]}`. Each FTD gets a normal record (platform `cisco_ftd`, `version` from
`sw_version` with the FMC and read time as its evidence, `model`), plus `source: fmc`,
`managed_by`, `collected` and `domain`. There is no config: `features` is empty and exposure is
the FTD's `exposure` tag (under the fmc entry's `ftd: {<name>: {criticality, exposure}}`), else
a firewall's assumed edge. `cisco_ftd` in `platforms.yaml` has `source: fmc` and no `version` or
`config` block; `read_device` on one listed under `devices:` returns a note saying to use `fmc:`.

Adding a platform: an entry in `devicefacts/platforms.yaml` (version file and regex, config file,
`parser: none` until a reader exists). A new reader is a module with `read(text, dev)` added to
`READERS` in `devicefacts/__init__.py`.

## credentials

```python
creds = credentials.Credentials(inventory.get("credentials"))   # CredentialError on a bad setting
pw = creds.get(name)          # the secret, or CredentialError naming each method tried
credentials.store(name, pw)   # what --set-credential does: into the OS store
```

`name` is a credential name: the inventory entry's `credential`, else its `username`. `get` tries,
in order, and the first that has a secret wins:

1. `NETOPS_SECRET_<NAME>` (`credentials.env_name(name)`: capitals, other characters as `_`).
2. The inventory's `credentials.command` (argv list, or one line split like a shell), with
   `{name}` replaced. Run with no shell, stdin closed, `credentials.timeout` seconds (30; on
   timeout the command and its children are killed). Its stdout, read as UTF-8, minus the
   trailing newline is the secret. A non-zero exit, empty or non-UTF-8 output, a timeout or a
   missing program passes to the next method; the reason keeps only the exit code or the kind of
   failure, never anything the command printed on stdout or stderr.
3. The OS credential store via `keyring`, service `netops-skills` (the same entries network-snapshot
   and network-push always used).

A caller makes one `Credentials` per run: each name is looked up once and kept in memory only, so
a run asks the vault once per name, not once per device. Never print, log or save what `get`
returns; the `CredentialError` text is safe to put in a report.
