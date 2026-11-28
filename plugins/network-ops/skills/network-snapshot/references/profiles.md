# Platform profile keys

One YAML file per platform in `platforms/`, named after its Netmiko device type. No Python
changes are needed to add one. `python scripts/snapshot.py --check-profiles` loads every profile
and refuses any that breaks the rules below.

## Contents
- Keys
- Rules the loader enforces
- Writing masks

## Keys

| Key | Required | Meaning |
|---|---|---|
| `status` | yes | `untested`, `lab-tested` or `tested`, with a comment saying where and when |
| `netmiko_device_type` | yes | Netmiko driver. `fortinet` always goes through the read-only guard |
| `uptime` | yes | `{cmd, regex, reload_reason?}`: reboot detection |
| `commands` | yes | Committed output. The **first** command must be the config: `when:` rules match it |
| `state_commands` | no | Device state: run by default, never committed. `--no-state` skips them |
| `health_commands` | no | Run only with `--health` |
| `invalid_markers` | yes | Text that means the device rejected a command |
| `no_data_markers` | no | Text that means accepted but nothing to show (`does not exist`, `% BGP not active`) |
| `privilege` | no | `{cmd, regex}`: the account's privilege level, reported, not saved |
| `vrfs` | no | `{cmd, regex}`: VRF names from this run's output, for `{vrf}` commands |
| `host_table` | no | Which host-table readers apply (default: the device type). Today `cisco_ios` and `fortinet` |
| `strip` | no | Regexes: whole lines removed from committed output |
| `mask` | no | `{pattern, replace}`: parts of lines replaced in committed output (multiline) |
| `sort_blocks` | no | `{command: start regex}`: sort repeated blocks (neighbor tables) |

Each command entry: `cmd`, plus optional `timeout` (seconds, default 90), `when` (regex matched
against this run's config; the command is skipped when it does not match), `tier: full` (state
commands only; run only with `--full`). A command listed in several classes runs once per device.

## Rules the loader enforces

- Every command starts with `show`, `get` or `display`, is one line, and has no pipe that writes
  to the device (`| redirect`, `| append`, `| tee`). The same check runs again on every command
  built from device output, just before it is sent.
- `{vrf}` needs a `vrfs` block. Each VRF name must match `[A-Za-z0-9_.:-]{1,32}`; others are
  reported under `invalid_vrfs` and never sent.

## Writing masks

Take two runs of the command on an unchanged device and diff them. Strip a line when the whole
line is a counter or timer; mask the part when the rest of the line matters. Make the
replacement absorb padding (`( ?) *` then `--\1`) when the masked value changes width, or the
columns after it shift. Add a test to `tests/test_masks.py` that shows the quiet pair is equal
and a real change still differs.
