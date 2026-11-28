# network-snapshot state expansion: lab evidence

Lab v2 (CML), 2026-11-28, read-only. Eleven Cisco IOL nodes (IOS-XE 17.16) as `claude-ro`
(privilege 5) and FortiGate-VM 8.0.1 fw-01 as `claude-ro-cli`. Only `show` (Cisco) and
`get`/`show` (FortiGate) were sent, all through `scripts/snapshot.py`; no lab config was changed.
Passwords came from `NETOPS_SECRET_CLAUDE_RO` and `NETOPS_SECRET_CLAUDE_RO_CLI` (the environment
variable method in `lib/credentials`). Snapshot repo: a new scratch repo, outside this one. Before
the engine was written, one read-only probe script (show commands only, same account) saved
sample output for the parser tests.

## Runs

Nine full runs, 8 devices in parallel (`--workers 8`), default flags (state and host table on).

| Run | Code | Wall time | Committed diff | Why |
|---|---|---|---|---|
| 1 | first engine | 52.9 s | first snapshot (360 files) | baseline |
| 2 | same | 48.4 s | **empty** | |
| 3 | host table and review fixes | 49.5 s | fw-01 route ages | `01w6d19h` to `01w6d20h`: the FortiOS profile had no mask for ages over a week (an existing gap, now fixed) |
| 4 | same | 50.0 s | fw-01 route ages | same roll-over, more routes |
| 5 | week mask added | 49.4 s | fw-01 route ages | the new mask rewriting ages to `--` once |
| 6 | same | 48.9 s | **empty** | |
| 7 | same | 48.5 s | **empty** | |
| 8 | final (narrower no-data markers) | 49.2 s | **empty** | |
| 9 | final | 48.9 s | **empty** | |

Runs 8 and 9 ran the final code: two consecutive runs, empty committed diff, and no host changes.
Runs 6 to 9 cover more than one hour roll-over of the FortiGate route ages with no diff.

## Per device (run 9)

Commands sent include the uptime and privilege preflight. Rejected = committed plus state
commands the device refused. Skipped = not run because the config does not use the feature
(`when:`).

| Device | Seconds | Commands sent | Rejected | No data | Skipped | VRFs found |
|---|---|---|---|---|---|---|
| branch1-rtr-01 | 24.7 | 45 | 11 | 1 | 22 | MGMT |
| branch1-sw-01 | 23.0 | 41 | 4 | 1 | 26 | MGMT |
| fw-01 | 13.3 | 24 | 1 | 0 | 0 | none (FortiOS VRFs are in the routing table output) |
| hq-acc-sw-01 | 23.4 | 41 | 4 | 1 | 26 | MGMT |
| hq-acc-sw-02 | 23.1 | 41 | 4 | 1 | 26 | MGMT |
| hq-acc-sw-03 | 23.1 | 41 | 4 | 1 | 26 | MGMT |
| hq-acc-sw-04 | 22.6 | 41 | 4 | 1 | 26 | MGMT |
| hq-core-sw-01 | 24.8 | 44 | 4 | 1 | 23 | MGMT |
| hq-dist-sw-01 | 24.4 | 44 | 4 | 1 | 23 | MGMT |
| hq-dist-sw-02 | 24.6 | 44 | 4 | 1 | 23 | MGMT |
| hq-edge-rtr-01 | 25.4 | 45 | 11 | 0 | 22 | MGMT |
| isp-rtr-01 | 23.2 | 42 | 11 | 0 | 25 | MGMT |
| **Total** | 48.9 wall | 493 | 66 | 9 | 268 | |

- Rejected on every Cisco node: `show license summary`, `show switch detail`, `show module`,
  `show redundancy` (hardware or Catalyst-only; IOL lacks them). On the three routers also the six
  switch commands (`show interfaces status`, `switchport`, `trunk`, `show vlan brief`,
  `show vtp status`, `show etherchannel summary`) and, in state, `show mac address-table`. On
  fw-01: `get system interface transceiver` (hardware only). All expected on virtual images; no
  command was refused for privilege that the research did not predict.
- No data: `show bgp all summary` ("% BGP not active") on the nine nodes without BGP.
- Privilege preflight: level 5 on all eleven Cisco nodes.
- FortiGate guard: fw-01's console is in standard mode, so the guard read it with
  `get system console` and went on; no config command was sent.
- No `invalid_vrfs`, no command errors, no failures.

Size: committed output 777 KB in 360 files (about 65 KB per Cisco node, the rest fw-01's 404 KB
config and route tables); device state 127 KB.

## Host table (run 9)

`.snapshot/hosts.csv`: 52 rows (7 host, 42 network-device, 3 virtual). Three examples:

```
10.0.0.13,000c.29de.812b,default,,fw-01,port3,network-device,arp:hq-core-sw-01; if-self:fw-01,
192.168.1.86,2ccf.67e4.7b2a,MGMT,,,,host,arp:branch1-rtr-01; ... arp:isp-rtr-01,"no MAC table entry; ARP on branch1-rtr-01 Et0/0, ..."
,5254.00a6.674d,,10,hq-acc-sw-01,Et0/3,host,mac:hq-acc-sw-01:Et0/3; mac:hq-acc-sw-02:Et0/1; mac:hq-acc-sw-03:Et0/1; mac:hq-acc-sw-04:Et0/1; mac:hq-dist-sw-01:Et1/0; mac:hq-dist-sw-02:Et0/2,
```

1. The FortiGate's port3 address, seen in hq-core-sw-01's ARP and listed by fw-01 itself: proof of
   the core-to-firewall link, which no CDP or LLDP shows (the FortiGate sends neither).
2. A management-LAN host every Cisco node ARPs for in VRF MGMT; routed ports, no MAC table, so no
   port is claimed.
3. From run 1: an end host learned on hq-acc-sw-01 Et0/3, VLAN 10, the only non-uplink port among
   six MAC tables. Its MAC aged out of the tables by run 3 (silent host, 5 minute MAC aging) and the
   run reported it under `hosts.changes.gone`; this is expected and documented.

The FortiGate's ARP of the same management hosts appears as separate `default` VRF rows: fw-01's
port1 is on that LAN with no VRF, and VRFs are matched by name.
