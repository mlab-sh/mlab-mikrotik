# posture

The settings that claim to defend something, and the ones that quietly widen
the way in.

Every row says what the setting **is**, not what it should be. Where a value is
a decision the operator has to make, the row stays neutral; the grading lives
in [`audit`](Audit).

```bash
mlab-mikrotik posture
```

```
  Accounts

  USER      GROUP  LOGS IN FROM     WRITES  SECRETS  LAST LOGIN
  ops       full   anywhere         true    true     2026-09-03 20:07:28
  monitor   read   10.0.0.0/24      false   true
  mlab      audit  203.0.113.10/32  false   false    2026-09-03 23:27:02

  3 enabled accounts

  Management reach

  SETTING                STATE     DETAIL
  neighbour discovery    !dynamic  cdp,lldp,mndp
  MAC-telnet             all       layer 2 access to the console, no IP needed
  MAC-Winbox             all       layer 2 access to Winbox
  MAC-ping               on        answers pings addressed to the MAC
  RoMON                  off
  bandwidth test server  on        authenticated

  `none` is the hardened value for the interface lists; a named list is a decision, `all` is not

  Cryptography and time

  SETTING            STATE  DETAIL
  SSH strong crypto  off    host key rsa
  SSH forwarding     off    tunnels opened through the router's own SSH
  NTP client         on     synchronized
  SNMP               on     1 community, 1 in plain text (v1/v2c)

  Logging

  TOPICS    ACTION  TARGET  SURVIVES REBOOT
  info      memory  memory  false
  critical  echo    echo    false

  nothing is written to disk or sent to a remote collector — every line here is gone at the next reboot
```

## Accounts

`WRITES` and `SECRETS` resolve the account's *group* rather than repeating its
name: they say whether the group carries `write` and whether it carries
`sensitive`. An account that can read every pre-shared key on the router while
its group is named `read` shows up here as `false / true`.

`LOGS IN FROM` is `address=` on the user. `anywhere` on a router with a public
address is worth reading twice.

## Management reach

The four ways to reach this router that do not go through the IP firewall:

- **MAC-telnet** and **MAC-Winbox** reach the console at layer 2, with no IP
  address involved at all. `none` is the hardened value; a named interface list
  is a decision; `all` is not.
- **MAC-ping** answers pings addressed to the MAC.
- **RoMON** reaches other routers over layer 2 from this one, and lets them
  reach it.

**Neighbour discovery** is on the same list because what it gives away — this
router's identity, model and exact RouterOS version — is exactly what someone
needs to look up which advisories apply.

## Logging

Reported by **target**, not by action name. An action called `remote` that
writes to memory is precisely the trap this table exists to catch, and the
`SURVIVES REBOOT` column is computed from the target rather than the name.

Everything in `memory` is gone at the next reboot, and a reboot is the first
thing that happens after most incidents.

## JSON

```bash
mlab-mikrotik posture -o json | jq '.accounts[] | select(.secrets == true)'
```

Carries `accounts`, `management`, `crypto`, `logging` and `unreadable`.
