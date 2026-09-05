# whoami

What this account is, and everything it is allowed to read.

**Run this first.** Every other command's honesty rests on it: a table that is
empty because the account cannot see the menu must never read as an empty
router.

```bash
mlab-mikrotik whoami
```

```
  Account mlab

  instance        lab
  group           read
  allowed from    anywhere
  last logged in  2026-09-03 22:45:51
  policies        local, telnet, ssh, reboot, read, test, winbox, password, web, sniff, sensitive, api, romon, rest-api


  Beyond reading

  POLICY     ALLOWS
  sensitive  returns keys and passwords in clear text
  reboot     restarts the router
  sniff      captures traffic with the packet sniffer
  password   changes its own password
  romon      reaches other routers over RoMON

  a group carrying these is not a read-only group, whatever it is named
  ! this account reads secrets in clear text (`sensitive`); a snapshot must redact before writing

  Sessions open right now

  USER        FROM             VIA       SINCE                GROUP
  ops         198.51.100.20    winbox    2026-09-03 22:11:34  full
  mlab        203.0.113.10     rest-api  2026-09-03 22:45:51  read

  2 sessions
```

## Reading it

**`policies`** is what the account's group actually grants. RouterOS writes a
group's policy as one comma-separated string in which a leading `!` means
*denied* — `read,write,!ftp`. Splitting on the comma alone would report `ftp`
as granted, which is the wrong way round; this command does not.

**Beyond reading** lists the policies that are not about reading. The section
is absent when there are none, which is the state to aim for. See
[Account](Account) for the group to create instead.

**Sessions open right now** comes from `/user/active`. Your own REST requests
appear there, so seeing `mlab … rest-api` twice is this command and the one
before it, not a second operator.

## Warnings it raises

| Condition | Why it matters |
| --- | --- |
| The group is missing `read` or `rest-api` | Menus will report as refused, and a check that cannot run must not read as a pass |
| The group carries `sensitive` | Everything written to disk from now on has to be redacted first |
| No account of that name in `/user` | The login works, so the name is cased differently — worth knowing before a script matches on it |

## JSON

```bash
mlab-mikrotik whoami -o json | jq '.beyondReading'
```

Carries `granted`, `denied`, `missingForThisCli`, `beyondReading`,
`allowedAddress`, `lastLoggedIn` and the full `activeSessions` array.
