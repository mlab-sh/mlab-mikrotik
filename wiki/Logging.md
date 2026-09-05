# logging

Where this router's log goes, and what never reaches it.

```bash
mlab-mikrotik logging
```

```
  Where it goes

  TOPICS    ACTION  TARGET  SURVIVES REBOOT
  info      memory  memory  false
  error     memory  memory  false
  warning   memory  memory  false
  critical  echo    echo    false

  4 rules

  every active rule writes somewhere volatile — the whole log is gone at the
  next reboot, and a reboot is the first thing that happens after an incident
  a rule is judged by its action's target, not by the action's name

  What is recorded

  TOPIC     ANSWERS AFTERWARDS                            RECORDED BY  SURVIVES REBOOT
  account   who logged in, from where, and who failed to  —            false
  system    what changed in the configuration, and by w…  —            false
  critical  what the router considers an emergency        echo         false
  error     what failed                                   memory       false
  firewall  what the rules that log actually caught       —            false

  not recorded: account, system, firewall — these are the questions that cannot
  be answered afterwards

  Firewall refusals

  drop or reject rules  1
  with log=yes          0 of 1

  nothing records what this router turned away
```

## Two questions

**Does anything survive a reboot?** Everything in `memory` does not, and a
reboot is the first thing that happens after most incidents. A rule is judged
by its **action's target**, never by the action's name: an action called
`remote` that writes to memory is exactly the trap this table exists to catch.

**Are the topics that matter recorded at all?** RouterOS ships with `info`,
`error`, `warning` and `critical` going to memory and nothing else, so every
line beyond that is a decision somebody has to make.

| Topic | What it answers afterwards |
| --- | --- |
| `account` | who logged in, from where, and who failed to |
| `system` | what changed in the configuration, and by whom |
| `critical` | what the router considers an emergency |
| `error` | what failed |
| `firewall` | what the rules that log actually caught |

Topic matching follows RouterOS: a rule for `system` covers `system,info`.

## Firewall refusals

The last block counts the `drop` and `reject` rules and how many carry
`log=yes`. It deliberately does **not** tell you to log all of them — a busy
catch-all drop fills the log on its own, and the rules worth watching are the
narrow ones.

`audit` only raises this when *every* refusal is silent, for the same reason.

## Fixing it

```
/system logging action add name=remote target=remote remote=198.51.100.20
/system logging add topics=account action=remote
/system logging add topics=system,info action=remote
/system logging add topics=critical,error,warning action=remote
```

The first line is the one that matters: without a `remote` or `disk` action in
use, nothing survives the next reboot.
