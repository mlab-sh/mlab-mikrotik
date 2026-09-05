# audit

Every graded check in one report.

```bash
mlab-mikrotik audit
```

```
  Audit

      high  powerful accounts can log in from anywhere
            3 account(s) in a group carrying write, policy or sensitive have no
            address restriction: ops (full), backup (full), deploy (full)
            /user set <name> address=203.0.113.10/32

      high  IPv6 is configured and not filtered
            9 routable IPv6 address(es) on this router, and /ipv6/firewall/filter
            has no active rule — every IPv4 control on this box has no IPv6 counterpart
            /ipv6 firewall filter add chain=input action=drop, then build up from there

    medium  the RouterBOARD bootloader is behind the installed RouterOS
            firmware 7.12.2, and 7.24.2 ships with the RouterOS already installed —
            a RouterOS upgrade never moves the bootloader on its own
            /system routerboard upgrade, then /system reboot

       low  no firewall refusal is logged
            1 active drop/reject rule(s), none with log=yes — nothing records what
            this router turned away
            /ip firewall filter set <n> log=yes log-prefix=drop-input

  0 critical, 6 high, 9 medium, 3 low

  1 check(s) not run:
    wireless  this router has no wireless interfaces

  a check that could not run is not a pass
```

Three lines per finding: what it is, what was actually observed with the values
that led to it, and the RouterOS command that changes it.

## The footer is the point

It prints whether or not anything was found. A clean run on a router that
refused half its menus must not read as a clean router, and the only thing
standing between those two states is the skipped count.

`not applicable` and `refused` are different facts and are worded differently:

```
    wireless  this router has no wireless interfaces
    wireless  neither wireless menu could be read
```

## Options

| Flag | What it does |
| --- | --- |
| `--min-severity LEVEL` | Only findings at this severity or worse |
| `--area AREA` | Only one area: `accounts`, `services`, `exposure`, `segmentation`, `wireless`, `patch`, `logging` |
| `--fail-on LEVEL` | Exit 1 when anything at this severity or worse was found |

```bash
mlab-mikrotik audit --min-severity high
mlab-mikrotik audit --area exposure
mlab-mikrotik audit --fail-on high -q -o json
```

`--fail-on` is the CI gate. It does not change what is reported, only the exit
code — so a pipeline can print the whole report and still fail on the part that
matters.

## JSON

```bash
mlab-mikrotik audit -o json | jq '.findings[] | select(.severity=="high") | .title'
```

```json
{
  "findings": [ { "severity": "high", "area": "accounts", "title": "…", "detail": "…", "fix": "…" } ],
  "skipped":  [ { "check": "wireless", "because": "this router has no wireless interfaces" } ],
  "counts":   { "critical": 0, "high": 6, "medium": 9, "low": 3 },
  "unreadable": []
}
```

A script that treats an empty `findings` array as "clean" should be reading
`skipped` and `unreadable` too.

## What it collects

One pass, about thirty menus, in `collect::security`. Both wireless stacks are
attempted on purpose: the one this router does not carry answers
`400 no such command`, which lands in `unreadable` as **absent** — and that is
exactly how the wireless checks tell "no radios here" from "the menu was
refused".

See [Checks](Checks) for the catalogue and what each finding means.
