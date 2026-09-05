# diff

What changed between two snapshots.

```bash
mlab-mikrotik diff                      # the last two of this instance
mlab-mikrotik diff old.json             # that one against the newest
mlab-mikrotik diff old.json new.json    # exactly these two
```

```
  2026-08-01T09:00:00Z → 2026-09-05T19:00:12Z

  /ip/service
    ~ www main
        disabled  true → false

  /user
    + speed

  1 appeared, 0 disappeared, 1 changed
```

`+` appeared, `-` disappeared, `~` changed, with the field that moved and both
values.

## What identifies a row

Never `.id`. RouterOS reassigns those freely, so keying on them would report
every row as replaced after a reboot. Each menu has its own key instead:

| Menu | Key |
| --- | --- |
| `/ip/address`, `/ipv6/address` | `address` |
| `/ip/route` | `dst-address` + `gateway` |
| `/ip/service` | `name` + `vrf` |
| `/interface/bridge/port` | `bridge` + `interface` |
| `/ip/firewall/address-list` | `list` + `address` |
| `/system/logging` | `topics` + `action` |
| everything else | `name` |

A menu with no natural name — a firewall rule — keys on its **comment**, and
failing that on the row's own content. That means editing an uncommented rule
reads as one row leaving and another arriving, which is the honest rendering of
"a rule changed and nothing names it".

## What is ignored

Counters, clocks and identifiers, because leaving them in would report every
row as changed on every run, which is the same as reporting nothing.

The list is explicit, plus one prefix rule: every RouterOS fast-path counter is
named `fp-*` (`fp-rx-byte`, `fp-tx-packet`, `fp-rps-drop`). Without that rule,
two snapshots of a live router taken thirty seconds apart show every interface
as changed. With it, they diff to nothing.

A RouterOS upgrade is **not** ignored — `version` moving is reported, while the
uptime it reset is not.

## What it refuses

Two snapshots of different routers:

```
  ✖ these snapshots are of different routers (ABC123 and XYZ789);
    there is nothing honest to compare
```

The serial number comes from `/system/routerboard`. A CHR with no serial is
compared without the guard, because there is nothing to check against.

## Menus that went quiet

A menu readable in the older snapshot and not in the newer is a change in what
the **account** may see, not in the router. It gets its own line rather than
silently emptying a table:

```
  ! 1 menu(s) readable in the older snapshot and not in the newer: /ip/firewall/filter
  a menu that went quiet is a change in the account, and its rows are not compared
```

## Options

| Flag | What it does |
| --- | --- |
| `--menu MENU` | Only one menu, e.g. `/user` |
| `--presence` | Only arrivals and departures; hide field-level edits |

```bash
mlab-mikrotik diff --menu /ip/firewall/filter
mlab-mikrotik diff --presence
mlab-mikrotik diff -o json | jq '.differences[] | select(.menu=="/user")'
```
