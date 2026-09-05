# shadow

What turned up on this router that nobody announced.

The live configuration against the last snapshot, filtered down to
**arrivals** in the menus where an arrival is a decision somebody made.

```bash
mlab-mikrotik shadow
```

```
  Since 2026-08-01T09:00:00Z

  /system/scheduler  a task that runs on its own schedule
    + check-updates

  /user  an account that can log in
    + ftu

  2 arrival(s), 0 departure(s), 1 edit(s) — `diff` shows the edits
  1 row(s) RouterOS created for itself are not shown — add --dynamic

  these are things that were not here at the last snapshot, not accusations —
  a change window explains most of them, and the ones it does not are the point
```

## The twelve menus it watches

Ordered by what an arrival costs, because that is the order a reader wants:

| Menu | An arrival is |
| --- | --- |
| `/system/scheduler` | a task that runs on its own schedule |
| `/system/script` | a script the router can run |
| `/user` | an account that can log in |
| `/user/group` | a set of permissions |
| `/user/ssh-keys` | a key that logs in without a password |
| `/tool/netwatch` | a probe that can trigger a script |
| `/ip/service` | a service listening on the router |
| `/ip/firewall/filter` | a rule that admits or refuses traffic |
| `/ip/firewall/nat` | a rule that publishes or rewrites traffic |
| `/ip/dns/static` | a name this router answers for |
| `/interface` | an interface, including a tunnel |
| `/ip/address` | an address on this router |

The first two and `/tool/netwatch` are there for one reason: a scheduled task
that fetches and imports a script is the persistence mechanism seen on
compromised MikroTik routers since 2018. Phase five grades that; this command
notices it arrived.

`--all` widens to every menu in the snapshot catalogue.

## Dynamic rows are not arrivals

RouterOS creates rows for itself, and `/ip/service` is the worst offender:
`detnet`, `route_BGP`, `discover` are all dynamic, and a `dhcp` entry appears
for as long as a lease takes to renew. Their arrival is a consequence of
something working, not a decision — and reporting them buries the one line that
matters under a dozen that do not.

They are filtered out and counted. `--dynamic` includes them; [`diff`](Diff)
always shows them, because it is the complete picture rather than the
interesting part of it.

## Arrivals are facts, not accusations

The command says so on every run with something to report. Most arrivals are
explained by a change window; the ones that are not are the point of running
it.

## Options

| Flag | What it does |
| --- | --- |
| `--since PATH` | Compare against this snapshot instead of the most recent |
| `--all` | Every menu in the catalogue, not just the twelve |
| `--departures` | Also report what disappeared |
| `--dynamic` | Include rows RouterOS created for itself |

## On a schedule

```bash
mlab-mikrotik snapshot -q && mlab-mikrotik shadow -o json
```

Snapshot first, then compare — or the other way round, if you want the window
to be a full day rather than nothing. The second form is the useful one in
cron: `shadow` against yesterday's snapshot, then take today's.
