# snapshot

One dated, secret-free record of everything this account can read.

```bash
mlab-mikrotik snapshot
```

```
  ✔ saved /home/you/.mlab/mikrotik/snapshots/lab/2026-09-05T190012Z.json

  taken            2026-09-05T19:00:12Z
  router           gw-edge-01 (CCR2004-1G-12S+2XS)
  routeros         7.24.2 (stable)
  menus            56 (216 rows)
  secrets removed  1
  unreadable       1

  1 secret(s) were replaced by their length before this file was written
```

## Why this exists

There is no event stream on a RouterOS device. Nothing pushes, and the only
history the router keeps is a log that lives in memory until the next reboot.
Detection here is therefore **differential**: you do not read an alarm, you
compare two dated collections and qualify the difference.

That is slower than an alert, and it is harder to evade. An intruder can avoid
tripping a signature; they can hardly avoid existing in the inventory.

## It is not built on `/export`

The obvious approach would be `POST /rest/export`, which returns the whole
configuration as `.rsc` text. It does not work: over REST that call answers
`200` with an **empty array**. The configuration text never comes back, and the
`file=` form writes to the router's own storage, which a read-only tool has no
business doing.

So a snapshot is the REST menu catalogue instead — which is the better shape
anyway, because JSON diffs field by field where `.rsc` diffs line by line.

## What is recorded

Fifty-six menus, wider than what the graded checks read. A snapshot is written
once and compared for years, and a menu left out today cannot be compared
retroactively. That includes menus nothing currently grades — `/system/
scheduler`, `/system/script`, `/tool/netwatch` — because arrivals in them are
what phase five will hunt.

The list is `CATALOGUE` and `OPTIONAL` in `src/snapshot.rs`.

## Secrets

Every secret is replaced by its **length** before the file is written:

```json
"secret": "<redacted:16>"
```

A length is not a secret, and it is exactly what a strength check needs — so a
redacted snapshot can still be audited for a short pre-shared key. The value
itself never reaches the disk. See [Secrets](Secrets) for the field list and
why it is explicit rather than a substring rule.

The count is printed every time, because it is the measure of what this account
was handed. On an account without `sensitive` it will be zero, and that is a
fact about the account rather than about the router.

## Where files go

`$HOME/.mlab/mikrotik/snapshots/<instance>/<timestamp>.json`, `0600` inside a
`0700` directory. The filename is the UTC ISO 8601 stamp with the colons
removed, so a directory listing sorts chronologically.

`MLAB_MIKROTIK_SNAPSHOTS` moves the directory. `--out PATH` writes one file
somewhere else; `--stdout` prints it and saves nothing.

## Listing

```bash
mlab-mikrotik snapshot list
```

```
  Snapshots of lab

  TAKEN                 ROWS  SECRETS REMOVED  FILE
  2026-09-05T18:59:45Z  216   1                2026-09-05T185945Z.json
  2026-09-05T19:00:12Z  216   1                2026-09-05T190012Z.json

  2 snapshots
```

A file that will not parse is still listed, as `unreadable` — it is the one you
are looking for when something has gone wrong.

## On a schedule

```bash
mlab-mikrotik snapshot -q
```

Once a day from cron is enough for configuration drift; once an hour if the
router is exposed. Then [`shadow`](Shadow) on the same schedule, offset, is
what turns the pile into detection.
