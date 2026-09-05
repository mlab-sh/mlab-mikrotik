# Output

Two formats, and the rules that keep them from mixing.

## The default: a terminal render

Two-space indent, dimmed labels, one blank line around each block, colour used
only to encode state. Tables drop any column that is empty on this router, so a
device with no DHCP server does not get an empty `LEASE TIME` column.

## `-o json`

Raw JSON on stdout, untouched. Nothing is humanised there: no unit suffixes, no
colour, no truncation. A pipeline always sees exactly what the router returned,
plus whatever the command joined onto it.

```bash
mlab-mikrotik interfaces -o json | jq '.interfaces[] | select(.state == "down") | .name'
```

Every command that renders a table also carries an `unreadable` array in its
JSON, listing the menus that produced nothing and why. A script that treats an
empty result as "clean" should check it.

An instance can prefer a format: `"output": "json"` in the config file. A flag
or an environment variable still wins.

## The three streams

1. **stdout carries the result.** Nothing else is ever written there, so
   `-o json | jq` stays parsable while a spinner is running.
2. **stderr carries progress and status.** The spinner, `✔`, `!`, `›`.
3. **Nothing is drawn unless stderr is a terminal**, and nothing is drawn for
   work that finishes in under 250 ms. Pipes, CI logs and tests get clean
   output with no escape sequences.

`--quiet` silences the stderr side entirely. `CI=1` disables the animation but
keeps the warnings.

## Truncation

A table cell longer than 44 characters is clipped with `…` so one long value
cannot wreck the alignment — a loopback carrying six addresses, say. The full
value is always in `-o json`.
