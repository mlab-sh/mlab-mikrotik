# patch

How far behind this router is — in RouterOS, and in its bootloader.

```bash
mlab-mikrotik patch --allow-web
```

```
  RouterOS

  installed                7.24.2
  channel                  stable
  current on that channel  7.24.2
  verdict                  up to date

  RouterBOARD bootloader

  installed                   7.12.2
  shipped with this RouterOS  7.24.2
  verdict                     behind

  /system routerboard upgrade, then a reboot — a RouterOS upgrade never moves it
```

## Two gaps that move independently

**RouterOS against its channel.** `/system/package/update` reports the channel
and the installed version. It does *not* report the current one: that field
only appears after a `check-for-updates` has run on the router.

**The bootloader against RouterOS.** `/system/routerboard` reports the
firmware installed and the firmware that shipped with the RouterOS already on
the box. They are versioned separately and a RouterOS upgrade never moves the
first, which makes this the most common finding on an otherwise current
router. The example above is real behaviour, not an illustration.

## The router is never asked to check

`check-for-updates` would have the *router* contact MikroTik. A passive audit
does not change what a production router does on the wire, so `patch` asks
from this machine instead:

```
https://upgrade.mikrotik.com/routeros/NEWESTa7.stable  →  7.24.2 1788429434
```

A plain text file, no authentication, one per channel. See
[Enrichment](Enrichment).

The answer is cached for an hour and the line says so, because a cached answer
is served with or without the flag:

```
  current on that channel  7.24.2  (from cache, 7 minutes old)
```

`--refresh` asks again. Without `--allow-web`, nothing is asked and the verdict
is honest about it:

```
  current on that channel  not looked up
  verdict                  cannot say
```

`cannot say` and `up to date` are different answers, and a failed lookup
produces the first, never the second.

## Version comparison

Numeric, component by component, so `7.9` is behind `7.12` rather than ahead
of it. A string that is not a version number — and RouterOS on a damaged
install can report anything — produces no verdict rather than a wrong one.

## What audit does with this

`audit` grades the bootloader gap as **medium** and a RouterOS 6.x install as
**high**, both from data already on the router. The channel comparison needs
the network and so stays out of a default audit run. See [Checks](Checks).
