# footprint

What this router looks like from outside.

```bash
mlab-mikrotik footprint --allow-web
```

```
  Reachable from outside

  ADDRESS               INTERFACE     ORIGIN
  198.51.100.22/30      vlan1         static
  203.0.113.249/32      lo            static
  2001:db8:317e::2/64   sfp-sfpplus2  static

  3 public addresses

  Who operates them

  ADDRESS              AS                        OPERATOR        WHERE               HOSTING
  198.51.100.22        AS64500 Example Transit   Example         Brussels, Belgium   true
  203.0.113.249        AS64501 Example Access    Example Access  Strasbourg, France  false
  2001:db8:317e::2     AS64501 Example Access    Example Access  Strasbourg, France  false

  What answers there

  services with no address restriction  17
  port forwards                         2

  `exposure` lists them; `firewall` says whether a chain stops them
```

## Nothing is probed

The public address comes from the router's own `/ip/cloud`, which RouterOS
keeps current **even with DDNS disabled** — so it costs nothing and no packet
is sent anywhere. The rest come from `/ip/address` and `/ipv6/address`,
filtered to what the internet can route to.

The only thing that ever leaves this machine is an address that is public by
definition: it is the one every packet this router sends already carries in
its source field.

## What counts as public

Everything except RFC 1918, loopback, link-local, RFC 6598 carrier-grade NAT,
`0.0.0.0/8`, multicast and above; and for IPv6, `fe80::/10` link-local,
`fc00::/7` unique-local and `::1`.

A router behind a provider's NAT therefore reports **no public address of its
own**, which is the truth — and `/ip/cloud` still names the address the world
sees, listed separately as `(reported by /ip/cloud)`.

## What answers there

The two counts at the bottom are the reason the addresses matter. They are
deliberately just counts: [`exposure`](Exposure) lists what is listening and
what each service allows on its own, and [`firewall`](Firewall) says whether a
chain stops any of it. Joining the three into "port 8291 is reachable from the
internet" would need to know which interfaces face outward, and nothing in the
configuration says so reliably.

## Options

| Flag | What it does |
| --- | --- |
| `--allow-web` | Ask mlab.sh who operates each address |
| `--refresh` | Ignore a fresh cache entry and ask again |

Without `--allow-web` the addresses are still listed — only the operator table
is missing, and the command says so.

An operator lookup is cached for a day, and a cached answer is served with or
without the flag, so the table always says where it came from:

```
  from cache, 6 minutes old — add --refresh to ask again
```
