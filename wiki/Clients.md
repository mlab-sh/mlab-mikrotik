# clients

What the router knows about who is on the network.

```bash
mlab-mikrotik clients
```

```
  Hosts

  MAC                ADDRESS       NAME           INTERFACE      SEEN IN      STATUS     LAST SEEN
  00:00:5E:00:53:20  10.0.21.14    laptop-mk      br-access      lease arp    bound      2026-09-03 22:58:11
  00:00:5E:00:53:21  10.0.21.31    printer-1      ether3         lease        bound      2026-09-03 19:02:44
  00:00:5E:00:53:22  10.0.2.5                     sfp-sfpplus2   arp          reachable
  00:00:5E:00:53:23                               br-access      bridge
  00:00:5E:00:53:24  192.0.2.1     fw-edge-01     ether1         neighbor

  5 hosts
  from leases 2, arp 2, bridge 1, neighbours 1
```

## Four menus, one row per machine

None of them is authoritative on its own:

| Menu | What it actually says |
| --- | --- |
| `/ip/dhcp-server/lease` | What the router *handed out* — a name, an address, a lease state |
| `/ip/arp` | What *replied* on a subnet the router is on |
| `/interface/bridge/host` | Which *port* a MAC address sits behind |
| `/ip/neighbor` | A device that *announced itself* over MNDP, CDP or LLDP |

They are joined on the MAC address, which is the only identifier all four
carry, normalised to upper case first — `/ip/arp` and
`/interface/bridge/host` do not always agree on case, and a join on the raw
string silently loses half the rows.

**SEEN IN** is the interesting column. A host in `lease arp` is doing what it
was told. A host in `arp` alone, on a network that hands out every address,
configured itself.

## The tally line

`from leases 2, arp 2, bridge 1, neighbours 1` is there because an empty
column is ambiguous. A router with no DHCP server has no leases and no
`LAST SEEN` values, and without the tally a reader cannot tell that from a
collection failure.

## Options

| Flag | What it does |
| --- | --- |
| `--seen-in SOURCE` | Only hosts named by one menu: `lease`, `arp`, `bridge`, `neighbor` |
| `--static-only` | Only hosts with no DHCP lease |

```bash
mlab-mikrotik clients --static-only
mlab-mikrotik clients --seen-in neighbor
mlab-mikrotik clients -o json | jq '.hosts[] | select(.seenIn | contains("lease") | not)'
```

## What this is not

It is a point-in-time view, not a history. ARP entries expire, the bridge table
ages out, and a lease that was never renewed disappears. Turning this into
"what appeared since last time" needs two dated collections to compare, which
is the `shadow` command of phase three.
