# interfaces

The ports: what they are, whether they are up, what rides on them, and which of
them are dropping packets.

```bash
mlab-mikrotik interfaces
```

```
  Interfaces

  NAME              TYPE        STATE    ADDRESSES                     MTU    MAC                COMMENT
  ether1            ether       running  192.0.2.5/24                  1500   00:00:5E:00:53:01  OOB
  sfp-sfpplus1      ether       running                                1500   00:00:5E:00:53:02  TRANSIT-A
  sfp-sfpplus2      ether       running  10.0.1.2/30 10.0.2.6/30       1500   00:00:5E:00:53:03  TRANSIT-B
  sfp-sfpplus4      ether       down                                   1500   00:00:5E:00:53:05  SPARE
  VLAN-105-PEER     vlan        running                                1500   00:00:5E:00:53:02
  br-access         bridge      running  10.0.21.1/24                  1500   00:00:5E:00:53:10
  tun-partner       gre-tunnel  running  10.0.2.41/30                  1476
  lo                loopback    running  198.51.100.1/32               65536  00:00:00:00:00:00

  8 interfaces
  9 not shown (disabled, or filtered out) — add --all

  Counting errors or drops

  NAME       RX ERR  TX ERR  RX DROP  TX DROP  QUEUE DROP
  br-access  0       0       0        276      0

  these are cumulative since the counters were last reset, not a rate
```

## Where each column comes from

`/interface` gives the name, type, state, MAC, MTU and comment.
`/ip/address` gives the **ADDRESSES** column, joined on the interface name —
`interface` or `actual-interface`, so a VLAN or a bridge resolves correctly.
Disabled addresses are left out.

The join is on the *name*, never on `.id`, which RouterOS reassigns freely.

## STATE

One column out of two RouterOS properties, because reading either alone is
misleading.

| Value | Means |
| --- | --- |
| `running` | Not disabled, and the link is up |
| `down` | Not disabled, link is down |
| `disabled` | Switched off administratively — the link state is irrelevant |
| `enabled` | Not disabled, and this kind of interface reports no link state at all |

## The errors table

It appears only when something is non-zero. A port that is `running` and
quietly losing packets looks perfectly healthy in the table above, which is the
whole reason this section exists. The numbers are cumulative since the counters
were last reset, not a rate — the command says so rather than implying
otherwise.

## Options

| Flag | What it does |
| --- | --- |
| `--all` | Include administratively disabled interfaces |
| `--kind TYPE` | Only interfaces of one type: `ether`, `vlan`, `bridge`, `gre-tunnel`, … |

```bash
mlab-mikrotik interfaces --kind vlan
mlab-mikrotik interfaces --all -o json | jq '[.interfaces[] | select(.state=="down")] | length'
```

## Why `.proplist`

`/interface` carries thirty-odd properties per row, most of them counters. This
command asks for the twelve it needs, then makes a second, narrow request for
the counters. On a chassis switch with hundreds of ports that is the difference
between a table and a megabyte. See [Surfaces](Surfaces).
