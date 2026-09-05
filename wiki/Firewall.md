# firewall

The rules, and the one ordering question that can be answered honestly without
simulating a packet.

```bash
mlab-mikrotik firewall
```

```
  Filter

  #   CHAIN  ACTION  SRC            DST                PROTO  LOG    HITS  STATE   COMMENT
  0   input  accept                 192.0.2.1:8291     tcp    false  0     active  winbox from monitoring
  1   input  accept  203.0.113.4    192.0.2.1:161      udp    false  0     active  snmp from monitoring
  2   input  accept  203.0.113.4    192.0.2.1          icmp   false  0     active  icmp from monitoring
  15  input  drop                   192.0.2.1                 false  1171  active  block the rest

  16 rules

  Chains

  CHAIN  RULES  ACCEPTS  REFUSALS  CLOSES
  input  16     15       1         false

  a chain closes when its last active rule is a drop or reject that matches nothing in particular
  rule order beyond that is not analysed — that needs per-packet evaluation, and a guess would be worse than silence
```

## CLOSES is the column to read

`false` in the example above is not a mistake. The last rule *is* a drop — but
it carries `dst-address=192.0.2.1`, so it closes the chain for that one address
and lets everything aimed anywhere else straight through.

A chain closes when its last **active** rule is a `drop` or `reject` that
narrows nothing: no address, address list, port, protocol, interface or
connection state. The list of properties that count as narrowing is explicit,
in `src/checks/segmentation.rs`, because `comment`, `log` and the packet
counters are on every rule and would otherwise make the test always true.

## What this deliberately does not do

Decide which rules are dead or shadowed. That needs per-packet evaluation of
the whole ordered set, and a tool that guesses at it produces confident
nonsense. The command says so on screen rather than leaving you to assume it
was checked.

## Options

| Flag | What it does |
| --- | --- |
| `--chain CHAIN` | Only `input`, `forward`, `output`, `srcnat`, `dstnat` |
| `--all` | Include rules that are administratively disabled |
| `--ipv6` | Show the IPv6 tables instead of the IPv4 ones |

```bash
mlab-mikrotik firewall --chain input
mlab-mikrotik firewall --ipv6
mlab-mikrotik firewall --all -o json | jq '[.filter[] | select(.state=="disabled")] | length'
```

`--ipv6` is worth running on any router that has IPv6 addresses. A common shape
is a carefully built IPv4 filter next to an empty IPv6 one, and `audit` grades
that high.

## The `#` column

The rule's position in the menu, counting disabled rules — the same numbering
`/ip firewall filter print` uses, so a number here is a number you can act on.

## SRC and DST

One column per side, address list included: `dst-address-list=blocked` is as
much a destination as `dst-address=10.0.0.0/8`, and both render in the same
place. A port with no address reads as `:8291`.

## NAT and address lists

Below the filter, the same treatment for `/ip/firewall/nat` with a `TO` column,
and a summary of the address lists with how many entries each holds and how
many of those are dynamic.
