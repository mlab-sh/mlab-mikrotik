# blast

What a compromised host on one segment reaches.

The router routes between every network it holds an address on. The only thing
that stops it is the `forward` chain — so the question is answered by two
facts: are both segments on this router, and does anything in `forward` say no.

```bash
mlab-mikrotik blast --from ether1
```

```
  Segments on this router

  INTERFACE   ADDRESS           NETWORK
  ether1      192.0.2.5/24      192.0.2.0
  br-access   10.0.21.1/24      10.0.21.0
  br-guest    10.0.99.1/24      10.0.99.0

  3 segments

  The forward chain

  active rules       0
  ends in a refusal  no

  nothing filters traffic between these segments: the router routes, and
  every machine on any of them reaches every machine on all the others

  Reach

  FROM                TO                     STATE  RULES NAMING IT
  ether1 (192.0.2.0)  br-access (10.0.21.0)  open   0
  ether1 (192.0.2.0)  br-guest (10.0.99.0)   open   0

  2 ordered pair(s): 2 open, 0 filtered, 0 blocked
```

## Three states, and the middle one is honest

| State | Means |
| --- | --- |
| `open` | no rule names this pair, and the chain does not end in a refusal |
| `filtered` | some rule names one side or the other — read them, order matters |
| `blocked` | no rule names this pair, and the chain ends in a refusal |

**`filtered` is deliberately undecided.** Saying whether those rules allow or
refuse a given packet needs per-packet evaluation of the whole ordered set, and
a guess would be worse than silence. The command says so on every run rather
than leaving you to assume it was worked out.

The one ordering question it *does* answer is the same one
[`firewall`](Firewall) answers: whether the chain's last active rule is a
refusal that narrows nothing.

## What counts as a segment

An address on an interface — except a `/32` or a `/128`. A host route is the
router talking to itself; no other machine can sit on it, and counting one as
a segment fills the matrix with pairs nobody can be on either end of. On a
router with six loopback addresses that is the difference between 170 pairs
and 104.

## Reading a large matrix

Segments multiply: ten of them make ninety ordered pairs. So:

- when every pair says the same thing, that is printed as **one fact** rather
  than ninety rows;
- `--from <interface>` narrows to one origin and always prints the rows;
- `--pairs` prints the whole matrix whatever its size;
- `-o json` always carries every pair.

## Which rules count as naming a pair

Interface, interface list, and address or network, on either side — RouterOS
rules are written all of those ways, and a rule that names only the network
still governs the pair. Direction is respected: a rule with
`in-interface=guest` names the guest → lan pair and not the reverse.
