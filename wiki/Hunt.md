# hunt

The markers a compromised MikroTik router leaves behind.

```bash
mlab-mikrotik hunt
```

```
  Hunt

  accounts  a login left behind is the cheapest persistence there is
    · ops — group full — last login 2026-07-24 23:53:08
    · monitor — group read — last login never

  files on the router's storage  captures, backups and support dumps hold more than they look like they do
    · autosupout.rif (567.6 kB)
    · console-dump.txt (19.7 kB)
    · radius-check.pcap (464 B)

  2 of 10 markers found something
  add --all to see the ones that found nothing

  none of this is evidence of anything on its own. A scheduled task that fetches
  is a backup job on most routers and persistence on a few, and only you know
  which. What `hunt` gives you is the list to go through, not a verdict.
```

## Why RouterOS gets this command and the others do not

MikroTik is the one platform in this suite with a **public, repetitive corpus
of post-exploitation behaviour**. The Mēris campaigns, the `error.html` mining
injection, the persistence dropped after `CVE-2018-14847` — every post-mortem
describes the same handful of places, and every one of them can be read over
the API.

Neither `mlab-unifi` nor `mlab-proxmox` has that, which is why neither has a
`hunt`.

## The ten markers

| Marker | What it would mean |
| --- | --- |
| scheduled tasks | the persistence mechanism seen most often on RouterOS |
| scripts | what a scheduled task, a netwatch probe or a login can run |
| netwatch probes with a script | a second persistence path, forgotten after `/system/scheduler` is cleaned |
| SOCKS proxy | the relay every MikroTik botnet campaign since 2018 has left behind |
| web proxy | where the `error.html` injection campaigns put their payload |
| outbound tunnels | a path back into this network for whoever terminates it |
| accounts | a login left behind is the cheapest persistence there is |
| files on the router's storage | captures, backups and support dumps hold more than they look like they do |
| static DNS entries | a name this router answers for, whatever the real one resolves to |
| certificates | one this router did not need is one somebody else installed |

Markers that found nothing are hidden by default; `--all` shows them, which is
the form to use when you want to record that you looked.

## The sentence this hangs on

**None of this is evidence of anything on its own.** A scheduled task that runs
`/tool fetch` is a backup job on most routers and persistence on a few, and
nothing in the configuration distinguishes them — only the operator knows which
one they wrote. `hunt` produces the list to go through, never a verdict about
who put something there.

That is also why the graded version in `audit` is worded the way it is: a
scheduled fetch is **high**, not critical, and the detail says *confirm you
wrote it*. It rises to **critical** only when the same script both fetches and
changes accounts, SOCKS, the proxy or NAT — the combination the campaigns
actually left, and one no backup job needs.

## Files are not innocent

Three kinds are worth removing rather than leaving:

- **`.pcap`** — a packet capture, readable by anyone who can read the router's
  files.
- **`autosupout.rif`** — a support dump containing the whole configuration.
  MikroTik support is the only reason to make one.
- **`.backup`** — a binary configuration backup, restorable as-is onto another
  router.

## A RouterOS quirk this command had to work around

`GET /rest/file` embeds each file's **contents**, and one binary file makes the
entire response invalid UTF-8 — the request answers `200` with bytes that are
not JSON. Every read of `/file` in this tool names its properties explicitly.
See [Surfaces](Surfaces).
