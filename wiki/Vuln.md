# vuln

The published advisories that cover **this exact version**.

Not a reading list. This is the one place where RouterOS is better served than
UniFi: NVD carries version *ranges* for most of the RouterOS corpus and applies
them itself when the query carries a version, so the answer is "these cover
you" rather than "here are eighty-six advisories that mention RouterOS".

```bash
mlab-mikrotik vuln --allow-web
```

```
  RouterOS 6.48.0 (stable)

      high  CVE-2023-30799  CVSS 7.2  EPSS 1.4%
            MikroTik RouterOS stable before 6.49.7 and long-term through 6.48.6 are…
            ≥ 6.34, < 6.49.7 on the - branch

  critical  CVE-2022-45315  CVSS 9.8  EPSS 1.3%
            Mikrotik RouterOs before stable v7.6 was discovered to contain an out-o…
            < 7.6 on any branch

  11 cover this version, 1 could not be checked, 0 name another branch or version

  Could not be checked
    CVE-2021-3014  its bound ≤ "2021-01-04" is not a version number, so it cannot be checked
```

Every line says **why** it matched — the range and the branch — so the verdict
can be checked rather than trusted.

## Three answers, never two

| Verdict | Means |
| --- | --- |
| **covers this version** | a match's own bounds contain this version, on this branch |
| **could not be checked** | the advisory's bounds are not version numbers, or the record carries no CPE data |
| **names another branch or version** | NVD returned it, but every match names a branch this router is not on |

The middle one is the honest part of the answer and is never folded into
either of the others.

## Two things NVD's match does not do

**The edition.** A query for `…routeros:6.48.0` matches advisories written for
the long-term branch as readily as for stable, because the edition field of
the query is a wildcard. An advisory that only names `ltr` does not cover a
stable router. On the corpus, judging 6.48.0 as stable gives 11 hits; judging
the same version as long-term gives 9, with two excluded by name:

```
  Named another branch or version
    CVE-2025-6443   every match names another branch or another version (- < 7.20)
    CVE-2023-30800  every match names another branch or another version (- ≥ 6.0, < 6.49.10)
```

**Bounds that are not versions.** `CVE-2021-3014` carries
`version_end_including: "2021-01-04"` — a date. NVD's comparator sorts it
before every 7.x release and returns the CVE for every modern router. A bound
that will not parse as a version proves nothing, and is reported as such
rather than believed. That single record is the reason this command has a
third category at all.

## Options

| Flag | What it does |
| --- | --- |
| `--allow-web` | Ask vuln.mlab.sh; without it nothing is looked up |
| `--refresh` | Ignore a fresh cache entry and ask again |
| `--all` | Also list what was excluded, and why |
| `--version V` | Judge a version other than the installed one |
| `--channel C` | Judge against `stable`, `long-term` or `testing` instead of the router's own |

`--version` and `--channel` change nothing on the router. Together they answer
"would moving to long-term help", before doing it.

```bash
mlab-mikrotik vuln --allow-web --version 7.15.3
mlab-mikrotik vuln --allow-web --channel long-term --all
mlab-mikrotik vuln --allow-web -o json | jq '.assessed[] | select(.verdict=="applies") | .advisory.id'
```

## Where the answer came from

The corpus is cached for six hours, and a cached answer is served whether or
not `--allow-web` was passed — the flag gates the network, not data already on
disk. So the last line always says which it was:

```
  from cache, 8 minutes old — add --refresh to ask again
  looked up just now — add --refresh to ask again
```

## What is sent

`cpe:2.3:o:mikrotik:routeros:<version>` and nothing else. Not the identity,
not the serial, not a single line of configuration. See
[Enrichment](Enrichment).

## The limit worth stating

An advisory that names no version at all cannot be ruled out by this method,
and the command says so on every run. Absence of a match is not proof of
safety — it is the absence of a *published, versioned* claim.
