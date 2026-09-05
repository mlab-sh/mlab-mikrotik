# Secrets

What never reaches the disk, and why the list is explicit.

## The problem is upstream

RouterOS has no API token. It also has no read-only group worth the name: the
built-in `read` group carries the `sensitive` policy, so an account chosen for
its name gets pre-shared keys, IPsec secrets, RADIUS shared secrets and VPN
passwords back **in clear text**, without asking for them. See
[Account](Account).

That means anything this tool writes to disk has to be cleaned on the way out,
and it means [`whoami`](Whoami) warns when the account carries `sensitive` —
a tool that *could* have written a key to disk deserves the same scrutiny as
one that did.

## What replaces a secret

Its length, and nothing else.

```json
"secret": "<redacted:16>"
```

A length is not a secret, and it is exactly what a strength check needs: a
redacted snapshot can still be audited for a short pre-shared key. The value
itself never reaches the disk, and the count of replacements is printed on
every [`snapshot`](Snapshot) — it is the measure of what this account was
handed.

## The field list

Sixteen names, in `src/secrets.rs`:

```
password                    passphrase
pre-shared-key              wpa-pre-shared-key
wpa2-pre-shared-key         authentication-password
encryption-password         auth-password
secret                      secrets
private-key                 shared-secret
eap-password                mschap2-password
wireguard-private-key       supplicant-identity-password
```

**Deliberately an explicit list rather than a substring rule.** Matching on
`key` would take `key-type`, `host-key-size` and `public-key`, none of which is
a secret — and a redactor that noisy is one somebody switches off.

## Two things it does not do

**An empty value is left alone.** Marking it would turn "this profile has no
key" into "this profile has a key of length zero", which reads as configured.

**A value RouterOS already masked is not counted.** Without the `sensitive`
policy the router answers `***`. Replacing that with `<redacted:3>` would claim
the tool held a secret it never saw.

## What is still in a snapshot

Everything else, including things that are sensitive in a looser sense: SNMP
community names, which are the password in v1/v2c; the router's serial number;
account names; the addresses and comments of every rule.

A snapshot is a security document. It is written `0600` in a `0700` directory
for that reason, and it should be kept where the router's configuration would
be kept.

## What is never sent anywhere

Nothing. No phase-three command makes an outbound call of any kind. The one
external lookup the roadmap plans — CVE correlation in phase four — carries
version strings and nothing else, behind an explicit flag.
