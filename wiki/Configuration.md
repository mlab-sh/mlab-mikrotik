# Configuration

Instances, where they live, and what overrides what.

## The file

One JSON file, `$HOME/.mlab/mikrotik.conf`, written `0600` inside a `0700`
directory. It holds any number of named instances plus the name of the default
one.

```json
{
  "default": "lab",
  "profiles": {
    "lab": {
      "host": "192.0.2.1",
      "user": "mlab",
      "password": "…",
      "scheme": "https"
    }
  }
}
```

`MLAB_MIKROTIK_CONFIG` moves the file somewhere else.

## Why the password is stored as typed

RouterOS issues no API token. The REST API authenticates with HTTP Basic, which
sends the password itself on every request, so the CLI has to keep something it
can replay. Nothing weaker would work.

What follows from that:

- the file is `0600` in a `0700` directory, and every command warns if those
  permissions ever loosen;
- nothing prints it back — `profile show` and `config show` mask it, and the
  mask is `********` regardless of length, because a password's length narrows
  a guess;
- `--password` exists for scripts that already hold the secret, but
  `MIKROTIK_PASSWORD` is preferred, because a command line is visible to every
  user on the machine.

## Precedence

Each layer overrides the one before it: the stored instance, then the
environment, then the flags.

| Flag | Environment | In the file |
| --- | --- | --- |
| `--host` | `MLAB_MIKROTIK_HOST`, `MIKROTIK_HOST` | `host` |
| `--user`, `-u` | `MLAB_MIKROTIK_USER`, `MIKROTIK_USER` | `user` |
| `--password` | `MLAB_MIKROTIK_PASSWORD`, `MIKROTIK_PASSWORD` | `password` |
| `--scheme` | `MLAB_MIKROTIK_SCHEME`, `MIKROTIK_SCHEME` | `scheme` |
| `--insecure` / `--secure` | `MLAB_MIKROTIK_INSECURE`, `MIKROTIK_INSECURE` | `insecure` |
| `--output`, `-o` | `MLAB_MIKROTIK_OUTPUT`, `MIKROTIK_OUTPUT` | `output` |

The `MLAB_MIKROTIK_` form wins over the bare `MIKROTIK_` one, so a machine that
already has `MIKROTIK_HOST` set for something else can be overridden without
touching it.

Given a host and a user, the CLI runs with no config file at all:

```bash
MIKROTIK_PASSWORD="$ROUTER_PASSWORD" \
  mlab-mikrotik ping --host 192.0.2.1 -u mlab -o json
```

## Managing instances

```bash
mlab-mikrotik profile list          # `instance list` is the same command
mlab-mikrotik profile show lab
mlab-mikrotik profile use edge
mlab-mikrotik profile remove old
mlab-mikrotik config path
mlab-mikrotik config show
```

`profile list` marks the default and reports the TLS state of each:

```
  NAME  DEFAULT  TARGET             USER  TLS
  edge  false    http://192.0.2.9   ops   none
  lab   true     https://192.0.2.1  mlab  not verified

  2 instances
```

`tls none` means plain HTTP: the password crosses the network in the clear.
`not verified` means HTTPS against the certificate the router made for itself,
which is the default and is fine on a LAN; pass `--secure` once you have
installed a certificate it can prove.

## Removing the default

Deleting the default instance promotes whichever one is left, rather than
leaving a dangling name that would make every later command fail with "not
found".
