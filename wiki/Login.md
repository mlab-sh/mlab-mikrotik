# login

Create or update an instance, prove the credentials work, and only then write
the file.

```bash
mlab-mikrotik login --name lab --host 192.0.2.1 --user mlab
```

`login` asks for whatever it is missing, reads the password without echoing it,
tests the credentials against `/system/resource` and `/system/identity`, and
writes the config `0600` in a `0700` directory.

```
  ✔ connected to gw-edge-01 — RouterOS 7.24.2 (stable) on CCR2004-1G-12S+2XS
  ! TLS certificate verification is off for this instance
  ✔ saved instance "lab" to /home/you/.mlab/mikrotik.conf

  host      192.0.2.1
  user      mlab
  scheme    https
  password  ********
```

**A failed test writes nothing.** A wrong password produces the 401 and leaves
the config file exactly as it was.

## Options

| Flag | What it does |
| --- | --- |
| `--name`, `-n` | Instance name to create or update (default: `default`) |
| `--set-default` | Make this the default instance |
| `--no-test` | Save without checking the credentials — warns, and is the only way to configure a router that is currently down |
| `--non-interactive` | Never prompt; fail when something is missing |

The global connection flags all apply: `--host`, `--user`, `--password`,
`--scheme`, `--insecure` / `--secure`, `--output`.

## An empty password

RouterOS ships with an `admin` account that has none, and that is a real login
rather than a mistake in the tool. `login` accepts it and says so:

```
  ! this login has no password
```

## Plain HTTP

`--scheme http` reaches the `www` service on port 80. Basic auth sends the
password in the clear there, so the command says so every time:

```
  ! plain http: the password crosses the network in the clear
```

## Non-interactive

For CI, pass everything and keep the secret out of the command line:

```bash
MIKROTIK_PASSWORD="$ROUTER_PASSWORD" \
  mlab-mikrotik login -n ci --host 192.0.2.1 -u mlab --non-interactive
```
