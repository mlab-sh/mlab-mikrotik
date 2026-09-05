# api

Raw request against any menu, for everything the CLI does not wrap yet.

This is the lab bench: try a menu here, and once it earns its place, it gets a
module of its own.

```bash
mlab-mikrotik api GET /system/resource
mlab-mikrotik api GET /ip/address --list
mlab-mikrotik api GET /interface --list --props name,type,running
mlab-mikrotik api GET /ip/firewall/filter --list --limit 20
```

`PATH` is a RouterOS menu relative to `/rest`. A leading `/rest` is stripped if
you paste one, and a missing leading `/` is added.

## Options

| Flag | What it does |
| --- | --- |
| `--list` | Render an array response as a table instead of a block |
| `--limit N` | With `--list`, stop after N rows |
| `--props A,B,C` | RouterOS `.proplist` — only these properties |
| `--query K=V` | Extra query parameter, repeatable |
| `--data`, `-d` | JSON body: inline, `@file`, or `-` for stdin |
| `--write` | Required for any method that is not GET |

There is no `-d` short form clash and no `-q`: `-q` is the global `--quiet`.

## `--props` is not optional on wide menus

RouterOS has no pagination — a menu answers with its whole collection in one
array. `/ip/firewall/connection` on a busy router is tens of thousands of rows
with forty properties each.

```bash
mlab-mikrotik api GET /ip/firewall/connection --list --props src-address,dst-address,protocol --limit 50
```

## Writes are guarded

RouterOS maps the HTTP verbs onto console commands: `PATCH` is `set`, `PUT` is
`add`, `DELETE` is `remove`, and `POST` runs an arbitrary command. Anything
that is not a GET therefore changes a live router, and has to be asked for
twice:

```
$ mlab-mikrotik api DELETE '/ip/address/*99'
  ✖ DELETE changes the router; pass --write to allow it
hint: on RouterOS, PATCH is `set`, PUT is `add`, DELETE is `remove`, and POST
      runs an arbitrary console command
```

With `--write`, it warns before sending and then does exactly what you asked.
No wrapped command in this CLI has any such path: they issue GETs only.

## Reading the output

Without `--list`, the response is rendered as a key/value block, nesting into
objects and tables of objects. With `--list`, the columns are the scalar fields
of the first row, identity fields first.

`-o json` prints the response untouched, which is what to use when the shape is
the point:

```bash
mlab-mikrotik api GET /system/routerboard -o json
```
