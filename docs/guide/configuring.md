# Configuring

Where the defaults come from, and how to point a walk at servers other than the
real root.

- [Defaults](#defaults)
- [Pointing it somewhere else](#pointing-it-somewhere-else)

## Defaults

Flags you always type belong in a file instead. `dnstree` reads the first of
`$DNSTREE_CONFIG`, `$XDG_CONFIG_HOME/dnstree/config` (`~/.config/dnstree/config`
where that is unset, `%AppData%\dnstree\config` on Windows) and `~/.dnstreerc`:

```
# ~/.dnstreerc
format = emoji
dnssec
timeout = 3s
```

One long flag name per line, with the value it takes. `name value` works as well
as `name = value`, the dashes of a pasted command line are allowed and ignored,
and a flag that stands on its own needs no value. A line opening with `#` is a
comment; a `#` partway along a line is part of the value, so a setting and what
it is for go on separate lines. A name that is not a flag, or one missing the
value it takes, is reported against the line that wrote it, and so are `config`,
`no-config`, `version`, `schema`, `from`, `against`, `x`, `names` and
`without`: those nine ask something of the run rather than set a default for it.

> [!NOTE]
> A file named outright — by `$DNSTREE_CONFIG` or by `--config` — has to be
> there, and a missing one is an error. The two conventional locations are
> read if they exist.

The command line wins over the file, so `--format ascii` overrides the line
above and `--dnssec=false` turns a flag it set back off. Flags that answer one
question in different ways give way as a group, rather than colliding: naming
any of `--udp`, `--tcp`, `--dot` or `--doh` drops whichever transport the file
chose, and so it goes for `-4` and `-6`, for `--root` and `--root-hints`, and
for `--tls-ca` and `--tls-insecure`; `--against` drops a `diff`. Every format
but `tree`, `ascii` and `emoji` drops a `live` and a `watch` the file set, since
all the others are
written once at the end and leave neither anything to draw nor anything to
change; `json`, `dot`, `mermaid`, `waterfall-mermaid` and `openmetrics` drop an
`explain` and a `diff` as well, being read by a program that has the whole trace
already. A
format that serves no page drops a `web-addr` and a `no-browser` it set, and
`--from` drops a `live`, a `watch` and a `diff`, which are about walks being
made. `--config FILE` reads somewhere else, and `--no-config` reads nowhere.

`root` and `resolver` are the lines worth repeating: a file may carry as many
as the walk should start from, or ask, in the order they are written. One
`--root` or `--resolver` on the command line replaces every line of its kind,
rather than adding to them, and `--root-hints` replaces the roots too.

> [!TIP]
> [`dnstreerc.example`](../../dnstreerc.example) is a file of every setting worth
> making, annotated and commented out. Copy it and uncomment what you want.

## Pointing it somewhere else

Nothing about the walk assumes the real root. `--root` names the servers it
starts from, one flag each, and each may carry the port the server listens on:

```
$ dnstree --root a.root-servers.net@127.0.0.1:5353 --port 5354 \
    --trust-anchors ./anchors.xml --dnssec www.test A
```

A root that carries no port is asked on `--port`, and so is everything reached
by glue below it — glue carries addresses and never ports, so a hierarchy on
one host wants its root on a port of its own and the rest on `--port`.
`--root` and `--root-hints` say the same thing two ways, so only one of them
may be given. `--trust-anchors` takes IANA's `root-anchors.xml` or DS records
in presentation format.

`--resolver ADDR` points everything that needs a recursive server at one of
your own: the origin AS lookups and the timed comparison. `--no-asn` and
`--no-compare` skip either; asking for both is refused, since it leaves
`--resolver` nothing to do. `--asn-resolver` is its older name. One on the
command line replaces every one the file chose. Without it, the comparison
asks the first nameserver in `/etc/resolv.conf`; where there is none, as on
Windows, nothing is compared until one is named.

The origin AS lookups are TXT queries to Team Cymru's `origin.asn.cymru.com`
zones, made through the host's resolver or the first `--resolver`; `--no-asn`
turns them off.

For `--dot` and `--doh`, `--tls-ca FILE` verifies against a CA of your own.

> [!CAUTION]
> `--tls-insecure` verifies nothing at all. It is there to reach a server
> holding a test certificate, and it is worth nothing anywhere else.
