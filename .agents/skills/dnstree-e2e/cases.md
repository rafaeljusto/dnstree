# Cases

What each run is, and what a user should see. `$D` is the binary and `$B` is
`--no-asn --no-compare --color never`, as set up in [SKILL.md](SKILL.md). Every
case also has to pass the checks under "Judge every run" there.

The expectations were observed on 2026-10-03 at 043a63c. The targets are real
zones, chosen because they have stayed put for years:

| target | why |
| --- | --- |
| `example.com` | signed (secure), served by Cloudflare, answers A |
| `nope-e2e-zz9.iana.org` | NXDOMAIN under a signed zone with classic NSEC denial |
| `dnssec-failed.org` | deliberately bogus |
| `google.com` | unsigned (insecure), CAA `pki.goog`, and its servers echo ECS |
| `www.github.com` | a CNAME to `github.com` |
| `zonetransfer.me` | AXFR deliberately open |
| `cloudflare.com` | publishes CDS matching its DS |
| `one.one.one.one@1.1.1.1` | speaks DoT and DoH, answers DDR |
| `münchen.de` | a name outside ASCII |

When a target drifts, replace it and update this table. Don't loosen the
expectation.

## cli

These need no network: every one exits before a query goes out.

| id | run | expect |
| --- | --- | --- |
| help | `$D --help` | usage on stderr, exit 1 (`flag.ErrHelp` maps to the command-line code) |
| version | `$D --version` | one line, exit 0 |
| schema | `$D --schema` | exit 0, byte for byte the `docs/trace.schema.json` of the tree that was built |
| bad-flag | `$D --bogus example.com` | exit 1, names the flag |
| any | `$D example.com ANY`, then `AXFR`, then `IXFR` | exit 1 each, says why and what to ask instead |
| bad-type | `$D example.com NOTATYPE` | exit 1 |
| bad-name | `$D bad..name` | exit 1, "is not a domain name" |
| bad-x | `$D -x 999.1.1.1` | exit 1, "is not an address" |
| bad-format | `$D --format nope example.com` | exit 1 |
| bad-color | `$D --color sometimes example.com` | exit 1 |
| bad-timeout | `$D --timeout -1s example.com` | exit 1 |
| bad-subnet | `$D --subnet nonsense example.com` | exit 1 |
| udp-tcp | `$D --udp --tcp example.com` | exit 1: both cannot carry the queries |
| four-six | `$D -4 -6 example.com` | exit 1 |
| dot-doh | `$D --dot --doh example.com` | exit 1 |
| check-ds-alone | `$D --check-ds example.com` | exit 1: it needs `--dnssec` |
| ddr-no-compare | `$D --ddr --no-compare example.com` | exit 1 |
| diff-against | `$D --diff --against x.json example.com` | exit 1: ask for one |
| watch-short | `$D --watch 500ms example.com` | exit 1: a second is the least |
| live-waterfall | `$D --live --format waterfall example.com` | exit 1 |
| json-several | `$D --format json example.com A AAAA` | exit 1: one walk only. Also dot, mermaid, openmetrics and web |
| from-name | `$D --from ex.json example.com` | exit 1: no name to resolve |
| from-shape | `$D --from ex.json --no-asn` | exit 1: a walk already made cannot be changed |
| names-expect | `$D --names list --expect secure` | exit 1 |
| names-missing | `$D --names nope.txt` | exit 1, and the message should say which flag the file came from |
| hints-missing | `$D --root-hints nope.txt example.com` | exit 1, same |
| hints-junk | `$D --root-hints junk.txt example.com` | exit 1, names the file and line |
| anchors-junk | `$D --trust-anchors junk.txt --dnssec example.com` | exit 1, names the file and line |
| tls-ca-junk | `$D --dot --root one.one.one.one@1.1.1.1 --tls-ca junk.pem example.com` | exit 1: no certificate in it |

## walk

| id | run | expect |
| --- | --- | --- |
| plain | `$D $B example.com` | exit 0. The root, then `referral → com.`, then `example.com.` with A records, then `✔ answered` |
| types | `$D $B example.com A AAAA` | exit 0, two walks, each under a line that names it |
| nxdomain | `$D $B --expect nxdomain nope-e2e-zz9.iana.org` | exit 0. NXDOMAIN is an answer |
| nodata | `$D $B --expect nodata example.com NAPTR` | exit 0 |
| cname | `$D $B www.github.com` | exit 0, the CNAME to `github.com.` drawn, then the walk to its A |
| reverse | `$D $B -x 8.8.8.8` | exit 0, `8.8.8.8.in-addr.arpa.` PTR `dns.google.` |
| reverse6 | `$D $B -x 2001:4860:4860::8888` | exit 0, a PTR under `ip6.arpa.` |
| idn | `$D $B münchen.de` | exit 0, asked and drawn as `xn--mnchen-3ya.de.` |
| all | `$D $B --all example.com` | exit 0. Every nameserver of each zone asked: dozens of queries, not 3 |
| qmin | `$D $B --qmin www.example.com` | exit 0, hops marked `(minimised to …)` |
| without | `$D $B --without a.root-servers.net example.com` | exit 0, a.root not asked, and the summary says `without a.root-servers.net.` |
| nsid | `$D $B --nsid example.com` | exit 0, an `@identifier` beside the servers that publish one (the roots do) |
| cookie | `$D $B --cookie example.com` | exit 0, every hop says `cookie`, `no cookie` or one of the other states |
| subnet | `$D $B --subnet 8.8.8.0/24 www.google.com` | exit 0, Google's hops say `ecs scope /N` |
| explain | `$D $B --explain example.com` | exit 0, sentences under the tree naming the answer and who gave it |
| debug | `$D $B --debug example.com` | exit 0, one stderr line per query asked, and stdout unchanged |
| asn | `$D --no-compare --color never example.com` | exit 0, an `AS<n>` beside each server queried |
| compare | `$D --no-asn --color never example.com` | exit 0, the summary says `resolver in …` |
| resolvers | `$D --no-asn --color never --resolver 1.1.1.1 --resolver 8.8.8.8 example.com` | exit 0, `resolvers in …-…`, and any that disagreed named under the tree |
| asn-resolver | `$D --no-asn --color never --asn-resolver 1.1.1.1 example.com` | same as one `--resolver`: the old name still works |
| ddr | `$D --no-asn --color never --resolver 1.1.1.1 --ddr example.com` | exit 0, a `ddr: 1.1.1.1 offers doh …, dot …` line |
| ipv4 | `$D $B -4 example.com` | exit 0, only IPv4 addresses asked |
| ipv6 | `$D $B -6 example.com` | exit 0, only IPv6 addresses asked. Skip it if the environment has no IPv6 |
| color | `$D --no-asn --no-compare --color always example.com` | escapes on stdout even though it is a pipe |

## dnssec

| id | run | expect |
| --- | --- | --- |
| secure | `$D $B --dnssec --expect secure --expect fresh example.com` | exit 0, `[secure …]` on the hops |
| insecure | `$D $B --dnssec --expect insecure google.com` | exit 0 |
| bogus | `$D $B --dnssec dnssec-failed.org` | exit 3, `✘ bogus`, the tree still drawn |
| denial | `$D $B --dnssec --expect nxdomain --expect secure nope-e2e-zz9.iana.org` | exit 0. The NXDOMAIN rests on a signed proof |
| compact-denial | `$D $B --dnssec --expect nxdomain nope-e2e-zz9.example.com` | Cloudflare denies with compact NSEC (NXNAME). At 043a63c this reads as nodata and exits 4. Report what it does now |
| anchors | `$D $B --dnssec --trust-anchors good.ds example.com` | exit 0. `good.ds` holds the root DS for keys 20326 and 38696, in zone-file form |
| anchors-wrong | `$D $B --dnssec --trust-anchors bad.ds example.com` | exit 3. `bad.ds` is key 20326 with a zeroed digest |
| check-ds | `$D $B --dnssec --check-ds cloudflare.com` | exit 0, `cds matches the ds` |
| bogus-expect | `$D $B --dnssec --expect 1.2.3.4 dnssec-failed.org` | exit 3, not 4: the broken chain wins |

## transport

The roots speak neither DoT nor DoH, so walking from them with `--dot` takes
over a minute to fail. Start these from a resolver that speaks both.

| id | run | expect |
| --- | --- | --- |
| tcp | `$D $B --tcp example.com` | exit 0 |
| dot | `$D $B --dot --root one.one.one.one@1.1.1.1 example.com` | exit 0, one hop, A records |
| doh | `$D $B --doh --root one.one.one.one@1.1.1.1 example.com` | exit 0 |
| tls-ca | `$D $B --dot --root one.one.one.one@1.1.1.1 --tls-ca /etc/ssl/cert.pem example.com` | exit 0 (use the system bundle of the platform) |
| tls-insecure | `$D $B --dot --root 1.1.1.1 --tls-insecure example.com` | exit 0 |
| dot-no-name | `$D $B --dot --root 1.1.1.1 example.com` | exit 2, and the hop should say to name the server or pass `--tls-insecure`. At 043a63c it prints Go's `tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config` |
| fallback | `$D $B --dot --fallback --timeout 1s example.com` | exit 0: plain DNS picks up the hops DoT could not. Expect it to be slow |

## zone

| id | run | expect |
| --- | --- | --- |
| check-ns | `$D $B --check-ns example.com` | exit 0, a `(parent/child NS check)` hop |
| serial | `$D $B --serial example.com` | exit 0, a `(SOA of example.com.: N)` per nameserver |
| axfr-open | `$D $B --check-axfr zonetransfer.me SOA` | exit 0, `axfr open` on its nameservers. Nothing of the zone drawn |
| axfr-closed | `$D $B --check-axfr example.com` | exit 0, none open |
| axfr-doh | `$D $B --check-axfr --doh --root one.one.one.one@1.1.1.1 example.com` | the usage says `--doh` cannot ask it. Check that this is said, not silently skipped |
| recursion | `$D $B --check-recursion example.com` | exit 0, `recursion closed` per nameserver |
| caa | `$D $B --caa --expect caa:pki.goog google.com` | exit 0, `caa: google.com. decides it`, `may issue: pki.goog` |
| caa-miss | `$D $B --caa --expect caa:letsencrypt.org google.com` | exit 4 |

## budget

| id | run | expect |
| --- | --- | --- |
| max-queries | `$D $B --max-queries 2 example.com` | exit 2, `gave up after 2 queries`, and the summary should count 2. At 043a63c it says 3 |
| max-depth | `$D $B --max-depth 1 example.com` | exit 2, `gave up after 1 zone cuts`, the summary counting the queries drawn. At 043a63c it says 2 for 1 |
| max-cname | `$D $B --max-cname 1 www.github.com` | exit 0. One alias is all it has |
| max-cname-0 | `$D $B --max-cname 0 www.github.com` | 0 is read as the default of 8, so the alias is followed. Nothing in the usage says so, which is a ux finding until it does |
| timeout | `$D $B --timeout 200ms --retries 0 --root 192.0.2.1 example.com` | exit 2 within about a second, `timeout` on the hop |
| retries | the same with `--retries 2` | exit 2, `asked again after a silence`. With `--retries 0` that is absent |
| port | `$D $B --port 9 --timeout 300ms --retries 0 --root a.root-servers.net@198.41.0.4 example.com` | exit 2, `no server answered for .`, the tree drawn |

## start

| id | run | expect |
| --- | --- | --- |
| root | `$D $B --root a.root-servers.net@198.41.0.4 example.com` | exit 0, starts from a.root alone |
| root-hints | `$D $B --root-hints one.hints example.com` | exit 0, no other root drawn. `one.hints` is a named.root with only a.root's NS and A |

## formats

Make one saved walk first: `$D $B --dnssec --format json example.com > ex.json`
(exit 0, valid JSON with `jq`, `schema_version` present). Then draw it in every
format with `$D --color never --from ex.json --format F`. `--from` takes no
`$B`, since a walk already made cannot be changed.

| format | expect |
| --- | --- |
| tree | the tree, box-drawing characters |
| ascii | the same shape, nothing above 127 |
| emoji | the same shape, emoji in labels and never in the branch prefixes (every `├──` lines up) |
| waterfall | one row per query with bars |
| waterfall-ascii | `#` and `.` bars, nothing above 127 |
| waterfall-mermaid | a `---` front matter with the title, then `gantt` |
| markdown | a heading, the tree in a code fence, the explanation, the resolvers' table |
| json | the same JSON back: `jq -S` of both match |
| dot | `dot -Tsvg` renders it, when Graphviz is installed |
| mermaid | a `---` front matter with the title, then `flowchart LR` |
| openmetrics | `dnstree_` metric lines, ends with `# EOF` |

`web` and `web-3d` are under `long`.

## saved

| id | run | expect |
| --- | --- | --- |
| from-stdin | `$D --color never --from - < ex.json` | the same as `--from ex.json` |
| from-explain | `$D --color never --from ex.json --explain` | sentences, no query made |
| from-expect | `$D --from ex.json --expect secure` | exit 0, then `--expect bogus` exits 4 |
| against-same | `$D --color never --from ex.json --against ex.json` | exit 0, `nothing differs` |
| against-other | `$D $B --format json example.com AAAA > aaaa.json`, then `--from aaaa.json --against ex.json` | exit 1: not the same question |
| from-offline | any `--from` case with the network down, or `--root 192.0.2.1` | still works. `--from` asks nothing |

## script

| id | run | expect |
| --- | --- | --- |
| expect-rdata | `$D $B --expect <an A of example.com> example.com` | exit 0. Take the address from `ex.json` |
| expect-miss | `$D $B --expect 203.0.113.8 example.com` | exit 4, `expected 203.0.113.8, got …` on stderr |
| expect-eq | `$D $B --expect =answer example.com TXT` | exit 4: `=` forces rdata, and no TXT reads `answer` |
| expect-no-chain | `$D $B --expect secure example.com` | exit 4: `got a walk that followed no chain of trust` |
| expect-fresh-3d | `$D $B --dnssec --expect fresh:3d example.com` | exit 4 while Cloudflare signs for a day at a time: `run out in 1 day …` |
| names-file | a file with `example.com A`, a `#` comment, a blank line and `iana.org MX`, passed as `--names list` | exit 0, two walks each under its name, the comment and the blank skipped |
| names-stdin | the same piped to `--names -` | the same |
| names-worst | `--names` with `example.com` and `dnssec-failed.org` plus `--dnssec` | exit 3: the worst of them |
| diff-first | `$D $B --diff example.com` | exit 0, `nothing to compare: this is the first walk …`, one file in the cache |
| diff-second | the same again | `nothing has changed since …`, still one file |
| diff-names | `--names` with two questions and `--diff` | one cache file per question |

## config

Write the files under `$E2E/xdg-config`, and remove them after each case.

| id | run | expect |
| --- | --- | --- |
| xdg | `format = json` in `$XDG_CONFIG_HOME/dnstree/config`, then `$D --no-asn --no-compare example.com` | JSON out |
| env | the same file named by `DNSTREE_CONFIG` | JSON out |
| dotfile | the same in `$HOME/.dnstreerc`, with nothing else | JSON out |
| cli-wins | the file says `format = json`, the command line says `--format ascii` | ASCII out |
| group | the file says `tcp`, the command line says `--udp` | no "cannot both" error: the command line replaces the group |
| config-flag | `$D --config file …` | that file is read and the others are not |
| no-config | `$D --no-config …` with the file present | the file ignored |
| debug-config | `--debug` with a file | stderr says which file the defaults came from |
| check-ds-file | the file says `check-ds`, run without `--dnssec` | no error: heeded only by runs that check signatures |
| example | `$D --config dnstreerc.example $B example.com` | exit 0: the shipped example parses |

## long

Each of these runs in the background, gets its port polled for up to 20 seconds,
and is stopped with `kill -INT`. Interrupting it is how a user ends it, so the
exit code that follows counts.

| id | run | expect |
| --- | --- | --- |
| web | `$D $B --format web --no-browser --web-addr 127.0.0.1:PORT example.com` | stdout `the walk is at http://127.0.0.1:PORT/`. `GET /` is 200 HTML. `GET /trace.json` is the walk, valid against the schema. Exit 0 on interrupt |
| web-3d | the same with `--format web-3d` | the same |
| web-free-port | `--format web --no-browser` without `--web-addr` | prints an address on a free port, which answers. Read it from stdout |
| live | `script -q $E2E/cases/live/tty $D --no-asn --no-compare --live example.com < /dev/null` (it needs a terminal, and `script` needs a stdin it can own) | exit 0. The tty transcript ends with the same finished tree a run without `--live` prints |
| watch-expect | `$D $B --watch 2s --expect answer example.com` | exits 0 by itself, once the expectation holds |
| watch | `$D $B --watch 2s example.com` for about 7 seconds, then interrupted | one tree, then silence: nothing changed, so nothing said |

## web

dnstree-web on a free port: `$E2E/dnstree-web -addr 127.0.0.1:PORT`.

| id | run | expect |
| --- | --- | --- |
| health | `GET /healthz` | 200 `ok` |
| form | `GET /` | 200 HTML |
| ask | `GET /walk?name=example.com&type=A&view=tree` | 303 to `/tree/example.com/A/` |
| tree | `GET /tree/example.com/A/` | 200 |
| trace | `GET /tree/example.com/A/trace.json` | the walk, with DNSSEC checked (`"state": "secure"` on the root) |
| scene | `GET /3d/example.com/A/` | 200 |
| bad-name | `GET /walk?name=a/b&type=A&view=tree` | refused with a 4xx, nothing walked |
| bad-view | `GET /nope/example.com/A/` | 404 |
| rate | a second server with `-per-client 2`, then `trace.json` of three different names | 200, 200, 429. `/walk` only redirects, so it is never limited |
