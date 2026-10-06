# The dnstree guide

One page per topic. The [flag table](../../README.md#using-it) links each flag to
the section that covers it.

| Page | What it covers |
| --- | --- |
| [Configuring](configuring.md) | the file of defaults; other roots, ports, trust anchors and resolvers; `--tcp`, `--dot`, `--doh` and `--fallback` |
| [DNSSEC](dnssec.md) | the chain of trust, denial of existence, signatures running out, keys and DS short of the advice, the keys every nameserver publishes, `--check-ds`, `--report`, ECH |
| [Checking a zone](zones.md) | `--check-ns`, records that point where they may not, `--serial`, `--check-axfr`, `--check-recursion`, `--check-edns`, `--caa`, `--spf`, `--rdap`, extended errors, `--nsid`, `--cookie`, `--qmin`, `--without`, `--try-ns`, answer sizes |
| [Resolvers](resolvers.md) | the comparison with your resolver, several resolvers at once, answers kept longer than the zone allows, `--subnet`, `--ddr` |
| [Reading a walk](output.md) | `--explain`, `--live`, the waterfall, every other `--format`, `--schema`, `--pcap` |
| [Scripts and monitoring](scripting.md) | `--expect`, `--diff`, several questions and `--names`, `--watch`, `--from` and `--against`, OpenMetrics |
| [dnstree-web](dnstree-web.md) | the same walk behind a form, as a service |
