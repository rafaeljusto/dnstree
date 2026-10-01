# The dnstree guide

One page per topic. The [flag table](../../README.md#using-it) links each flag to
the section that covers it.

| Page | What it covers |
| --- | --- |
| [Configuring](configuring.md) | the file of defaults; other roots, ports, trust anchors and resolvers |
| [DNSSEC](dnssec.md) | the chain of trust, denial of existence, signatures running out, `--check-ds`, ECH |
| [Checking a zone](zones.md) | `--check-ns`, `--serial`, `--check-axfr`, `--check-recursion`, extended errors, `--nsid`, `--cookie`, `--qmin`, `--without`, answer sizes |
| [Resolvers](resolvers.md) | the comparison with your resolver, several resolvers at once, `--subnet`, `--ddr` |
| [Reading a walk](output.md) | `--explain`, `--live`, the waterfall, every other `--format`, `--schema` |
| [Scripts and monitoring](scripting.md) | `--expect`, `--diff`, `--watch`, `--from` and `--against`, OpenMetrics |
| [dnstree-web](dnstree-web.md) | the same walk behind a form, as a service |
