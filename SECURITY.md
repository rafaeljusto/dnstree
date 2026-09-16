# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for
receiving such patches depends on the CVSS v3.0 Rating:

| CVSS v3.0 | Supported Versions                        |
| --------- | ----------------------------------------- |
| 9.0-10.0  | Releases within the previous three months |
| 4.0-8.9   | Most recent release                       |

## Reporting a Vulnerability

Please report (suspected) security vulnerabilities to
**[cadastros@rafael.net.br](mailto:cadastros@rafael.net.br)**. You will receive a
response from us within 48 hours. If the issue is confirmed, we will release a
patch as soon as possible depending on complexity but historically within a few
days.

## What dnstree does with what it is given

dnstree talks to nameservers it was pointed at by the delegation it is
following, which means it talks to hosts a stranger chose. Two things follow
from that, and both are worth knowing when judging a report:

- **Answers are never trusted beyond their bailiwick.** A server may only hand
  out addresses for names at or below the zone it serves, and anything further
  afield is resolved on its own instead. A report showing a server able to steer
  the walk somewhere it should not reach is a vulnerability, not a bug.
- **Every walk is bounded.** Queries, zone cuts, aliases and nameserver
  resolutions all have budgets, so a hostile delegation can waste time but
  cannot make dnstree run forever. A report showing otherwise is a
  vulnerability.

The DNSSEC verdicts are diagnostic: dnstree reports what it found so you can see
a broken chain, and exits 3 when one is bogus. It is not a validating resolver
and nothing should be routed through it as though it were.
