# dnstree-web

`dnstree-web` is the same walk behind a form: somebody types a name and a type,
and gets the scene or the tree at an address of its own, such as
`/3d/www.example.com/A/`, that can be handed on. Every release publishes it as a
container, beside the command line's; `make image-web` builds one from the tree:

```
docker run --rm -p 8080:8080 ghcr.io/rafaeljusto/dnstree-web
```

Every walk checks the chain of trust, and nothing a visitor sends reaches the
resolver but the question. Glue pointing at a private, loopback or link-local
address is recorded as refused and never asked, so a zone cannot aim the server
at the network it runs on. Walks for the same question are made once and kept
for a minute, and `-walks`, `-per-client` and `-timeout` bound how many run,
how many one client starts, and how long each may take. It listens on `$PORT`
when the host sets one; behind a proxy, `-client-header` names the header that
carries the visitor's address, and the last address in it, the one the proxy
wrote, is the one counted. The host needs UDP and TCP out to port 53, and
IPv6 to reach the servers that only have it.
