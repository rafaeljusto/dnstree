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
for a minute (`-keep`), and `-walks`, `-per-client` and `-timeout` bound how
many run, how many one client starts, and how long each may take. It listens on
`-addr`, `:8080` by default, or on `$PORT` when the host sets one; behind a
proxy, `-client-header` names the header that carries the visitor's address,
and the last address in it, the one the proxy wrote, is the one counted. The
host needs UDP and TCP out to port 53, and IPv6 to reach the servers that only
have it.

## On AWS Lambda

`make web-lambda` zips the server for Lambda's `provided.al2023` runtime, one
zip per architecture, into `build/`. Upload one as the function's code with
handler `bootstrap` and the matching architecture, and attach the [Lambda Web
Adapter](https://github.com/aws/aws-lambda-web-adapter) layer, which turns each
invocation into a request to the server on `:8080`:

```
arn:aws:lambda:<region>:753240598075:layer:LambdaAdapterLayerArm64:28
arn:aws:lambda:<region>:753240598075:layer:LambdaAdapterLayerX86:28
```

Version 28 of the layer is the adapter's 1.1.0.

Set `AWS_LWA_READINESS_CHECK_PATH=/healthz` on the function, and put a function
URL or a regional or HTTP API Gateway in front. The zip's `bootstrap` counts the
last address in `X-Forwarded-For`, which only holds when nothing but AWS reaches
the function; with CloudFront in front, the last address is CloudFront's, and
every visitor behind one edge counts as one. Give the function a timeout above
`-timeout` (15 seconds) and keep it out of a VPC, or give the VPC a NAT, so it
can reach port 53. Lambda outside a VPC has no IPv6, so servers that only have
it go unanswered. Each instance keeps its own walks and its own counts, so the
page's second request can walk again on a cold instance, and `-per-client`
holds per instance rather than for the whole function.
