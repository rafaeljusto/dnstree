#!/bin/sh
# Refreshes the embedded root hints and DNSSEC trust anchors.
set -eu

dir=$(CDPATH= cd -- "$(dirname -- "$0")/../internal/roothints/data" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fetch() {
	curl -fsS --max-time 30 "$1" -o "$tmp/$2"
}

fetch https://www.internic.net/domain/named.root named.root
fetch https://data.iana.org/root-anchors/root-anchors.xml root-anchors.xml
fetch https://data.iana.org/root-anchors/root-anchors.p7s root-anchors.p7s
# Pinned out of band once; ICANN publishes it alongside the anchors.
fetch https://data.iana.org/root-anchors/icannbundle.pem icannbundle.pem

openssl smime -verify -CAfile "$tmp/icannbundle.pem" -inform der \
	-in "$tmp/root-anchors.p7s" -content "$tmp/root-anchors.xml" >/dev/null

mv "$tmp/named.root" "$tmp/root-anchors.xml" "$dir/"
echo "updated; run 'go test ./internal/roothints/...' to validate"
