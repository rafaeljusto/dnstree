#!/usr/bin/env bash
# dig-docker.sh up DIR | down DIR — a current BIND dig in a container, for a host
# whose own dig is older. up writes DIR/dig, which compare.sh takes as DIG;
# down removes the container. Only run once the user has agreed to it.
set -eu

# ISC's own image is built for amd64 alone, and from this Alpine; its
# bind-tools is the same BIND 9.20, native on arm64 too, and no server.
IMAGE=alpine:3.24
DIR=$2
NAME=dnstree-dig-$(basename "$DIR")

case $1 in
up)
	docker run -d --rm --name "$NAME" "$IMAGE" sleep 86400 > /dev/null
	docker exec "$NAME" apk add --no-cache --quiet bind-tools
	# One container answers every dig: starting one per query would cost
	# more than the query.
	printf '#!/bin/sh\nexec docker exec %s dig "$@"\n' "$NAME" > "$DIR/dig"
	chmod +x "$DIR/dig"
	"$DIR/dig" -v 2>&1
	;;
down)
	docker rm -f "$NAME" > /dev/null 2>&1 || true
	rm -f "$DIR/dig"
	;;
*)
	echo "usage: $0 up|down DIR" >&2
	exit 1
	;;
esac
