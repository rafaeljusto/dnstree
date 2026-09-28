#!/bin/sh
# Takes the still of --format web-3d in docs/: serves a real walk, lets headless
# Chrome run the page's clock past the replay, and screenshots what it drew.
# CHROME names the browser when it is not where this looks for it.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dnstree=${DNSTREE:-$root/build/dnstree}
out=${1:-$root/docs/demo-3d.png}

if [ -z "${CHROME:-}" ]; then
	for c in google-chrome google-chrome-stable chromium chromium-browser \
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
		"/Applications/Chromium.app/Contents/MacOS/Chromium"; do
		if command -v "$c" >/dev/null 2>&1; then
			CHROME=$c
			break
		fi
	done
fi
if [ -z "${CHROME:-}" ]; then
	echo "no chrome or chromium found; set CHROME to its path" >&2
	exit 1
fi

tmp=$(mktemp -d)
pid=
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -rf "$tmp"' EXIT

"$dnstree" --format web-3d --no-browser --dnssec www.example.com >"$tmp/serve" 2>&1 &
pid=$!

# Piped, dnstree names the address in a plain line once the walk is done.
url=
for _ in $(seq 90); do
	url=$(sed -n 's/^the walk is at //p' "$tmp/serve")
	[ -n "$url" ] && break
	kill -0 "$pid" 2>/dev/null || break
	sleep 0.5
done
if [ -z "$url" ]; then
	cat "$tmp/serve" >&2
	echo "dnstree never said where the walk is served" >&2
	exit 1
fi

# SwiftShader draws WebGL2 without a GPU, so this works on a runner too. The
# virtual time budget runs the clock past the replay without waiting for it.
"$CHROME" --headless \
	--use-angle=swiftshader --enable-unsafe-swiftshader \
	--hide-scrollbars --window-size=1200,700 --force-device-scale-factor=2 \
	--virtual-time-budget=12000 --screenshot="$out" "$url" 2>/dev/null
echo "wrote $out"
