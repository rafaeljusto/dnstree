#!/usr/bin/env bash
# compare.sh BIN LIST OUT — walk every "NAME [TYPE]" line of LIST with BIN and
# hold each walk against dig: the server the walk ended at, asked again, and two
# validating resolvers. One row per question goes to OUT/results.tsv.
set -u
DIG=${DIG:-dig}
export DIG

if [ "${1:-}" = one ]; then
	shift
	BIN=$1 OUT=$2 NAME=$3 TYPE=$4
	D=$OUT/q/q_$(printf '%s_%s' "$NAME" "$TYPE" | tr -c 'A-Za-z0-9._-' '_')
	mkdir -p "$D"
	printf '%s %s\n' "$NAME" "$TYPE" > "$D/question"

	timeout 120 "$BIN" --no-asn --no-compare --color never --format json "$NAME" "$TYPE" > "$D/trace.json" 2> "$D/err"
	code=$?

	# The same reading Trace.Result and Trace.Trust make, so that a mismatch
	# here is a mismatch in the walk and not in this script.
	jq -c --arg t "$TYPE" '
		def result: if .aside then null else
			((if ((.kind | IN("answer","cname","nodata","nxdomain")) and (.minimised | not)) then . else null end) as $self
			| reduce (.children // [])[] as $c ($self; ($c | result) as $d | if $d then $d else . end)) end;
		def mainline: if .aside then empty else ., ((.children // [])[] | mainline) end;
		(.root | result) as $r
		| {kind: ($r.kind // "none"),
		   asked: ($r.asked.name // ""),
		   server: ($r.server.ip // ""),
		   compact: ($r.compact // false),
		   answers: ([($r.records // [])[] | select(.type | ascii_upcase == ($t | ascii_upcase)) | .data] | unique),
		   dnssec: (if $r.dnssec then
				(if $r.dnssec.state == "secure"
				 then ([.root | mainline | select(.kind == "cname" and (.minimised | not) and .dnssec and .dnssec.state != "secure") | .dnssec.state] | first // "secure")
				 else $r.dnssec.state end)
			else ([.root | mainline | select(.dnssec) | .dnssec.state] | last // "none") end)}
	' "$D/trace.json" > "$D/walk.json" 2>/dev/null || echo '{"kind":"unreadable","asked":"","server":"","compact":false,"answers":[],"dnssec":"none"}' > "$D/walk.json"

	# dig ASK FILE ARGS... : status, flags and the sorted rdata of TYPE.
	ask() {
		local f=$1; shift
		"$DIG" +time=3 +tries=2 +dnssec +nosplit +nocmd +nostats +noquestion +noauthority +noadditional "$@" > "$f.raw" 2>&1
		{
			sed -n 's/.*status: \([A-Z]*\).*/\1/p' "$f.raw" | head -1
			sed -n 's/^;; flags: \([a-z ]*\);.*/\1/p' "$f.raw" | head -1
			awk -v t="$(echo "$TYPE" | tr a-z A-Z)" '!/^;/ && NF >= 5 && toupper($4) == t { $1=$2=$3=$4=""; sub(/^ +/, ""); print }' "$f.raw" | sort -u
		} > "$f"
	}
	status() { sed -n 1p "$1"; }
	flags() { sed -n 2p "$1"; }
	answers() { sed -n '3,$p' "$1"; }

	kind=$(jq -r .kind "$D/walk.json")
	asked=$(jq -r .asked "$D/walk.json")
	server=$(jq -r .server "$D/walk.json")
	dnssec=$(jq -r .dnssec "$D/walk.json")
	jq -r '.answers[]' "$D/walk.json" > "$D/walk.answers"

	# Compact denial (RFC 9824) is NOERROR on the wire, and dnstree reads it as
	# the NXDOMAIN it stands for.
	case $kind in
	nxdomain) ours=NXDOMAIN; [ "$(jq -r .compact "$D/walk.json")" = true ] && ours=NOERROR ;;
	answer | cname | nodata) ours=NOERROR ;;
	*) ours=- ;;
	esac

	notes=
	class=ok

	auth=-
	if [ -n "$server" ] && [ -n "$asked" ]; then
		# A server may rotate a set, or hand out a share of it that moves on a
		# timer; ask a few times, apart, before calling a difference one.
		: > "$D/auth.seen"
		for try in 1 2 3 4 5; do
			[ $try -gt 1 ] && sleep 1
			ask "$D/auth" +norec "@$server" "$asked" "$TYPE"
			auth=$(status "$D/auth")
			[ -z "$auth" ] && auth=unreachable && break
			answers "$D/auth" | cmp -s - "$D/walk.answers" && break
			answers "$D/auth" | paste -sd ' ' - >> "$D/auth.seen"
		done
	fi
	varies=$(sort -u "$D/auth.seen" 2>/dev/null | wc -l | tr -d ' ')

	# Fully qualified, or dig reads a TLD such as ch or in as a class.
	fqdn=${NAME%.}.
	for r in 1.1.1.1 8.8.8.8; do
		ask "$D/rec-$r" "@$r" "$fqdn" "$TYPE"
		if [ "$(status "$D/rec-$r")" = SERVFAIL ]; then
			ask "$D/rec-$r-cd" +cd "@$r" "$fqdn" "$TYPE"
		fi
	done
	rec1=$(status "$D/rec-1.1.1.1") rec2=$(status "$D/rec-8.8.8.8")
	ad=0
	case " $(flags "$D/rec-1.1.1.1") " in *" ad "*) ad=$((ad + 1)) ;; esac
	case " $(flags "$D/rec-8.8.8.8") " in *" ad "*) ad=$((ad + 1)) ;; esac
	cdok=0
	for r in 1.1.1.1 8.8.8.8; do
		[ -f "$D/rec-$r-cd" ] && [ "$(status "$D/rec-$r-cd")" != SERVFAIL ] && [ -n "$(status "$D/rec-$r-cd")" ] && cdok=$((cdok + 1))
	done

	if grep -qE 'panic:|goroutine |runtime error|DATA RACE' "$D/err" || [ $code -eq 124 ] || [ $code -eq 1 ] || [ $code -gt 4 ]; then
		class=crash notes="exit $code"
	elif [ "$auth" != - ] && [ "$auth" != unreachable ] && [ "$ours" != - ] && [ "$auth" != "$ours" ]; then
		class=auth-rcode notes="walk $ours, server $auth"
	elif [ "$auth" = NOERROR ] && ! answers "$D/auth" | cmp -s - "$D/walk.answers"; then
		if answers "$D/auth" | tr A-Z a-z | cmp -s - <(tr A-Z a-z < "$D/walk.answers"); then
			class=auth-case
		elif [ "$varies" -gt 1 ]; then
			class=auth-varies notes="$varies different answers in 5 asks"
		else
			class=auth-answer
		fi
	elif [ $code -eq 2 ] && { [ "$rec1" = NOERROR ] || [ "$rec1" = NXDOMAIN ]; } && [ "$rec1" = "$rec2" ]; then
		class=no-answer notes="resolvers $rec1"
	elif [ $code -eq 3 ] && [ $cdok -eq 0 ] && [ "$rec1" != SERVFAIL ] && [ "$rec2" != SERVFAIL ]; then
		class=bogus-only-here notes="resolvers $rec1/$rec2"
	elif [ $code -ne 3 ] && [ $cdok -eq 2 ]; then
		class=bogus-missed notes="both resolvers fail validation, walk $dnssec"
	elif [ "$ours" != - ] && [ "$rec1" = "$rec2" ] && { [ "$rec1" = NOERROR ] || [ "$rec1" = NXDOMAIN ]; } && [ "$rec1" != "$ours" ]; then
		class=rec-rcode notes="walk $ours, resolvers $rec1"
	elif [ "$dnssec" = secure ] && [ $ad -eq 0 ] && [ "$rec1" = NOERROR ] && [ "$rec2" = NOERROR ]; then
		class=secure-unproven notes="neither resolver set AD"
	elif [ "$dnssec" = insecure ] && [ $ad -eq 2 ]; then
		class=secure-missed notes="both resolvers set AD"
	elif [ "$auth" = unreachable ]; then
		class=auth-unreachable notes="$server"
	elif [ "$rec1" = NOERROR ] && ! answers "$D/rec-1.1.1.1" | cmp -s - "$D/walk.answers" && ! answers "$D/rec-8.8.8.8" | cmp -s - "$D/walk.answers"; then
		class=rec-answer
	fi

	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s/%s\t%s\t%s\t%s\n' "$class" "$NAME" "$TYPE" "$code" "$kind" "$dnssec" "$auth" "$rec1" "$rec2" "$ad" "$notes" "$D" > "$D/row"
	exit 0
fi

BIN=$1 LIST=$2 OUT=$3
JOBS=${JOBS:-4}
# A dig older than 9.18 draws HTTPS, SVCB and newer types as TYPE65 and the
# like, which would read as a mismatch on every one of them.
"$DIG" -v 2>&1 | grep -qE 'DiG 9\.(1[89]|[2-9][0-9])' || echo "warning: $("$DIG" -v 2>&1) predates 9.18; newer types will not compare. Set DIG." >&2
mkdir -p "$OUT/q"
grep -vE '^[[:space:]]*(#|$)' "$LIST" | while read -r name type _; do
	printf '%s\0%s\0' "$name" "${type:-A}"
done | xargs -0 -n 2 -P "$JOBS" "$0" one "$BIN" "$OUT"

{
	printf 'class\tname\ttype\texit\tkind\tdnssec\tauth\tresolvers\tad\tnotes\tdir\n'
	cat "$OUT"/q/*/row | sort
} > "$OUT/results.tsv"
cut -f1 "$OUT/results.tsv" | tail -n +2 | sort | uniq -c | sort -rn
