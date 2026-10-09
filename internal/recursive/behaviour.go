package recursive

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Behave reads what each resolver --check-resolver asked was seen to do. It
// says Unknown wherever the answers could mean two things: a test zone run by
// somebody else can change, and a resolver is not the only thing between here
// and the authoritative servers.
func Behave(tr *trace.Trace) {
	if tr == nil {
		return
	}
	for _, answer := range tr.Resolvers {
		if answer == nil || answer.Behaviour == nil {
			continue
		}
		answer.Behaviour.Validates = validates(answer.Behaviour)
		answer.Behaviour.Rewrites = rewrites(answer.Behaviour)
		answer.Behaviour.Subnet, answer.Behaviour.Echoes = subnet(answer.Behaviour)
		answer.Behaviour.Minimises = minimises(answer.Behaviour.Minimisation)
	}
}

// validates is whether the resolver refused the broken name. One that fails
// it, and answers once told not to check, failed its validation. One that
// answers it outright does not validate, unless the root's SOA came back
// authentic: then the test zone is likelier to have been fixed than the
// resolver to be validating everything but it.
func validates(b *trace.Behaviour) trace.Observed {
	broken, root := b.Broken, b.Root
	switch {
	case broken == nil || broken.Err != "":
		return trace.ObservedUnknown
	case broken.Rcode == "SERVFAIL":
		if again := broken.Unchecked; again != nil && again.Err == "" && again.Rcode == "NOERROR" {
			return trace.ObservedYes
		}
		if slices.ContainsFunc(broken.Extended, trace.ExtendedError.Validation) {
			return trace.ObservedYes
		}
	case broken.Rcode == "NOERROR" && len(trace.Answers(broken.Records, "A")) > 0 && !broken.Authentic &&
		root != nil && root.Err == "" && root.Rcode == "NOERROR" && !root.Authentic:
		return trace.ObservedNo
	}
	return trace.ObservedUnknown
}

// rewrites is whether a name that cannot exist came back with addresses.
func rewrites(b *trace.Behaviour) trace.Observed {
	missing := b.Missing
	switch {
	case missing == nil || missing.Err != "":
		return trace.ObservedUnknown
	case missing.Rcode == "NXDOMAIN":
		return trace.ObservedNo
	case missing.Rcode == "NOERROR" && len(trace.Answers(missing.Records, "A")) > 0:
		return trace.ObservedYes
	}
	return trace.ObservedUnknown
}

// subnet is whether either echo was sent a client subnet. Each counts only
// where it answered in the shape its operator writes, the resolver's own
// address included: an answer without that is no evidence of an absence.
func subnet(b *trace.Behaviour) (trace.Observed, []trace.Echo) {
	var echoes []trace.Echo
	for _, echo := range []trace.Echo{googleEcho(b.Google), akamaiEcho(b.Akamai)} {
		if echo.Sent != trace.ObservedUnknown {
			echoes = append(echoes, echo)
		}
	}
	switch {
	case slices.ContainsFunc(echoes, func(e trace.Echo) bool { return e.Sent == trace.ObservedYes }):
		return trace.ObservedYes, echoes
	case len(echoes) > 0:
		return trace.ObservedNo, echoes
	}
	return trace.ObservedUnknown, nil
}

// googleEcho reads Google's answer: one string with the address the question
// came from, and another, "edns0-client-subnet <prefix>", where a subnet did.
// A string of any other shape leaves it unknown, so that a zone that changes
// what it writes cannot pass for one that saw no subnet.
func googleEcho(answer *trace.Resolver) trace.Echo {
	echo := trace.Echo{Operator: "google", Sent: trace.ObservedUnknown}
	var source, sent bool
	for _, record := range echoRecords(answer) {
		texts := txtStrings(record)
		if len(texts) != 1 {
			return echo
		}
		if prefix, ok := strings.CutPrefix(texts[0], "edns0-client-subnet "); ok {
			if echo.Bits, ok = prefixBits(prefix); !ok {
				return echo
			}
			sent = true
			continue
		}
		if _, err := netip.ParseAddr(texts[0]); err != nil {
			return echo
		}
		source = true
	}
	return read(echo, source, sent)
}

// akamaiEcho reads Akamai's answer: pairs of strings, "ns" with the address
// the question came from, "ip" with the client's as the server reckons it,
// and "ecs" with "<prefix>/<scope>" where a subnet came. Anything else leaves
// it unknown, as for Google.
func akamaiEcho(answer *trace.Resolver) trace.Echo {
	echo := trace.Echo{Operator: "akamai", Sent: trace.ObservedUnknown}
	var source, sent bool
	for _, record := range echoRecords(answer) {
		texts := txtStrings(record)
		if len(texts) != 2 {
			return echo
		}
		switch texts[0] {
		case "ecs":
			parts := strings.Split(texts[1], "/")
			if len(parts) != 3 {
				return echo
			}
			var ok bool
			if echo.Bits, ok = prefixBits(parts[0] + "/" + parts[1]); !ok {
				return echo
			}
			sent = true
		case "ns", "ip":
			if _, err := netip.ParseAddr(texts[1]); err != nil {
				return echo
			}
			source = source || texts[0] == "ns"
		default:
			return echo
		}
	}
	return read(echo, source, sent)
}

// read settles an echo once every string in its answer was understood. A
// /0 carries no address at all: it is how a resolver asks not to be given an
// answer for a subnet (RFC 7871 section 7.1.2), so it counts as none sent.
func read(echo trace.Echo, source, sent bool) trace.Echo {
	switch {
	case sent && echo.Bits > 0:
		echo.Sent = trace.ObservedYes
	case sent || source:
		echo.Sent, echo.Bits = trace.ObservedNo, 0
	}
	return echo
}

// minimises reads internet.nl's verdict, which the zone writes in words.
func minimises(answer *trace.Resolver) trace.Observed {
	for _, record := range echoRecords(answer) {
		for _, text := range txtStrings(record) {
			switch {
			case strings.HasPrefix(text, "HOORAY"):
				return trace.ObservedYes
			case strings.HasPrefix(text, "NO "):
				return trace.ObservedNo
			}
		}
	}
	return trace.ObservedUnknown
}

func echoRecords(answer *trace.Resolver) []string {
	if answer == nil || answer.Err != "" || answer.Rcode != "NOERROR" {
		return nil
	}
	return trace.Answers(answer.Records, "TXT")
}

func prefixBits(text string) (int, bool) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		return 0, false
	}
	return prefix.Bits(), true
}

// txtStrings splits a TXT record, as the codec writes it out, back into its
// strings, undoing the escapes. Anything outside the quotes is not part of
// one.
func txtStrings(data string) []string {
	var (
		texts  []string
		b      strings.Builder
		quoted bool
	)
	for i := 0; i < len(data); i++ {
		ch := data[i]
		switch {
		case ch == '"':
			if quoted {
				texts = append(texts, b.String())
				b.Reset()
			}
			quoted = !quoted
		case !quoted:
		case ch == '\\' && i+3 < len(data) && decimal(data[i+1:i+4]):
			n, _ := strconv.ParseUint(data[i+1:i+4], 10, 8)
			b.WriteByte(byte(n))
			i += 3
		case ch == '\\' && i+1 < len(data):
			b.WriteByte(data[i+1])
			i++
		default:
			b.WriteByte(ch)
		}
	}
	return texts
}

// decimal is whether text is the three digits of a \DDD escape. Past 255 it
// is none, and the backslash quotes only the first digit.
func decimal(text string) bool {
	_, err := strconv.ParseUint(text, 10, 8)
	return err == nil
}
