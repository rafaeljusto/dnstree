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
		answer.Behaviour.Subnet, answer.Behaviour.Echoes, answer.Behaviour.Sources = subnet(answer.Behaviour)
		answer.Behaviour.Minimises = minimises(answer.Behaviour.Minimisation)
		answer.Behaviour.Synthesises, answer.Behaviour.Prefixes = synthesises(answer.Behaviour.DNS64)
	}
}

// Located reads whether each resolver's questions reached the echoes from
// outside the AS of its own address. It runs after the origin AS lookups, and
// only judges a resolver public says is on the internet: one at a private
// address is expected to pass its questions on through somebody else.
func Located(tr *trace.Trace, public func(netip.Addr) bool) {
	if tr == nil {
		return
	}
	for _, answer := range tr.Resolvers {
		if answer == nil || answer.Behaviour == nil || len(answer.Behaviour.Sources) == 0 ||
			!public(answer.Server.IP) {
			continue
		}
		answer.Behaviour.Elsewhere = elsewhere(answer.Server.ASN, answer.Behaviour.Sources)
	}
}

// elsewhere is no where any source shares the resolver's AS, and yes only
// where every source's AS is known and none does: a source the lookups found
// nothing for may be the one inside.
func elsewhere(own *trace.ASNInfo, sources []trace.Server) trace.Observed {
	if own == nil {
		return trace.ObservedUnknown
	}
	if slices.ContainsFunc(sources, func(s trace.Server) bool { return s.ASN != nil && s.ASN.Number == own.Number }) {
		return trace.ObservedNo
	}
	if slices.ContainsFunc(sources, func(s trace.Server) bool { return s.ASN == nil }) {
		return trace.ObservedUnknown
	}
	return trace.ObservedYes
}

// wellKnown are the addresses of ipv4only.arpa. (RFC 7050): where
// one of them sits in a made-up AAAA is where the prefix ends.
var wellKnown = []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 0, 170}), netip.AddrFrom4([4]byte{192, 0, 0, 171})}

// synthesises is whether the resolver made up an AAAA for a name that has
// none, and the prefixes it made them under. An AAAA that carries neither
// known address at any length RFC 6052 allows is still made up, but names no
// prefix: guessing one would pass a real address off as synthesised.
func synthesises(answer *trace.Resolver) (trace.Observed, []netip.Prefix) {
	if answer == nil || answer.Err != "" || answer.Rcode != "NOERROR" {
		return trace.ObservedUnknown, nil
	}
	made := trace.Answers(answer.Records, "AAAA")
	if len(made) == 0 {
		return trace.ObservedNo, nil
	}
	var prefixes []netip.Prefix
	for _, data := range made {
		addr, err := netip.ParseAddr(data)
		if err != nil {
			continue
		}
		for _, bits := range trace.DNS64Lengths {
			if inside, ok := trace.Embedded(addr, bits); ok && slices.Contains(wellKnown, inside) {
				if prefix := netip.PrefixFrom(addr, bits).Masked(); !slices.Contains(prefixes, prefix) {
					prefixes = append(prefixes, prefix)
				}
				break
			}
		}
	}
	return trace.ObservedYes, prefixes
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

// maxSources bounds the addresses kept from the echoes, each an AS lookup:
// they name one each, and whatever answers in a resolver's place can name
// as many as fit in a datagram.
const maxSources = 4

// subnet is whether either echo was sent a client subnet, and the addresses
// the questions came from. Each counts only where it answered in the shape its
// operator writes, the resolver's own address included: an answer without
// that is no evidence of an absence.
func subnet(b *trace.Behaviour) (trace.Observed, []trace.Echo, []trace.Server) {
	var (
		echoes  []trace.Echo
		sources []trace.Server
	)
	google, fromGoogle := googleEcho(b.Google)
	akamai, fromAkamai := akamaiEcho(b.Akamai)
	for _, seen := range []struct {
		echo trace.Echo
		from []netip.Addr
	}{{google, fromGoogle}, {akamai, fromAkamai}} {
		if seen.echo.Sent == trace.ObservedUnknown {
			continue
		}
		echoes = append(echoes, seen.echo)
		for _, addr := range seen.from {
			if len(sources) < maxSources && !slices.ContainsFunc(sources, func(s trace.Server) bool { return s.IP == addr }) {
				sources = append(sources, trace.Server{IP: addr})
			}
		}
	}
	switch {
	case slices.ContainsFunc(echoes, func(e trace.Echo) bool { return e.Sent == trace.ObservedYes }):
		return trace.ObservedYes, echoes, sources
	case len(echoes) > 0:
		return trace.ObservedNo, echoes, sources
	}
	return trace.ObservedUnknown, nil, nil
}

// googleEcho reads Google's answer: one string with the address the question
// came from, and another, "edns0-client-subnet <prefix>", where a subnet did.
// A string of any other shape leaves it unknown, so that a zone that changes
// what it writes cannot pass for one that saw no subnet.
func googleEcho(answer *trace.Resolver) (trace.Echo, []netip.Addr) {
	echo := trace.Echo{Operator: "google", Sent: trace.ObservedUnknown}
	var (
		sources []netip.Addr
		sent    bool
	)
	for _, record := range echoRecords(answer) {
		texts := txtStrings(record)
		if len(texts) != 1 {
			return echo, nil
		}
		if prefix, ok := strings.CutPrefix(texts[0], "edns0-client-subnet "); ok {
			if echo.Bits, ok = prefixBits(prefix); !ok {
				return echo, nil
			}
			sent = true
			continue
		}
		addr, err := netip.ParseAddr(texts[0])
		if err != nil {
			return echo, nil
		}
		sources = append(sources, addr.Unmap())
	}
	return read(echo, sources, sent)
}

// akamaiEcho reads Akamai's answer: pairs of strings, "ns" with the address
// the question came from, "ip" with the client's as the server reckons it,
// and "ecs" with "<prefix>/<scope>" where a subnet came. Anything else leaves
// it unknown, as for Google.
func akamaiEcho(answer *trace.Resolver) (trace.Echo, []netip.Addr) {
	echo := trace.Echo{Operator: "akamai", Sent: trace.ObservedUnknown}
	var (
		sources []netip.Addr
		sent    bool
	)
	for _, record := range echoRecords(answer) {
		texts := txtStrings(record)
		if len(texts) != 2 {
			return echo, nil
		}
		switch texts[0] {
		case "ecs":
			parts := strings.Split(texts[1], "/")
			if len(parts) != 3 {
				return echo, nil
			}
			var ok bool
			if echo.Bits, ok = prefixBits(parts[0] + "/" + parts[1]); !ok {
				return echo, nil
			}
			sent = true
		case "ns", "ip":
			addr, err := netip.ParseAddr(texts[1])
			if err != nil {
				return echo, nil
			}
			// "ip" is the client, which is nobody's business here.
			if texts[0] == "ns" {
				sources = append(sources, addr.Unmap())
			}
		default:
			return echo, nil
		}
	}
	return read(echo, sources, sent)
}

// read settles an echo once every string in its answer was understood. A
// /0 carries no address at all: it is how a resolver asks not to be given an
// answer for a subnet (RFC 7871 section 7.1.2), so it counts as none sent.
func read(echo trace.Echo, sources []netip.Addr, sent bool) (trace.Echo, []netip.Addr) {
	switch {
	case sent && echo.Bits > 0:
		echo.Sent = trace.ObservedYes
	case sent || len(sources) > 0:
		echo.Sent, echo.Bits = trace.ObservedNo, 0
	}
	return echo, sources
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
