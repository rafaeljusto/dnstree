package recursive

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// claimed reads a resolver's RESINFO record and holds what it claims against
// what --check-resolver saw it do. qnamemin from a resolver seen to ask for
// the whole name is a mismatch, and so is an error it returned and did not
// list; one it lists and never returned had no reason to come up.
func claimed(answer *trace.Resolver) {
	if answer.DDR == nil || answer.DDR.Info == nil {
		return
	}
	info := answer.DDR.Info
	info.QNameMin, info.ExtErr, info.InfoURL = Claims(info.Text)
	info.Minimises, info.Unlisted = "", nil
	if info.QNameMin {
		info.Minimises = answer.Behaviour.Minimises
		if info.Minimises == "" {
			info.Minimises = trace.ObservedUnknown
		}
	}
	if info.ExtErr != nil {
		for _, code := range returned(answer) {
			if !trace.Lists(info.ExtErr, code) {
				info.Unlisted = append(info.Unlisted, code)
			}
		}
	}
}

// returned are the extended error codes the resolver answered with during
// the run, sorted and once each.
func returned(answer *trace.Resolver) []uint16 {
	var codes []uint16
	add := func(r *trace.Resolver) {
		for ; r != nil; r = r.Unchecked {
			for _, e := range r.Extended {
				codes = append(codes, e.Code)
			}
		}
	}
	add(answer)
	if b := answer.Behaviour; b != nil {
		for _, r := range []*trace.Resolver{b.Broken, b.Root, b.Missing, b.Google, b.Akamai, b.Minimisation, b.DNS64} {
			add(r)
		}
		for _, s := range b.Sentinels {
			add(s.Is)
			add(s.Not)
		}
	}
	slices.Sort(codes)
	return slices.Compact(codes)
}

// Claims reads the strings of a RESINFO record, one key or key=value each
// (RFC 9606 section 4, RFC 6763 section 6). Keys are matched without regard
// to case, only the first of a key counts (RFC 6763 section 6.4), and a key
// this build does not know or a value it cannot read is left out, as the RFC
// asks. The strings arrive escaped, so a backslash in a value is a byte that
// was not printable.
func Claims(text []string) (qnamemin bool, exterr []trace.CodeRange, infoURL string) {
	seen := map[string]bool{}
	for _, pair := range text {
		key, value, valued := strings.Cut(pair, "=")
		key = strings.ToLower(key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		switch key {
		case "qnamemin":
			qnamemin = !valued
		case "exterr":
			exterr = codeRanges(value)
		case "infourl":
			if httpsURL(value) {
				infoURL = value
			}
		}
	}
	return qnamemin, exterr, infoURL
}

// codeRanges reads a list such as 15-17,20, nil for anything else: one item
// that cannot be read makes the whole claim one that cannot be held to.
func codeRanges(value string) []trace.CodeRange {
	if value == "" {
		return nil
	}
	var ranges []trace.CodeRange
	for item := range strings.SplitSeq(value, ",") {
		from, to, ranged := strings.Cut(item, "-")
		if !ranged {
			to = from
		}
		lo, errLo := strconv.ParseUint(from, 10, 16)
		hi, errHi := strconv.ParseUint(to, 10, 16)
		if errLo != nil || errHi != nil || lo > hi {
			return nil
		}
		ranges = append(ranges, trace.CodeRange{From: uint16(lo), To: uint16(hi)})
	}
	return ranges
}

// httpsURL is an https URL with a host, in printable ASCII and nothing that
// would end it early where it is drawn. The scheme is the RFC's rule; the rest
// keeps a stranger's link from passing for something else.
func httpsURL(value string) bool {
	rest, ok := strings.CutPrefix(strings.ToLower(value), "https://")
	if !ok || rest == "" || rest[0] == '/' || len(value) > maxInfoURL {
		return false
	}
	return !strings.ContainsFunc(value, func(r rune) bool {
		return r <= ' ' || r > '~' || strings.ContainsRune(`\"<>`+"`", r)
	})
}

// maxInfoURL is the longest link drawn. A string in a TXT record holds 255
// octets, so this only bounds a trace read back with --from.
const maxInfoURL = 255
