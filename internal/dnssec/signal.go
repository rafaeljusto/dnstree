package dnssec

import (
	"fmt"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Signal holds what a zone asks its parent to publish, in its CDS and CDNSKEY
// records, against the DS the parent's referral carried in authority. It judges
// the request and nothing else: whether the records were signed by the zone's
// keys is the chain's to say, and a caller asks it before this.
//
// A key is named by its tag and algorithm, and where the same key is described
// with the same digest type on both sides the digests have to agree too. A
// parent that publishes a SHA-1 digest beside the SHA-256 one the zone asks for
// holds the same key, and is not a rollover waiting to happen.
func Signal(authority []dns.RR, zone string, cds, cdnskey []dns.RR) *trace.Signal {
	var (
		asked []*dns.DS
		keys  []*dns.DNSKEY
	)
	for _, rr := range cds {
		if record, ok := rr.(*dns.CDS); ok && dns.EqualName(record.Hdr.Name, zone) {
			asked = append(asked, &record.DS)
		}
	}
	for _, rr := range cdnskey {
		if record, ok := rr.(*dns.CDNSKEY); ok && dns.EqualName(record.Hdr.Name, zone) {
			keys = append(keys, &record.DNSKEY)
		}
	}
	held := dsRecords(authority, zone)

	signal := &trace.Signal{Held: tags(held, func(ds *dns.DS) uint16 { return ds.KeyTag })}
	if len(asked) == 0 && len(keys) == 0 {
		signal.State = trace.SignalNone
		return signal
	}

	// RFC 8078 spells the request for no DS with algorithm zero, alone: one
	// such record in each set, and nothing beside it. A delete in one set and a
	// key in the other is two requests, which a parent acts on neither of.
	zeroDS := func(ds *dns.DS) bool { return ds.Algorithm == 0 }
	zeroKey := func(key *dns.DNSKEY) bool { return key.Algorithm == 0 }
	if slices.ContainsFunc(asked, zeroDS) || slices.ContainsFunc(keys, zeroKey) {
		alone := len(asked) <= 1 && len(keys) <= 1
		every := !slices.ContainsFunc(asked, func(ds *dns.DS) bool { return !zeroDS(ds) }) &&
			!slices.ContainsFunc(keys, func(key *dns.DNSKEY) bool { return !zeroKey(key) })
		if !alone || !every {
			signal.State, signal.Reason = trace.SignalInconsistent, "a request to remove the DS stands beside a request for a key"
			return signal
		}
		signal.State = trace.SignalDelete
		return signal
	}

	// Every key is digested once for each digest type either side spells, so
	// what a zone publishes costs work in proportion to it and no more.
	digests := digested(keys, asked, held)

	if reason := disagree(asked, keys, digests); reason != "" {
		signal.State, signal.Reason = trace.SignalInconsistent, reason
		return signal
	}

	if len(asked) > 0 {
		signal.Requested = tags(asked, func(ds *dns.DS) uint16 { return ds.KeyTag })
	} else {
		signal.Requested = tags(keys, (*dns.DNSKEY).KeyTag)
	}

	signal.State = trace.SignalMatch
	if reason := differs(asked, keys, held, digests); reason != "" {
		signal.State, signal.Reason = trace.SignalPending, reason
	}
	return signal
}

// named is a key as a DS names it: by its tag and algorithm.
type named struct {
	tag       uint16
	algorithm uint8
}

// spelled is one digest of a key, the way a DS spells it.
type spelled struct {
	named
	digestType uint8
}

// digested is every CDNSKEY digested with every digest type the CDS or the DS
// uses, lowercase. A digest type this build cannot compute is left out, and a
// key missing from it is no evidence either way.
func digested(keys []*dns.DNSKEY, sets ...[]*dns.DS) map[spelled]map[string]bool {
	types := map[uint8]bool{}
	for _, set := range sets {
		for _, ds := range set {
			types[ds.DigestType] = true
		}
	}
	digests := map[spelled]map[string]bool{}
	for _, key := range keys {
		for digestType := range types {
			ds := key.ToDS(digestType)
			if ds == nil {
				continue
			}
			at := spelled{named{key.KeyTag(), key.Algorithm}, digestType}
			if digests[at] == nil {
				digests[at] = map[string]bool{}
			}
			digests[at][strings.ToLower(ds.Digest)] = true
		}
	}
	return digests
}

// disagree says how the CDS and the CDNSKEY describe different keys, where the
// zone publishes both. A parent that finds them at odds acts on neither.
func disagree(asked []*dns.DS, keys []*dns.DNSKEY, digests map[spelled]map[string]bool) string {
	if len(asked) == 0 || len(keys) == 0 {
		return ""
	}
	published := map[named]bool{}
	for _, key := range keys {
		published[named{key.KeyTag(), key.Algorithm}] = true
	}
	requested := map[named]bool{}
	for _, ds := range asked {
		key := named{ds.KeyTag, ds.Algorithm}
		requested[key] = true
		if !published[key] {
			return fmt.Sprintf("the CDS of key %d matches no CDNSKEY", ds.KeyTag)
		}
		// A digest type nothing here computes is taken on the tag and the
		// algorithm alone.
		if known := digests[spelled{key, ds.DigestType}]; known != nil && !known[strings.ToLower(ds.Digest)] {
			return fmt.Sprintf("the CDS of key %d matches no CDNSKEY", ds.KeyTag)
		}
	}
	for _, key := range keys {
		if !requested[named{key.KeyTag(), key.Algorithm}] {
			return fmt.Sprintf("the CDNSKEY of key %d has no CDS", key.KeyTag())
		}
	}
	return ""
}

// differs says how what the zone asks for is not what the parent holds, empty
// where it is the same set of keys.
func differs(asked []*dns.DS, keys []*dns.DNSKEY, held []*dns.DS, digests map[spelled]map[string]bool) string {
	wanted := map[named]bool{}
	asking := map[spelled]map[string]bool{}
	for _, ds := range asked {
		key := named{ds.KeyTag, ds.Algorithm}
		wanted[key] = true
		at := spelled{key, ds.DigestType}
		if asking[at] == nil {
			asking[at] = map[string]bool{}
		}
		asking[at][strings.ToLower(ds.Digest)] = true
	}
	for _, key := range keys {
		wanted[named{key.KeyTag(), key.Algorithm}] = true
	}
	holding := map[named]bool{}
	for _, ds := range held {
		holding[named{ds.KeyTag, ds.Algorithm}] = true
	}

	if len(wanted) != len(holding) || !everyIn(wanted, holding) {
		return "the zone asks for " + keyList(tagsOf(wanted)) + " and the parent holds " + keyList(tagsOf(holding))
	}

	// The same tag and algorithm on both sides is nearly always the same key,
	// and the digests settle it wherever both sides spell one out.
	for _, ds := range held {
		at := spelled{named{ds.KeyTag, ds.Algorithm}, ds.DigestType}
		digest := strings.ToLower(ds.Digest)
		for _, known := range []map[string]bool{asking[at], digests[at]} {
			if known != nil && !known[digest] {
				return fmt.Sprintf("the zone asks for another key tagged %d than the one the parent holds", ds.KeyTag)
			}
		}
	}
	return ""
}

func everyIn[K comparable](a, b map[K]bool) bool {
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func tagsOf(set map[named]bool) []uint16 {
	var out []uint16
	for key := range set {
		out = append(out, key.tag)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func tags[T any](records []T, tag func(T) uint16) []uint16 {
	var out []uint16
	for _, record := range records {
		out = append(out, tag(record))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// keyList names keys by their tags in a sentence.
func keyList(tags []uint16) string {
	if len(tags) == 0 {
		return "no key"
	}
	named := make([]string, len(tags))
	for i, tag := range tags {
		named[i] = fmt.Sprint(tag)
	}
	if len(named) == 1 {
		return "key " + named[0]
	}
	return "keys " + strings.Join(named[:len(named)-1], ", ") + " and " + named[len(named)-1]
}
