package fakens

import (
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Denial is how a signed zone proves something is not there: that a child has
// no DS, that a name does not exist, or that it exists with nothing of the type
// asked for. A zone signs the gaps in itself, so the shape of the gaps is what
// this file builds.
type Denial string

// The shapes a zone signs its gaps in. The zero value is what the large TLDs do.
const (
	// DenialNSEC3OptOut hashes the names and leaves the unsigned delegations
	// out of the chain, which is how com. and net. sign their gaps.
	DenialNSEC3OptOut Denial = ""

	// DenialNSEC3 hashes the names and leaves nothing out.
	DenialNSEC3 Denial = "nsec3"

	// DenialNSEC names the gaps outright, the way a small signed zone does.
	DenialNSEC Denial = "nsec"
)

// The NSEC3 parameters the fake zones sign with, the ones RFC 5155 uses in its
// own examples.
const (
	nsec3Salt       = "aabbccdd"
	nsec3Iterations = 12
	nsec3HashLength = 20 // SHA-1
)

// denial is the zone's signed word about name: that it holds nothing of the
// type asked for, or — when absent is set — that it is not in the zone at all.
// It is the authority section a real signed server would attach, built from the
// zone as it stands. Which types the name does hold is in the record itself, so
// the type asked for never comes into building it.
func (s *Server) denial(name string, absent bool) []dns.RR {
	if s.signer == nil || s.behaviour.NoDenial {
		return nil
	}
	if s.denialKind == DenialNSEC {
		return s.nsecDenial(name, absent)
	}
	return s.nsec3Denial(name, absent)
}

// nsecDenial answers with the gaps themselves. A name that is not there needs
// the gap holding it and the gap holding the wildcard that would have covered
// it; a name that is there needs only its own record.
func (s *Server) nsecDenial(name string, absent bool) []dns.RR {
	chain := s.nsecChain()
	if len(chain) == 0 {
		return nil
	}

	if !absent {
		for _, nsec := range chain {
			if dns.EqualName(nsec.Hdr.Name, name) {
				return []dns.RR{nsec}
			}
		}
		// An empty non-terminal owns no record, so the gap spanning it is what
		// says it is there.
		return pick(chain, func(nsec *dns.NSEC) bool { return nsecCovers(nsec, name) })
	}

	denial := pick(chain, func(nsec *dns.NSEC) bool { return nsecCovers(nsec, name) })
	wildcard := "*." + strings.TrimPrefix(s.origin, ".")
	for _, nsec := range chain {
		if !nsecCovers(nsec, wildcard) || slices.Contains(denial, dns.RR(nsec)) {
			continue
		}
		denial = append(denial, nsec)
	}
	return denial
}

// nsec3Denial answers with the hashes of the gaps. A name that is not there
// takes three records: the deepest ancestor that is there, the gap holding the
// name one label below it, and the gap holding the wildcard.
func (s *Server) nsec3Denial(name string, absent bool) []dns.RR {
	chain := s.nsec3Chain()
	if len(chain) == 0 {
		return nil
	}

	if !absent {
		for _, nsec3 := range chain {
			if ownerHash(nsec3.Hdr.Name) == s.hash(name) {
				return []dns.RR{nsec3}
			}
		}
		return covering(chain, s.hash(name))
	}

	// The closest encloser is the deepest ancestor of the name the chain names.
	encloser, nextCloser := s.origin, name
	for n := dnsutil.Labels(name); n > dnsutil.Labels(s.origin); n-- {
		candidate := ancestorOf(name, n)
		if slices.ContainsFunc(chain, func(r *dns.NSEC3) bool { return ownerHash(r.Hdr.Name) == s.hash(candidate) }) {
			encloser, nextCloser = candidate, ancestorOf(name, n+1)
			break
		}
		nextCloser = candidate
	}

	denial := pick(chain, func(r *dns.NSEC3) bool { return ownerHash(r.Hdr.Name) == s.hash(encloser) })
	for _, rr := range covering(chain, s.hash(nextCloser)) {
		if !slices.Contains(denial, rr) {
			denial = append(denial, rr)
		}
	}
	for _, rr := range covering(chain, s.hash("*."+strings.TrimPrefix(encloser, "."))) {
		if !slices.Contains(denial, rr) {
			denial = append(denial, rr)
		}
	}
	return denial
}

// nsecChain is the zone's names in canonical order, each pointing at the next,
// with the last closing the circle at the apex.
func (s *Server) nsecChain() []*dns.NSEC {
	names, types := s.owners(false)
	chain := make([]*dns.NSEC, 0, len(names))
	for i, name := range names {
		next := s.origin
		if i+1 < len(names) {
			next = names[i+1]
		}
		nsec := &dns.NSEC{Hdr: dns.Header{Name: name, Class: dns.ClassINET, TTL: 3600}}
		nsec.NextDomain = next
		nsec.TypeBitMap = types[name]
		chain = append(chain, nsec)
	}
	return chain
}

// nsec3Chain is the same circle drawn round the hashes instead of the names.
// An opt-out zone leaves the delegations it does not vouch for out of it, which
// is the whole point of opt-out: they cost it nothing to leave unsaid.
func (s *Server) nsec3Chain() []*dns.NSEC3 {
	optingOut := s.denialKind == DenialNSEC3OptOut
	names, types := s.owners(!optingOut)

	hashes := make([]string, 0, len(names))
	owned := map[string][]uint16{}
	for _, name := range names {
		if optingOut && s.unsignedDelegation(name) {
			continue
		}
		hash := s.hash(name)
		hashes = append(hashes, hash)
		owned[hash] = types[name]
	}
	slices.Sort(hashes)

	chain := make([]*dns.NSEC3, 0, len(hashes))
	for i, hash := range hashes {
		next := hashes[0]
		if i+1 < len(hashes) {
			next = hashes[i+1]
		}
		nsec3 := &dns.NSEC3{Hdr: dns.Header{Name: s.under(hash), Class: dns.ClassINET, TTL: 3600}}
		nsec3.Hash, nsec3.Iterations = 1, nsec3Iterations
		nsec3.Salt, nsec3.SaltLength = nsec3Salt, uint8(len(nsec3Salt)/2)
		nsec3.HashLength = nsec3HashLength
		nsec3.NextDomain = next
		nsec3.TypeBitMap = owned[hash]
		if optingOut {
			nsec3.Flags = 1
		}
		chain = append(chain, nsec3)
	}
	return chain
}

// owners is every name the zone speaks for, in canonical order, with the types
// each one holds. Glue below a delegation is somebody else's and is left out;
// empty non-terminals are named only in an NSEC3 chain, which is where RFC 5155
// asks for them.
func (s *Server) owners(withEmptyNonTerminals bool) ([]string, map[string][]uint16) {
	delegations := map[string]bool{}
	for _, rr := range s.records() {
		name := dnsutil.Canonical(rr.Header().Name)
		if dns.RRToType(rr) == dns.TypeNS && !dns.EqualName(name, s.origin) {
			delegations[name] = true
		}
	}
	occluded := func(name string) bool {
		for cut := range delegations {
			if !dns.EqualName(name, cut) && dnsutil.IsBelow(cut, name) {
				return true
			}
		}
		return false
	}

	types := map[string][]uint16{}
	for _, rr := range s.records() {
		name := dnsutil.Canonical(rr.Header().Name)
		if occluded(name) {
			continue
		}
		if rrtype := dns.RRToType(rr); !slices.Contains(types[name], rrtype) {
			types[name] = append(types[name], rrtype)
		}
	}
	// Everything the zone signs carries a signature, and every name in the
	// chain carries its own link of it.
	for name := range types {
		types[name] = append(types[name], dns.TypeRRSIG, dns.TypeNSEC)
	}

	if withEmptyNonTerminals {
		for _, name := range keysOf(types) {
			for n := dnsutil.Labels(name) - 1; n > dnsutil.Labels(s.origin); n-- {
				if ancestor := ancestorOf(name, n); types[ancestor] == nil {
					types[ancestor] = []uint16{}
				}
			}
		}
	}

	names := make([]string, 0, len(types))
	for name := range types {
		names = append(names, name)
	}
	slices.SortFunc(names, dns.CompareName)
	return names, types
}

// unsignedDelegation reports whether name is a cut this zone hands out without
// vouching for, which is what an opt-out chain may skip.
func (s *Server) unsignedDelegation(name string) bool {
	if dns.EqualName(name, s.origin) {
		return false
	}
	var isCut bool
	for _, rr := range s.records() {
		if dns.RRToType(rr) == dns.TypeNS && dns.EqualName(rr.Header().Name, name) {
			isCut = true
		}
	}
	return isCut && len(s.ds(name)) == 0
}

// hash is the NSEC3 owner hash of a name under this zone's parameters.
func (s *Server) hash(name string) string {
	return dnsutil.NSEC3Name(dnsutil.Canonical(name), nsec3Salt, nsec3Iterations)
}

// under is one label inside the zone. The root is the reason this is not a
// concatenation: its origin is already the separator.
func (s *Server) under(label string) string {
	return label + "." + strings.TrimPrefix(s.origin, ".")
}

// nsecCovers is the gap an NSEC spans, the last one wrapping to the apex.
func nsecCovers(nsec *dns.NSEC, name string) bool {
	owner, next := nsec.Hdr.Name, nsec.NextDomain
	if dns.CompareName(owner, next) >= 0 {
		return dns.CompareName(owner, name) < 0 || dns.CompareName(name, next) < 0
	}
	return dns.CompareName(owner, name) < 0 && dns.CompareName(name, next) < 0
}

// covering is the record of a hashed chain spanning one hash.
func covering(chain []*dns.NSEC3, hash string) []dns.RR {
	return pick(chain, func(nsec3 *dns.NSEC3) bool {
		from, to := ownerHash(nsec3.Hdr.Name), nsec3.NextDomain
		if from >= to {
			return hash > from || hash < to
		}
		return hash > from && hash < to
	})
}

// pick is the records of a chain that answer to want, as the section carries them.
func pick[T dns.RR](chain []T, want func(T) bool) []dns.RR {
	var chosen []dns.RR
	for _, rr := range chain {
		if want(rr) {
			chosen = append(chosen, rr)
		}
	}
	return chosen
}

// ownerHash is the hash an NSEC3 owner name carries, which is its first label.
func ownerHash(owner string) string {
	label, _, found := strings.Cut(owner, ".")
	if !found {
		return ""
	}
	return strings.ToUpper(label)
}

// ancestorOf is the last n labels of name.
func ancestorOf(name string, n int) string {
	if n <= 0 {
		return "."
	}
	labels := dnsutil.Split(dnsutil.Fqdn(name))
	if name == "." || n >= len(labels) {
		return dnsutil.Fqdn(name)
	}
	return dnsutil.Fqdn(strings.Join(labels[len(labels)-n:], "."))
}

// keysOf is the keys of m, taken before it is written to.
func keysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
