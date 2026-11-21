package resolver

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// ZoneFile is what a zone file holds, as the questions --zone-file asks of the
// zone's servers.
type ZoneFile struct {
	// Zone is the owner of the file's SOA record.
	Zone string

	// Questions are in the order the file first names them.
	Questions []FileQuestion

	// Names counts the owners asked about. Wildcards and Escaped count the
	// ones skipped: a wildcard cannot be asked as it is written, and this build
	// sends a name as it is written, so an escape would reach the wire as text.
	// Unaskable counts the sets of a type this build has no name to ask by,
	// such as the private records a signer keeps its state in.
	Names, Wildcards, Escaped, Unaskable int
}

// FileQuestion is one question to walk, with what the file says its answer is.
type FileQuestion struct {
	Name, Type string

	// Records are the file's, in the text a walk records. For an alias they
	// are the CNAME, while Type is A: asked that way, the walk follows the
	// alias and sees whether its target exists.
	Records []trace.RR
}

// unasked are the types a file holds that are no question of their own: a
// signature or a denial is the signer's, and comes with the answers it covers.
var unasked = map[uint16]bool{dns.TypeRRSIG: true, dns.TypeNSEC: true, dns.TypeNSEC3: true}

// ReadZoneFile reads a zone file in the format of RFC 1035, section 5. Origin
// is where relative names start before any $ORIGIN; it may be empty for a file
// that sets its own. Path names the file in errors. $INCLUDE is refused, so the
// run reads only the file it was given. Records out of the zone, and below a
// cut other than its NS and DS, are glue or some other zone's and are skipped.
func ReadZoneFile(r io.Reader, origin, path string) (*ZoneFile, error) {
	parser := dns.NewZoneParser(r, origin, path)
	included := false
	parser.IncludeAllowFunc = func(string, string) bool { included = true; return false }

	var all []dns.RR
	zone := ""
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		if dns.RRToType(rr) == dns.TypeSOA {
			name := dnsutil.Canonical(rr.Header().Name)
			if zone != "" && zone != name {
				return nil, fmt.Errorf("%s: two SOA records, for %s and %s, and a file holds one zone", path, zone, name)
			}
			zone = name
		}
		all = append(all, rr)
	}
	if err := parser.Err(); err != nil {
		if included {
			return nil, fmt.Errorf("%w; --zone-file reads only the file it is given, so copy what it includes into it", err)
		}
		if origin == "" {
			return nil, fmt.Errorf("%w; where the file has relative names, name the zone after --zone-file, or open the file with $ORIGIN", err)
		}
		return nil, err
	}
	if zone == "" {
		return nil, fmt.Errorf("%s: no SOA record, so it is not a zone", path)
	}

	// A cut is a name below the apex with NS records: below it the zone has
	// only glue, and at it only the delegation and its DS.
	var cuts []string
	for _, rr := range all {
		if name := dnsutil.Canonical(rr.Header().Name); dns.RRToType(rr) == dns.TypeNS && name != zone && !slices.Contains(cuts, name) {
			cuts = append(cuts, name)
		}
	}

	file := &ZoneFile{Zone: zone}
	index := map[[2]string]int{}
	owners := map[string]bool{}
	wildcards, escaped, unaskable := map[string]bool{}, map[string]bool{}, map[[2]string]bool{}
	for _, rr := range all {
		name, rrtype := dnsutil.Canonical(rr.Header().Name), dns.RRToType(rr)
		if unasked[rrtype] || !dnsutil.IsBelow(zone, name) || delegated(cuts, name, rrtype) {
			continue
		}
		switch {
		case strings.HasPrefix(name, "*."):
			wildcards[name] = true
			continue
		case strings.Contains(name, "\\"):
			escaped[name] = true
			continue
		}

		asked := dnsutil.TypeToString(rrtype)
		if Askable(name, asked) != nil {
			unaskable[[2]string{name, asked}] = true
			continue
		}
		if rrtype == dns.TypeCNAME {
			asked = "A"
		}
		key := [2]string{name, asked}
		i, ok := index[key]
		if !ok {
			i = len(file.Questions)
			index[key] = i
			file.Questions = append(file.Questions, FileQuestion{Name: rr.Header().Name, Type: asked})
		}
		file.Questions[i].Records = append(file.Questions[i].Records, records([]dns.RR{rr})...)
		owners[name] = true
	}
	file.Names, file.Wildcards, file.Escaped, file.Unaskable = len(owners), len(wildcards), len(escaped), len(unaskable)
	return file, nil
}

// delegated reports whether a record belongs to a zone delegated from this
// one. Every cut is held against it: one cut can sit below another, and its NS
// set is then the child's, not this zone's.
func delegated(cuts []string, name string, rrtype uint16) bool {
	for _, at := range cuts {
		if !dnsutil.IsBelow(at, name) || name == at && (rrtype == dns.TypeNS || rrtype == dns.TypeDS) {
			continue
		}
		return true
	}
	return false
}
