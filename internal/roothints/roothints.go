// Package roothints provides the priming data for an iterative resolution: the
// root nameserver addresses and the DNSSEC trust anchors of the root zone.
//
// The embedded files are parsed into plain Go types, without the DNS codec, so
// that everything built on top stays cheap to test.
package roothints

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
)

//go:embed data/named.root
var embeddedHints []byte

// Server is a root nameserver as listed in a hints file.
type Server struct {
	Name  string       // FQDN, lowercase
	Addrs []netip.Addr // in file order, usually one IPv4 and one IPv6
}

// Hints is the parsed content of a named.root file.
type Hints struct {
	Servers []Server
}

var defaultHints = sync.OnceValues(func() (*Hints, error) {
	return Load(bytes.NewReader(embeddedHints))
})

// Default returns the hints embedded at build time, refreshed by
// scripts/refresh-roothints.sh.
func Default() (*Hints, error) {
	return defaultHints()
}

// LoadFile reads a hints file, as given to --root-hints.
func LoadFile(path string) (*Hints, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h, err := Load(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return h, nil
}

// Load parses a named.root file: the NS RRset of the root zone plus the address
// records of those nameservers. Anything else is ignored.
func Load(r io.Reader) (*Hints, error) {
	var (
		order []string
		seen  = make(map[string]bool)
		addrs = make(map[string][]netip.Addr)
	)

	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		owner, rrtype, rdata, err := parseRecord(scanner.Text())
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}

		switch rrtype {
		case "":
			continue
		case "NS":
			if owner != "." {
				continue
			}
			if name := fqdn(rdata[0]); !seen[name] {
				seen[name] = true
				order = append(order, name)
			}
		case "A", "AAAA":
			addr, err := netip.ParseAddr(rdata[0])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			if addr.Is4() != (rrtype == "A") {
				return nil, fmt.Errorf("line %d: %s is not a valid %s address", line, rdata[0], rrtype)
			}
			addrs[owner] = append(addrs[owner], addr)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	hints := &Hints{}
	for _, name := range order {
		// A nameserver without glue cannot be used to prime.
		if a := addrs[name]; len(a) > 0 {
			hints.Servers = append(hints.Servers, Server{Name: name, Addrs: a})
		}
	}
	if len(hints.Servers) == 0 {
		return nil, fmt.Errorf("no root nameserver with an address")
	}
	return hints, nil
}

// parseRecord splits one line of a zone file into owner, type and rdata
// fields. It returns an empty type for blank and comment-only lines.
func parseRecord(line string) (owner, rrtype string, rdata []string, err error) {
	if i := strings.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", nil, nil
	}
	if len(fields) < 4 {
		return "", "", nil, fmt.Errorf("expected at least 4 fields, got %d", len(fields))
	}

	owner, fields = fqdn(fields[0]), fields[2:] // fields[1] is the TTL
	if isClass(fields[0]) {
		fields = fields[1:]
		if len(fields) < 2 {
			return "", "", nil, fmt.Errorf("record has no rdata")
		}
	}
	return owner, strings.ToUpper(fields[0]), fields[1:], nil
}

func isClass(s string) bool {
	switch strings.ToUpper(s) {
	case "IN", "CH", "HS", "CS":
		return true
	}
	return false
}

// fqdn lowercases a name and makes sure it ends with the root label.
func fqdn(name string) string {
	name = strings.ToLower(name)
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
