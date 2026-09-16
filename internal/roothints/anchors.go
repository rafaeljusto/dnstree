package roothints

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed data/root-anchors.xml
var embeddedAnchors []byte

// Anchor is a DS record of the root zone used to start the DNSSEC chain.
type Anchor struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte

	// Validity as published by IANA. Zero means unbounded.
	ValidFrom  time.Time
	ValidUntil time.Time
}

// String renders the anchor in DS presentation format.
func (a Anchor) String() string {
	return fmt.Sprintf(".\tIN\tDS\t%d %d %d %s",
		a.KeyTag, a.Algorithm, a.DigestType, strings.ToUpper(hex.EncodeToString(a.Digest)))
}

// Anchors is a set of root DS records, retired ones included.
type Anchors []Anchor

// ValidAt drops the anchors that are not published as usable at t.
func (a Anchors) ValidAt(t time.Time) Anchors {
	var valid Anchors
	for _, anchor := range a {
		if !anchor.ValidFrom.IsZero() && t.Before(anchor.ValidFrom) {
			continue
		}
		if !anchor.ValidUntil.IsZero() && !t.Before(anchor.ValidUntil) {
			continue
		}
		valid = append(valid, anchor)
	}
	return valid
}

var defaultAnchors = sync.OnceValues(func() (Anchors, error) {
	return LoadAnchors(bytes.NewReader(embeddedAnchors))
})

// DefaultAnchors returns the anchors embedded at build time, refreshed by
// scripts/refresh-roothints.sh. Callers filter with ValidAt.
func DefaultAnchors() (Anchors, error) {
	return defaultAnchors()
}

// LoadAnchorsFile reads an anchors file, as given to --trust-anchors.
func LoadAnchorsFile(path string) (Anchors, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	a, err := LoadAnchors(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return a, nil
}

// LoadAnchors parses either the IANA root-anchors.xml or a file of DS records
// in presentation format.
func LoadAnchors(r io.Reader) (Anchors, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "<") {
		return parseAnchorsXML(data)
	}
	return parseAnchorsDS(string(data))
}

type xmlTrustAnchor struct {
	XMLName    xml.Name `xml:"TrustAnchor"`
	Zone       string   `xml:"Zone"`
	KeyDigests []struct {
		ValidFrom  string `xml:"validFrom,attr"`
		ValidUntil string `xml:"validUntil,attr"`
		KeyTag     uint16 `xml:"KeyTag"`
		Algorithm  uint8  `xml:"Algorithm"`
		DigestType uint8  `xml:"DigestType"`
		Digest     string `xml:"Digest"`
	} `xml:"KeyDigest"`
}

func parseAnchorsXML(data []byte) (Anchors, error) {
	var doc xmlTrustAnchor
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if zone := fqdn(doc.Zone); zone != "." {
		return nil, fmt.Errorf("trust anchors are for zone %q, only the root is supported", zone)
	}

	var anchors Anchors
	for _, kd := range doc.KeyDigests {
		anchor := Anchor{KeyTag: kd.KeyTag, Algorithm: kd.Algorithm, DigestType: kd.DigestType}

		var err error
		if anchor.Digest, err = parseDigest(kd.Digest, kd.DigestType); err != nil {
			return nil, fmt.Errorf("key tag %d: %w", kd.KeyTag, err)
		}
		if anchor.ValidFrom, err = parseTime(kd.ValidFrom); err != nil {
			return nil, fmt.Errorf("key tag %d: validFrom: %w", kd.KeyTag, err)
		}
		if anchor.ValidUntil, err = parseTime(kd.ValidUntil); err != nil {
			return nil, fmt.Errorf("key tag %d: validUntil: %w", kd.KeyTag, err)
		}
		anchors = append(anchors, anchor)
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("no key digest found")
	}
	return anchors, nil
}

func parseAnchorsDS(text string) (Anchors, error) {
	var anchors Anchors
	for line, s := range strings.Split(text, "\n") {
		owner, rrtype, rdata, err := parseRecord(s)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line+1, err)
		}
		if rrtype == "" {
			continue
		}
		if rrtype != "DS" {
			return nil, fmt.Errorf("line %d: expected a DS record, got %s", line+1, rrtype)
		}
		if owner != "." {
			return nil, fmt.Errorf("line %d: DS is for zone %q, only the root is supported", line+1, owner)
		}

		anchor, err := parseDS(rdata)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line+1, err)
		}
		anchors = append(anchors, anchor)
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("no DS record found")
	}
	return anchors, nil
}

// parseDS reads the rdata fields of a DS record: key tag, algorithm, digest
// type and digest, the last possibly split over several fields.
func parseDS(fields []string) (Anchor, error) {
	if len(fields) < 4 {
		return Anchor{}, fmt.Errorf("expected 4 DS fields, got %d", len(fields))
	}

	keyTag, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return Anchor{}, fmt.Errorf("key tag: %w", err)
	}
	algorithm, err := strconv.ParseUint(fields[1], 10, 8)
	if err != nil {
		return Anchor{}, fmt.Errorf("algorithm: %w", err)
	}
	digestType, err := strconv.ParseUint(fields[2], 10, 8)
	if err != nil {
		return Anchor{}, fmt.Errorf("digest type: %w", err)
	}
	digest, err := parseDigest(strings.Join(fields[3:], ""), uint8(digestType))
	if err != nil {
		return Anchor{}, err
	}
	return Anchor{
		KeyTag:     uint16(keyTag),
		Algorithm:  uint8(algorithm),
		DigestType: uint8(digestType),
		Digest:     digest,
	}, nil
}

// digestLength is the expected size of each DS digest type (RFC 4034, 4509, 6605).
var digestLength = map[uint8]int{1: 20, 2: 32, 4: 48}

func parseDigest(s string, digestType uint8) ([]byte, error) {
	digest, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, fmt.Errorf("digest: %w", err)
	}
	if want, known := digestLength[digestType]; known && len(digest) != want {
		return nil, fmt.Errorf("digest type %d needs %d bytes, got %d", digestType, want, len(digest))
	}
	if len(digest) == 0 {
		return nil, fmt.Errorf("empty digest")
	}
	return digest, nil
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}
