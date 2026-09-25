package roothints_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/roothints"
)

func TestDefaultAnchors(t *testing.T) {
	anchors, err := roothints.DefaultAnchors()
	if err != nil {
		t.Fatalf("DefaultAnchors: %v", err)
	}

	// The current KSKs: 20326 in place since 2017, 38696 published in 2024.
	valid := anchors.ValidAt(time.Now())
	got := make(map[uint16]roothints.Anchor, len(valid))
	for _, anchor := range valid {
		got[anchor.KeyTag] = anchor
	}
	for _, keyTag := range []uint16{20326, 38696} {
		anchor, ok := got[keyTag]
		if !ok {
			t.Errorf("key tag %d is missing from the valid anchors", keyTag)
			continue
		}
		if anchor.Algorithm != 8 || anchor.DigestType != 2 {
			t.Errorf("key tag %d: got algorithm %d digest type %d, want 8 and 2",
				keyTag, anchor.Algorithm, anchor.DigestType)
		}
		if len(anchor.Digest) != 32 {
			t.Errorf("key tag %d: got a %d byte SHA-256 digest, want 32", keyTag, len(anchor.Digest))
		}
	}
	if _, revoked := got[19036]; revoked {
		t.Error("key tag 19036 is retired but still reported as valid")
	}
}

func TestAnchorsValidAt(t *testing.T) {
	const anchorsXML = `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="test" source="test">
    <Zone>.</Zone>
    <KeyDigest id="retired" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
        <KeyTag>19036</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType>
        <Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
    </KeyDigest>
    <KeyDigest id="current" validFrom="2017-02-02T00:00:00+00:00">
        <KeyTag>20326</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType>
        <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
    </KeyDigest>
</TrustAnchor>`

	anchors, err := roothints.LoadAnchors(strings.NewReader(anchorsXML))
	if err != nil {
		t.Fatalf("LoadAnchors: %v", err)
	}
	if len(anchors) != 2 {
		t.Fatalf("got %d anchors, want 2", len(anchors))
	}

	tests := []struct {
		at   string
		want []uint16
	}{
		{at: "2010-01-01T00:00:00Z", want: nil},
		{at: "2011-01-01T00:00:00Z", want: []uint16{19036}},
		{at: "2018-01-01T00:00:00Z", want: []uint16{19036, 20326}},
		{at: "2019-01-11T00:00:00Z", want: []uint16{20326}}, // validUntil is exclusive
		{at: "2026-01-01T00:00:00Z", want: []uint16{20326}},
	}
	for _, test := range tests {
		t.Run(test.at, func(t *testing.T) {
			at, err := time.Parse(time.RFC3339, test.at)
			if err != nil {
				t.Fatalf("parsing %q: %v", test.at, err)
			}

			var got []uint16
			for _, anchor := range anchors.ValidAt(at) {
				got = append(got, anchor.KeyTag)
			}
			if len(got) != len(test.want) {
				t.Fatalf("got key tags %v, want %v", got, test.want)
			}
			for i := range got {
				if got[i] != test.want[i] {
					t.Fatalf("got key tags %v, want %v", got, test.want)
				}
			}
		})
	}
}

func TestLoadAnchorsPresentation(t *testing.T) {
	const anchors = `
; the same anchors a dsset file or "dig . DS" would give
.	172800	IN	DS	20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
.	172800	IN	DS	38696 8 2 683D2D0ACB8C 9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
`

	got, err := roothints.LoadAnchors(strings.NewReader(anchors))
	if err != nil {
		t.Fatalf("LoadAnchors: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d anchors, want 2", len(got))
	}

	// Presentation anchors carry no validity, so they are always usable.
	if valid := got.ValidAt(time.Time{}); len(valid) != 2 {
		t.Errorf("got %d anchors valid at the zero time, want 2", len(valid))
	}

	want := ".\tIN\tDS\t20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
	if got[0].String() != want {
		t.Errorf("got %q, want %q", got[0].String(), want)
	}
}

func TestLoadAnchorsError(t *testing.T) {
	tests := map[string]string{
		"empty":            "",
		"truncated xml":    `<TrustAnchor><Zone>.</Zone>`,
		"no key digest":    `<TrustAnchor><Zone>.</Zone></TrustAnchor>`,
		"not the root":     `<TrustAnchor><Zone>example.com</Zone><KeyDigest><KeyTag>1</KeyTag></KeyDigest></TrustAnchor>`,
		"short digest":     ".	172800	IN	DS	20326 8 2 E06D44B8",
		"odd hex digest":   ".	172800	IN	DS	20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8",
		"key tag overflow": ".	172800	IN	DS	70000 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		"wrong zone":       "example.com.	172800	IN	DS	20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		"not a ds record":  ".	3600000	IN	NS	a.root-servers.net.",
		"missing rdata":    ".	172800	IN	DS	20326 8 2",
	}

	for name, anchors := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := roothints.LoadAnchors(strings.NewReader(anchors)); err == nil {
				t.Error("got no error, want one")
			}
		})
	}
}

func TestLoadAnchorsFile(t *testing.T) {
	if _, err := roothints.LoadAnchorsFile(filepath.Join("data", "root-anchors.xml")); err != nil {
		t.Errorf("LoadAnchorsFile: %v", err)
	}
	if _, err := roothints.LoadAnchorsFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("got no error for a missing file, want one")
	}
}
