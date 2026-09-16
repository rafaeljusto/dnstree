//go:build live

// These tests go out to the real root servers, so they only run when asked
// for: go test -tags live ./...
package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestLive resolves a name that has been there for decades, the whole way down
// from the root, and checks that the chain of trust holds. It is the only test
// that can catch the embedded hints or anchors going stale.
func TestLive(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(t.Context(), []string{"--dnssec", "--no-asn", "--color", "never", "example.com", "A"}, &stdout, &stderr)
	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{"a.root-servers.net.", "referral → com.", "example.com.", "[secure"} {
		if !strings.Contains(out, want) {
			t.Errorf("got no %q in the walk:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[bogus") {
		t.Errorf("got a broken chain of trust:\n%s", out)
	}
}
