//go:build live

// These tests go out to the real root servers, so they only run when asked
// for: go test -tags live ./...
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/transport"
)

// TestLive resolves a name that has been there for decades, the whole way down
// from the root, and checks that the chain of trust holds. It is the only test
// that can catch the embedded hints or anchors going stale.
func TestLive(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(t.Context(), []string{"--dnssec", "--no-asn", "--no-compare", "--color", "never", "example.com", "A"}, &stdout, &stderr)
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

// TestLiveBrokenOnPurpose checks that the name --check-resolver reads a
// resolver's validation from is still broken. Fixed, the check reads as
// unknown rather than wrong, and only this notices.
func TestLiveBrokenOnPurpose(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(t.Context(), []string{"--dnssec", "--no-asn", "--no-compare", "--color", "never", transport.BrokenName, "A"}, &stdout, &stderr)
	if code != exitBogus {
		t.Fatalf("got exit %d, want %d: %s is no longer broken\n%s%s", code, exitBogus, transport.BrokenName, stdout.String(), stderr.String())
	}
}

// TestLiveEchoes checks that the zones --check-resolver reads ECS and
// minimisation from still answer in the shape it reads. Google's resolver
// sends a subnet to its own zone and minimises, so an unknown from it means a
// zone has changed.
func TestLiveEchoes(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(t.Context(), []string{"--check-resolver", "--resolver", "8.8.8.8", "--no-asn", "--color", "never", "example.com", "A"}, &stdout, &stderr)
	if code != exitAnswer {
		t.Fatalf("got exit %d, want %d\n%s%s", code, exitAnswer, stdout.String(), stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "8.8.8.8 sends ECS (/24) to google") || !strings.Contains(out, "and minimises queries") {
		t.Errorf("got no ECS sent to %s or no minimisation from %s:\n%s", transport.GoogleEcho, transport.MinimisationEcho, out)
	}
}
