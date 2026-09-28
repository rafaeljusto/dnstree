package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunRefusesAFlagItDoesNotKnow(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(t.Context(), []string{"-format", "tree"}, &stderr); code != 1 {
		t.Errorf("got exit code %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "-format") {
		t.Errorf("got %q, want the flag named", stderr.String())
	}
}

func TestRunRefusesAnAddressItCannotListenOn(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(t.Context(), []string{"-addr", "256.0.0.1:0"}, &stderr); code != 1 {
		t.Errorf("got exit code %d, want 1: %s", code, stderr.String())
	}
}
