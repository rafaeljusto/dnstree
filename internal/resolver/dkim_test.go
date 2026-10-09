package resolver_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakens"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// dkimRecord is the TXT rdata of a key record whose RSA key is bits long, in
// the strings of at most 255 octets a zone file has to split it into.
func dkimRecord(tb testing.TB, tags string, bits int) string {
	tb.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n.Add(n, big.NewInt(1)), E: 65537})
	if err != nil {
		tb.Fatal(err)
	}
	record := tags + "p=" + base64.StdEncoding.EncodeToString(der)
	var quoted []string
	for chunk := range slices.Chunk([]byte(record), 255) {
		quoted = append(quoted, `"`+string(chunk)+`"`)
	}
	return strings.Join(quoted, " ")
}

func TestMailDKIM(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		extra    string
		selector string

		found   trace.PolicyFound
		state   trace.DKIMState
		bits    int
		testing bool
		alias   string
		warning string // a part of a warning that has to be there, empty for none
	}{
		"a 2048 bit key is usable": {
			extra:    `google._domainkey IN TXT ` + dkimRecord(t, "v=DKIM1; k=rsa; ", 2048),
			selector: "google", found: trace.PolicyPublished, state: trace.DKIMUsable, bits: 2048,
		},
		"a key at an alias is read where the alias leads": {
			extra: `s2._domainkey IN CNAME keys
keys IN TXT ` + dkimRecord(t, "v=DKIM1; t=y; ", 1024),
			selector: "s2", found: trace.PolicyPublished, state: trace.DKIMUsable, bits: 1024, testing: true,
			alias: "keys.example.com.",
		},
		"a revoked key is said without a warning": {
			extra:    `old._domainkey IN TXT "v=DKIM1; k=rsa; p="`,
			selector: "old", found: trace.PolicyPublished, state: trace.DKIMRevoked,
		},
		"a 512 bit key is one receivers do not verify": {
			extra:    `s512._domainkey IN TXT ` + dkimRecord(t, "v=DKIM1; ", 512),
			selector: "s512", found: trace.PolicyPublished, state: trace.DKIMWeak, bits: 512,
			warning: "512 bits, under the 1024 receivers verify",
		},
		"a key that allows only sha1 is one receivers do not verify": {
			extra:    `sha._domainkey IN TXT ` + dkimRecord(t, "v=DKIM1; h=sha1; ", 2048),
			selector: "sha", found: trace.PolicyPublished, state: trace.DKIMSHA1, bits: 2048,
			warning: "allows only sha1",
		},
		"a key record pasted with its quotes is invalid": {
			extra:    `bad._domainkey IN TXT ` + strings.ReplaceAll(dkimRecord(t, `"v=DKIM1; `, 2048), `""`, `"\"`),
			selector: "bad", found: trace.PolicyInvalid, warning: "the DKIM key at bad._domainkey.example.com. is no key",
		},
		"two key records at one selector are invalid": {
			extra: `two._domainkey IN TXT "v=DKIM1; p="
two._domainkey IN TXT ` + dkimRecord(t, "v=DKIM1; ", 2048),
			selector: "two", found: trace.PolicyInvalid, warning: "2 TXT records",
		},
		"a selector with no key is missing": {
			selector: "nothere", found: trace.PolicyNone,
			warning: "there is no DKIM key at nothere._domainkey.example.com.",
		},
		"an alias to a provider that dropped the key is missing": {
			extra:    `s1._domainkey IN CNAME s1.gone.plain.com.`,
			selector: "s1", found: trace.PolicyNone, alias: "s1.gone.plain.com.",
			warning: "it is an alias for s1.gone.plain.com., which holds no key",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h, cfg := mailed(t, `@ IN MX 10 mx
`+tt.extra, fakens.Behaviour{}, false)
			cfg.DKIM = []string{tt.selector}

			tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "example.com", "A")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if len(tr.Mail.DKIM) != 1 {
				t.Fatalf("got %d DKIM keys, want 1", len(tr.Mail.DKIM))
			}
			key := tr.Mail.DKIM[0]
			if key.Selector != tt.selector || key.Name != tt.selector+"._domainkey.example.com." {
				t.Errorf("got selector %s at %s", key.Selector, key.Name)
			}
			if key.Found != tt.found || key.State != tt.state || key.Bits != tt.bits || key.Testing != tt.testing {
				t.Errorf("got %s %q %d bits testing %v (%s), want %s %q %d bits testing %v",
					key.Found, key.State, key.Bits, key.Testing, key.Why, tt.found, tt.state, tt.bits, tt.testing)
			}
			if key.Lookup.Alias != tt.alias {
				t.Errorf("got alias %q, want %q", key.Lookup.Alias, tt.alias)
			}
			dkimWarnings := slices.DeleteFunc(slices.Clone(tr.Warnings), func(w string) bool { return !strings.Contains(w, "DKIM") })
			switch {
			case tt.warning == "" && len(dkimWarnings) > 0:
				t.Errorf("got warnings %q, want none about DKIM", dkimWarnings)
			case tt.warning != "" && !slices.ContainsFunc(dkimWarnings, func(w string) bool { return strings.Contains(w, tt.warning) }):
				t.Errorf("got warnings %q, want one saying %q", dkimWarnings, tt.warning)
			}
			if concern := tr.About[strings.Join(dkimWarnings, "")]; tt.warning != "" && concern.Area != trace.AreaMail {
				t.Errorf("got the warning about %q, want it about mail", concern.Area)
			}
		})
	}
}

// TestMailDKIMBogus covers a key in a zone whose signatures do not validate,
// which a receiver that validates cannot have.
func TestMailDKIMBogus(t *testing.T) {
	t.Parallel()

	h, cfg := mailed(t, `@ IN MX 10 mx
s1._domainkey IN CNAME s1.mailhost.com.`, fakens.Behaviour{BadSignature: true}, true)
	cfg.DKIM = []string{"s1"}

	tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "example.com", "A")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	key := tr.Mail.DKIM[0]
	if key.Found != trace.PolicyFailed || !strings.Contains(key.Why, "does not validate") {
		t.Errorf("got %s (%s), want it failed for not validating", key.Found, key.Why)
	}
	if !slices.ContainsFunc(tr.Warnings, func(w string) bool {
		return strings.Contains(w, "the DKIM key at s1._domainkey.example.com. does not validate")
	}) {
		t.Errorf("got warnings %q, want one saying the key does not validate", tr.Warnings)
	}
}

// TestMailDKIMBudget covers selectors the budget runs out before: they are
// left unasked, which is no failure of the zone's.
func TestMailDKIMBudget(t *testing.T) {
	t.Parallel()

	for budget := 4; budget <= 16; budget++ {
		h, cfg := mailed(t, `@ IN MX 10 mx`, fakens.Behaviour{}, false)
		cfg.DKIM, cfg.Budget.MaxQueries = []string{"a", "b", "c"}, budget

		tr, err := newResolver(t, h, cfg).Resolve(t.Context(), "example.com", "A")
		if err != nil {
			t.Fatalf("budget %d: Resolve: %v", budget, err)
		}
		if tr.Mail == nil {
			continue
		}
		for _, key := range tr.Mail.DKIM {
			if key.Found == trace.PolicyFailed && !strings.Contains(key.Why, "budget") {
				t.Errorf("budget %d: got %s failed (%s), want only the budget to stop it", budget, key.Selector, key.Why)
			}
		}
		if slices.ContainsFunc(tr.Warnings, func(w string) bool {
			return strings.Contains(w, "DKIM") && strings.Contains(w, "fails") && strings.Contains(w, "budget")
		}) {
			t.Errorf("budget %d: got warnings %q, want none blaming the zone for the budget", budget, tr.Warnings)
		}
	}
}
