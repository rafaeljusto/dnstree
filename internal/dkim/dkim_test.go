package dkim_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/dkim"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// rsaKey is p= for an RSA key of bits, as a SubjectPublicKeyInfo, or with
// pkcs1 as the bare RSAPublicKey. A receiver only ever reads its size.
func rsaKey(t testing.TB, bits int, pkcs1 bool) string {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	public := &rsa.PublicKey{N: n, E: 65537}
	if pkcs1 {
		return base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(public))
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

var ed25519Key = base64.StdEncoding.EncodeToString(make([]byte, 32))

func TestRead(t *testing.T) {
	rsa2048 := rsaKey(t, 2048, false)
	for name, tc := range map[string]struct {
		record  string
		found   trace.PolicyFound
		state   trace.DKIMState
		keyType string
		bits    int
		testing bool
		why     string
	}{
		"a 2048 bit rsa key, every tag spelled out": {
			record: "v=DKIM1; k=rsa; h=sha256; s=email; p=" + rsa2048,
			found:  trace.PolicyPublished, state: trace.DKIMUsable, keyType: "rsa", bits: 2048,
		},
		"a key with no tags but p, which is rsa by default": {
			record: "p=" + rsa2048,
			found:  trace.PolicyPublished, state: trace.DKIMUsable, keyType: "rsa", bits: 2048,
		},
		"a bare RSAPublicKey, as the RFC's text has it": {
			record: "v=DKIM1; p=" + rsaKey(t, 2048, true),
			found:  trace.PolicyPublished, state: trace.DKIMUsable, keyType: "rsa", bits: 2048,
		},
		"a key split by whitespace, ending in a semicolon": {
			record: "v=DKIM1;\tk=rsa ;p=" + rsa2048[:40] + " \r\n " + rsa2048[40:] + ";",
			found:  trace.PolicyPublished, state: trace.DKIMUsable, keyType: "rsa", bits: 2048,
		},
		"a 1024 bit key, short of what signers are asked for": {
			record: "v=DKIM1; p=" + rsaKey(t, 1024, false),
			found:  trace.PolicyPublished, state: trace.DKIMUsable, keyType: "rsa", bits: 1024,
			why: "1024 bits, under the 2048 RFC 8301 asks signers for",
		},
		"a 512 bit key, which receivers do not verify": {
			record: "v=DKIM1; p=" + rsaKey(t, 512, false),
			found:  trace.PolicyPublished, state: trace.DKIMWeak, keyType: "rsa", bits: 512,
		},
		"a key that allows only sha1": {
			record: "v=DKIM1; h=sha1; p=" + rsa2048,
			found:  trace.PolicyPublished, state: trace.DKIMSHA1, keyType: "rsa", bits: 2048,
		},
		"a key that allows sha1 and sha256": {
			record: "v=DKIM1; h=sha1 : SHA256; p=" + rsa2048,
			found:  trace.PolicyPublished, state: trace.DKIMUsable, keyType: "rsa", bits: 2048,
		},
		"an ed25519 key": {
			record: "v=DKIM1; k=ed25519; p=" + ed25519Key,
			found:  trace.PolicyPublished, state: trace.DKIMUsable, keyType: "ed25519",
		},
		"a revoked key": {
			record: "v=DKIM1; k=rsa; p=",
			found:  trace.PolicyPublished, state: trace.DKIMRevoked, keyType: "rsa",
		},
		"a key still testing": {
			record: "v=DKIM1; t=s:y; p=" + rsa2048,
			found:  trace.PolicyPublished, state: trace.DKIMUsable, keyType: "rsa", bits: 2048, testing: true,
		},
		"a key for every service": {
			record: "v=DKIM1; s=*; p=" + rsa2048,
			found:  trace.PolicyPublished, state: trace.DKIMUsable, keyType: "rsa", bits: 2048,
		},
		"a key for something other than email": {
			record: "v=DKIM1; s=tlsrpt; p=" + rsa2048,
			found:  trace.PolicyInvalid, why: "its s= says it is not for email",
		},
		"a version that is not first": {
			record: "k=rsa; v=DKIM1; p=" + rsa2048,
			found:  trace.PolicyInvalid, why: "its v= is not DKIM1 as its first tag",
		},
		"a version that is not DKIM1": {
			record: "v=DKIM2; p=" + rsa2048,
			found:  trace.PolicyInvalid, why: "its v= is not DKIM1 as its first tag",
		},
		"no p at all": {
			record: "v=DKIM1; k=rsa",
			found:  trace.PolicyInvalid, why: "it has no p=",
		},
		"a key type receivers do not know": {
			record: "v=DKIM1; k=dsa; p=" + rsa2048,
			found:  trace.PolicyInvalid, why: "k=dsa is no key type receivers know",
		},
		"a p that is not base64": {
			record: "v=DKIM1; p=not*base64",
			found:  trace.PolicyInvalid, why: "its p= is not base64",
		},
		"a p that is base64 but no key": {
			record: "v=DKIM1; p=" + ed25519Key,
			found:  trace.PolicyInvalid, why: "its p= is no RSA key",
		},
		"an ed25519 key of the wrong length": {
			record: "v=DKIM1; k=ed25519; p=" + rsa2048,
			found:  trace.PolicyInvalid,
		},
		"a hash list with nothing receivers verify with": {
			record: "v=DKIM1; h=md5; p=" + rsa2048,
			found:  trace.PolicyInvalid, why: "its h= names no hash receivers verify with",
		},
		"a tag named twice": {
			record: "v=DKIM1; p=" + rsa2048 + "; p=",
			found:  trace.PolicyInvalid, why: "it does not parse: p= is named twice",
		},
		"two semicolons in a row": {
			record: "v=DKIM1;; p=" + rsa2048,
			found:  trace.PolicyInvalid,
		},
		"a quote pasted from a web form": {
			record: `"v=DKIM1; p=` + rsa2048 + `"`,
			found:  trace.PolicyInvalid,
		},
		"a tag name that begins with a digit": {
			record: "v=DKIM1; 1x=y; p=" + rsa2048,
			found:  trace.PolicyInvalid,
		},
		"a line break not followed by whitespace": {
			record: "v=DKIM1; p=" + rsa2048[:40] + "\r\n" + rsa2048[40:],
			found:  trace.PolicyInvalid,
		},
		"a character past ascii": {
			record: "v=DKIM1; n=café; p=" + rsa2048,
			found:  trace.PolicyInvalid,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := dkim.Read(tc.record)
			if got.Found != tc.found || got.State != tc.state || got.Type != tc.keyType || got.Bits != tc.bits || got.Testing != tc.testing {
				t.Errorf("read %s %q %s %d testing %v (%s), want %s %q %s %d testing %v",
					got.Found, got.State, got.Type, got.Bits, got.Testing, got.Why, tc.found, tc.state, tc.keyType, tc.bits, tc.testing)
			}
			if tc.why != "" && got.Why != tc.why {
				t.Errorf("why %q, want %q", got.Why, tc.why)
			}
			if got.Found == trace.PolicyInvalid && got.Why == "" {
				t.Error("invalid, without saying why")
			}
		})
	}
}

// FuzzRead reads a key record as a zone wrote it. Whatever it holds, the
// read never panics, comes to one of its results, keeps only tags the grammar
// allows, and reads the same again from the tags it kept.
func FuzzRead(f *testing.F) {
	for _, seed := range []string{
		"v=DKIM1; k=rsa; h=sha256; s=email; p=" + rsaKey(f, 1024, false),
		"v=DKIM1; k=ed25519; t=y:s; p=" + ed25519Key,
		"p=" + rsaKey(f, 512, true),
		"v=DKIM1; p=",
		"v=DKIM1; h=sha1; n=a note; p=" + rsaKey(f, 1024, false) + ";",
		"v=DKIM1;; p= \r\n x",
		"k=rsa; v=DKIM1; p=é",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, record string) {
		got := dkim.Read(record)
		switch got.Found {
		case trace.PolicyPublished:
			switch got.State {
			case trace.DKIMUsable, trace.DKIMRevoked, trace.DKIMWeak, trace.DKIMSHA1:
			default:
				t.Fatalf("published as %q, which no key comes to", got.State)
			}
			if got.Type != "rsa" && got.Type != "ed25519" {
				t.Errorf("published with key type %q", got.Type)
			}
			if got.State == trace.DKIMWeak && got.Bits >= 1024 || got.Type == "ed25519" && got.Bits != 0 {
				t.Errorf("%s %s key of %d bits", got.State, got.Type, got.Bits)
			}
		case trace.PolicyInvalid:
			if got.Why == "" || got.State != "" || got.Bits != 0 {
				t.Errorf("invalid as %q with %d bits (%q)", got.State, got.Bits, got.Why)
			}
			return
		default:
			t.Fatalf("found %q, which reading a record does not come to", got.Found)
		}

		seen := map[string]bool{}
		var rejoined []string
		for _, tag := range got.Tags {
			if seen[tag.Name] {
				t.Errorf("%s= kept twice", tag.Name)
			}
			seen[tag.Name] = true
			if strings.ContainsAny(tag.Value, ";") || strings.ContainsFunc(tag.Name+tag.Value, func(c rune) bool { return c > 0x7e }) {
				t.Errorf("kept %s=%q, which a tag cannot hold", tag.Name, tag.Value)
			}
			rejoined = append(rejoined, tag.Name+"="+tag.Value)
		}
		again := dkim.Read(strings.Join(rejoined, "; "))
		if again.Found != got.Found || again.State != got.State || again.Type != got.Type || again.Bits != got.Bits || again.Testing != got.Testing {
			t.Errorf("read again from its tags as %s %q %s %d, not %s %q %s %d",
				again.Found, again.State, again.Type, again.Bits, got.Found, got.State, got.Type, got.Bits)
		}
	})
}
