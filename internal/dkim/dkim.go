// Package dkim reads the key record a domain publishes for one DKIM selector
// (RFC 6376 3.6.1) as strictly as its grammar, and says what a receiver makes
// of the key in it (RFC 8301, RFC 8463). It never speaks the wire.
package dkim

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Read reads one key record. Found comes back published or invalid, and the
// lookup's fields are left to the caller.
func Read(record string) trace.DKIMKey {
	key := trace.DKIMKey{Record: record, Found: trace.PolicyPublished}
	tags, err := tagList(record)
	if err != nil {
		key.Found, key.Why = trace.PolicyInvalid, "it does not parse: "+err.Error()
		return key
	}
	key.Tags = tags
	if why := read(&key); why != "" {
		key.Found, key.Why, key.Type, key.Bits, key.State = trace.PolicyInvalid, why, "", 0, ""
	}
	return key
}

// read fills in the key from its tags, and says what keeps a receiver from
// reading one, empty for nothing.
func read(key *trace.DKIMKey) string {
	value := func(name string) (string, bool) {
		i := slices.IndexFunc(key.Tags, func(t trace.PolicyTag) bool { return t.Name == name })
		if i < 0 {
			return "", false
		}
		return key.Tags[i].Value, true
	}

	if v, ok := value("v"); ok && (key.Tags[0].Name != "v" || !strings.EqualFold(v, "DKIM1")) {
		return "its v= is not DKIM1 as its first tag"
	}
	if s, ok := value("s"); ok && !slices.ContainsFunc(list(s), func(service string) bool {
		return service == "*" || strings.EqualFold(service, "email")
	}) {
		return "its s= says it is not for email"
	}
	if t, ok := value("t"); ok {
		key.Testing = slices.ContainsFunc(list(t), func(flag string) bool { return strings.EqualFold(flag, "y") })
	}

	key.Type = "rsa"
	if k, ok := value("k"); ok {
		key.Type = strings.ToLower(k)
	}
	if key.Type != "rsa" && key.Type != "ed25519" {
		return "k=" + key.Type + " is no key type receivers know"
	}

	p, ok := value("p")
	if !ok {
		return "it has no p="
	}
	p = strings.Map(func(c rune) rune {
		if isSpace(byte(c)) {
			return -1
		}
		return c
	}, p)
	if p == "" {
		key.State, key.Why = trace.DKIMRevoked, "its p= is empty, which withdraws the key"
		return ""
	}
	data, err := base64.StdEncoding.Strict().DecodeString(p)
	if err != nil {
		return "its p= is not base64"
	}

	switch key.Type {
	case "rsa":
		public, why := rsaKey(data)
		if why != "" {
			return why
		}
		key.Bits = public.N.BitLen()
	case "ed25519":
		// The key itself, not wrapped the way an RSA key is (RFC 8463 4.2).
		if len(data) != ed25519.PublicKeySize {
			return fmt.Sprintf("its p= is %d bytes, not the %d of an ed25519 key", len(data), ed25519.PublicKeySize)
		}
	}

	hashes := []string{"sha1", "sha256"}
	if h, ok := value("h"); ok {
		hashes = list(h)
	}
	sha256 := slices.ContainsFunc(hashes, func(h string) bool { return strings.EqualFold(h, "sha256") })
	sha1 := slices.ContainsFunc(hashes, func(h string) bool { return strings.EqualFold(h, "sha1") })
	switch {
	case !sha256 && sha1 && key.Type == "rsa":
		key.State, key.Why = trace.DKIMSHA1, "its h= allows only sha1, which receivers do not verify (RFC 8301)"
	case !sha256:
		return "its h= names no hash receivers verify with"
	case key.Type == "rsa" && key.Bits < 1024:
		key.State, key.Why = trace.DKIMWeak, strconv.Itoa(key.Bits)+" bits, under the 1024 receivers verify (RFC 8301)"
	case key.Type == "rsa" && key.Bits < 2048:
		key.State, key.Why = trace.DKIMUsable, strconv.Itoa(key.Bits)+" bits, under the 2048 RFC 8301 asks signers for"
	default:
		key.State = trace.DKIMUsable
	}
	return ""
}

// rsaKey decodes an RSA key, which is published as a SubjectPublicKeyInfo
// (RFC 6376 erratum 3017), or now and then as the bare RSAPublicKey the RFC's
// text names.
func rsaKey(data []byte) (*rsa.PublicKey, string) {
	if parsed, err := x509.ParsePKIXPublicKey(data); err == nil {
		public, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, "its p= holds a key that is not RSA"
		}
		return public, ""
	}
	if public, err := x509.ParsePKCS1PublicKey(data); err == nil {
		return public, ""
	}
	return nil, "its p= is no RSA key"
}

// tagList splits a record into its tags (RFC 6376 3.2): a name of a letter
// then letters, digits and underscores, named once, and a value of printable
// characters but ";", with whitespace allowed around and between them.
func tagList(record string) ([]trace.PolicyTag, error) {
	var tags []trace.PolicyTag
	named := map[string]bool{}
	specs := strings.Split(record, ";")
	// A list may end in one ";".
	if last := specs[len(specs)-1]; len(specs) > 1 && fws(last) {
		specs = specs[:len(specs)-1]
	}
	for _, spec := range specs {
		name, value, ok := strings.Cut(spec, "=")
		if !ok {
			return nil, fmt.Errorf("%q is no tag=value", trim(spec))
		}
		name, value = trim(name), trim(value)
		if !tagName(name) {
			return nil, fmt.Errorf("%q is no tag name", name)
		}
		if !spaced(spec) || !tagValue(value) {
			return nil, fmt.Errorf("the value of %s= has a character a tag cannot hold", name)
		}
		if named[name] {
			return nil, fmt.Errorf("%s= is named twice", name)
		}
		named[name] = true
		tags = append(tags, trace.PolicyTag{Name: name, Value: value})
	}
	return tags, nil
}

func tagName(name string) bool {
	if name == "" || !isAlpha(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if c := name[i]; !isAlpha(c) && !isDigit(c) && c != '_' {
			return false
		}
	}
	return true
}

// tagValue reports whether value is printable characters but ";".
func tagValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if c := value[i]; (c < 0x21 || c > 0x7e) && !isSpace(c) {
			return false
		}
	}
	return true
}

// spaced reports whether every run of whitespace in s is folding whitespace.
func spaced(s string) bool {
	for i := 0; i < len(s); {
		if !isSpace(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isSpace(s[j]) {
			j++
		}
		if !fws(s[i:j]) {
			return false
		}
		i = j
	}
	return true
}

// fws reports whether s is whitespace only: spaces, tabs, and line breaks
// each followed by one of them (RFC 5322 3.2.2).
func fws(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t':
		case '\r':
			if i+2 >= len(s) || s[i+1] != '\n' || s[i+2] != ' ' && s[i+2] != '\t' {
				return false
			}
			i++
		default:
			return false
		}
	}
	return true
}

func trim(s string) string {
	return strings.TrimFunc(s, func(c rune) bool { return c < 0x80 && isSpace(byte(c)) })
}

// list splits a value of colon-separated items, as h=, s= and t= are.
func list(value string) []string {
	var items []string
	for item := range strings.SplitSeq(value, ":") {
		items = append(items, trim(item))
	}
	return items
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
