package resolver

import (
	"testing"

	"codeberg.org/miekg/dns"
)

func TestMixCase(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		in, want string
	}{
		"a name in lower case":                       {in: "example.com.", want: "ExAmPlE.cOm."},
		"a name already in upper case":               {in: "EXAMPLE.COM.", want: "ExAmPlE.cOm."},
		"letters counted across labels, not in each": {in: "a.b.c.", want: "A.b.C."},
		"digits and hyphens left as they are":        {in: "2.0.192.in-addr.arpa.", want: "2.0.192.In-AdDr.ArPa."},
		"octets above ascii left as they are":        {in: "\xc3\xa9t\xc3\xa9.fr.", want: "\xc3\xa9T\xc3\xa9.fR."},
		"the root, with nothing to mix":              {in: ".", want: "."},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := mixCase(tt.in)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if !dns.EqualName(got, tt.in) {
				t.Errorf("got %q, which is not the same name as %q", got, tt.in)
			}
		})
	}
}
