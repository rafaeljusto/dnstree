package idn_test

import (
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/idn"
)

func TestASCII(t *testing.T) {
	tests := map[string]struct {
		name    string
		want    string
		wantErr bool
	}{
		"a name already in ASCII, left as it was": {name: "WWW.Example.com.", want: "WWW.Example.com."},
		"an umlaut":                           {name: "münchen.de", want: "xn--mnchen-3ya.de"},
		"capitals folded, the final dot kept": {name: "MÜNCHEN.de.", want: "xn--mnchen-3ya.de."},
		"a script of its own in every label":  {name: "例え.テスト", want: "xn--r8jz45g.xn--zckzah"},
		"underscores beside it":               {name: "_25._tcp.bücher.example", want: "_25._tcp.xn--bcher-kva.example"},
		"a direction override":                {name: "\u202eexample.com", wantErr: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := idn.ASCII(test.name)
			if test.wantErr {
				if err == nil {
					t.Fatalf("got %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ASCII: %v", err)
			}
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}
