package resolver

import (
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

func TestDenial(t *testing.T) {
	t.Parallel()

	const qname = "dnstree-listing.example.com."
	for name, tt := range map[string]struct {
		authority []string
		want      trace.Denial
	}{
		"real neighbours on either side of the name": {
			authority: []string{
				"api.example.com. 3600 IN NSEC www.example.com. A RRSIG NSEC",
				"example.com. 3600 IN NSEC api.example.com. SOA NS RRSIG NSEC DNSKEY",
			},
			want: trace.DenialNSEC,
		},
		"neighbours made up around the name (RFC 4470)": {
			authority: []string{
				"example.com. 3600 IN NSEC \\000.example.com. SOA NS RRSIG NSEC DNSKEY",
				"dnstree-listinf\\255.example.com. 3600 IN NSEC \\000.dnstree-listing.example.com. RRSIG NSEC",
			},
			want: trace.DenialMadeUp,
		},
		"the name itself as the owner (RFC 9824)": {
			authority: []string{"dnstree-listing.example.com. 3600 IN NSEC \\000.dnstree-listing.example.com. RRSIG NSEC NXNAME"},
			want:      trace.DenialMadeUp,
		},
		"hashed names": {
			// Upper case: the codec packs no other base32hex since v0.6.128.
			authority: []string{"1avvqn74sg75ukfvf25dgcethgq638ek.example.com. 3600 IN NSEC3 1 0 0 - 75B9ID679QQOIJ81OC7UT2EJIKVUQRPU A RRSIG"},
			want:      trace.DenialNSEC3,
		},
		"no denial at all": {
			authority: []string{"example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600"},
			want:      trace.DenialNone,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			msg := dns.NewMsg(qname, dns.TypeA)
			msg.Rcode = dns.RcodeNameError
			for _, text := range tt.authority {
				msg.Ns = append(msg.Ns, mustRR(t, text))
			}
			// The names have to be read off the wire, as the octets the
			// server sent, the way the probe gets them.
			if err := msg.Pack(); err != nil {
				t.Fatalf("Pack: %v", err)
			}
			back := &dns.Msg{Data: msg.Data}
			if err := back.Unpack(); err != nil {
				t.Fatalf("Unpack: %v", err)
			}
			if got := denial(back, qname); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}
