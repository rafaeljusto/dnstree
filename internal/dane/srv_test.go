package dane_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/dane"
	"github.com/rafaeljusto/dnstree/v2/internal/testutil/fakemx"
	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

var secure = &trace.DNSSECStatus{State: trace.Secure}

// srvTarget is a target DANE covers, at one address both families of whose
// lookups DNSSEC proved.
func srvTarget(name string, port uint16, records ...trace.TLSARecord) trace.SRVTarget {
	return trace.SRVTarget{
		Name: name, Port: port, DANE: trace.DANEVerified, Records: records,
		IPv4: &trace.Lookup{DNSSEC: secure}, IPv6: &trace.Lookup{DNSSEC: secure},
		Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		TLSA:  &trace.Lookup{Name: "_" + "x._tcp." + name},
	}
}

// redirect dials addr whatever was asked, and counts the dials.
func redirect(addr netip.AddrPort, dialled *atomic.Int32) dane.Dial {
	return func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		dialled.Add(1)
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", addr.String())
	}
}

func TestCheckSRV(t *testing.T) {
	t.Parallel()

	ca := fakemx.Issue(t, nil, true, walked.AddDate(-1, 0, 0), walked.AddDate(5, 0, 0))
	domain := fakemx.Issue(t, &ca, false, walked.AddDate(0, 0, -7), walked.AddDate(0, 3, 0), "example.com")
	host := fakemx.Issue(t, &ca, false, walked.AddDate(0, 0, -7), walked.AddDate(0, 3, 0), "chat1.example.net")
	stray := fakemx.Issue(t, &ca, false, walked.AddDate(0, 0, -7), walked.AddDate(0, 3, 0), "elsewhere.example.org")
	old := fakemx.Issue(t, nil, false, walked.AddDate(-1, 0, 0), walked.AddDate(1, 0, 0), "chat1.example.net")

	for _, tt := range []struct {
		name     string
		protocol fakemx.Protocol
		how      fakemx.Mode
		served   fakemx.Issued
		service  string
		port     uint16
		records  []trace.TLSARecord
		want     trace.PresentedState
		why      string
		warned   string
	}{
		{name: "a server that starts TLS at once is matched on its own port", protocol: fakemx.Implicit, served: host,
			service: "_imaps", port: 993, records: []trace.TLSARecord{record(3, 1, 1, host.Cert)},
			want: trace.PresentedMatch, why: "a client that checks DANE connects to it"},
		{name: "an XMPP server is matched after STARTTLS in its stream", protocol: fakemx.XMPP, served: host,
			service: "_xmpp-client", port: 5222, records: []trace.TLSARecord{record(3, 1, 1, host.Cert)},
			want: trace.PresentedMatch},
		{name: "the port says how TLS starts where the service label does not", protocol: fakemx.XMPP, served: host,
			service: "_chat", port: 5269, records: []trace.TLSARecord{record(3, 1, 1, host.Cert)},
			want: trace.PresentedMatch},
		{name: "a DANE-TA record vouches for a leaf that names the service domain", protocol: fakemx.XMPP, served: domain,
			service: "_xmpp-server", port: 5269, records: []trace.TLSARecord{record(2, 0, 1, ca.Cert)},
			want: trace.PresentedMatch},
		{name: "a DANE-TA record vouches for a leaf that names the target", protocol: fakemx.XMPP, served: host,
			service: "_xmpp-server", port: 5269, records: []trace.TLSARecord{record(2, 0, 1, ca.Cert)},
			want: trace.PresentedMatch},
		{name: "a DANE-TA record does not vouch for a leaf that names another server", protocol: fakemx.XMPP, served: stray,
			service: "_xmpp-server", port: 5269, records: []trace.TLSARecord{record(2, 0, 1, ca.Cert)},
			want: trace.PresentedMismatch, why: "names none of chat1.example.net, example.com",
			warned: "a client that checks DANE does not connect to chat1.example.net. at 192.0.2.10 on port 5269: a DANE-TA record matches, but"},
		{name: "a key renewed without its TLSA record is said with when", protocol: fakemx.Implicit, served: host,
			service: "_xmpps-client", port: 5223, records: []trace.TLSARecord{record(3, 1, 1, old.Cert)},
			want: trace.PresentedMismatch, why: "no TLSA record matches",
			warned: "chat1.example.net. at 192.0.2.10 presents on port 5223 a certificate issued 2026-09-24 that no TLSA record of its matches"},
		{name: "an XMPP server without STARTTLS is one a client does not connect to", protocol: fakemx.XMPP, how: fakemx.Plain, served: host,
			service: "_xmpp-client", port: 5222, records: []trace.TLSARecord{record(3, 1, 1, host.Cert)},
			want: trace.PresentedMismatch, why: "it does not offer STARTTLS, so a client that checks DANE does not connect to it",
			warned: "does not offer STARTTLS"},
		{name: "an XMPP server that refuses STARTTLS is one a client does not connect to", protocol: fakemx.XMPP, how: fakemx.Picky, served: host,
			service: "_xmpp-client", port: 5222, records: []trace.TLSARecord{record(3, 1, 1, host.Cert)},
			want: trace.PresentedMismatch, why: "it refuses STARTTLS", warned: "it refuses STARTTLS"},
		{name: "a server that speaks SMTP where XMPP was due could not be checked", protocol: fakemx.SMTP, served: host,
			service: "_xmpp-client", port: 5222, records: []trace.TLSARecord{record(3, 1, 1, host.Cert)},
			want: trace.PresentedUnreached, why: "the stream",
			warned: "--tlsa could not check any of the servers of _x._tcp.example.com."},
		{name: "a submission server is matched after SMTP's STARTTLS", protocol: fakemx.SMTP, served: host,
			service: "_submission", port: 587, records: []trace.TLSARecord{record(3, 1, 1, host.Cert)},
			want: trace.PresentedMatch},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			addr := fakemx.ServeOver(t, tt.protocol, tt.how, tt.served.Key, tt.served.Cert, ca.Cert)
			s := &trace.SRV{Name: tt.service + "._tcp.example.com.", Targets: []trace.SRVTarget{
				srvTarget("chat1.example.net.", tt.port, tt.records...),
			}}
			if tt.service == "_xmpp-client" && tt.protocol == fakemx.SMTP {
				s.Name = "_x._tcp.example.com."
				s.Targets[0].Port = 5222
			}
			tr := &trace.Trace{Started: walked, SRV: s}
			var dialled atomic.Int32
			dane.Check(context.Background(), tr, dane.Config{Timeout: time.Second, Dial: redirect(addr, &dialled)})

			warned := strings.Join(tr.Warnings, "\n")
			if tt.warned == "" && warned != "" || !strings.Contains(warned, tt.warned) {
				t.Errorf("warnings = %q, want %q", warned, tt.warned)
			}
			presented := s.Targets[0].Presented
			if len(presented) != 1 {
				t.Fatalf("presented = %+v, want one address", presented)
			}
			if got := presented[0]; got.State != tt.want || !strings.Contains(got.Why, tt.why) {
				t.Errorf("got %s (%s), want %s with %q", got.State, got.Why, tt.want, tt.why)
			}
		})
	}
}

// TestCheckSRVUnknownService covers a service --tlsa cannot start TLS for: it
// connects to nothing, and says so rather than guess.
func TestCheckSRVUnknownService(t *testing.T) {
	t.Parallel()

	tr := &trace.Trace{Started: walked, SRV: &trace.SRV{Name: "_minecraft._tcp.example.com.", Targets: []trace.SRVTarget{
		srvTarget("mc.example.com.", 25565, trace.TLSARecord{Usage: 3, Selector: 1, Matching: 1, Usable: true}),
	}}}
	var dialled atomic.Int32
	dane.Check(context.Background(), tr, dane.Config{Timeout: time.Second, Dial: redirect(netip.AddrPort{}, &dialled)})

	if dialled.Load() != 0 || tr.SRV.Targets[0].Presented != nil {
		t.Errorf("dialled %d times, presented %+v, want nothing", dialled.Load(), tr.SRV.Targets[0].Presented)
	}
	want := "--tlsa did not check mc.example.com. on port 25565, since it does not know how _minecraft starts TLS"
	if warned := strings.Join(tr.Warnings, "\n"); !strings.Contains(warned, want) {
		t.Errorf("warnings = %q, want %q", warned, want)
	}
}

// TestCheckSRVOnce covers two records that name one host on one port, and a
// target DANE does not cover: the host is connected to once, both records say
// what it showed, and the other is left alone.
func TestCheckSRVOnce(t *testing.T) {
	t.Parallel()

	leaf := fakemx.Issue(t, nil, false, walked.AddDate(0, 0, -7), walked.AddDate(0, 3, 0), "chat1.example.net")
	addr := fakemx.ServeOver(t, fakemx.Implicit, fakemx.Honest, leaf.Key, leaf.Cert)
	insecure := srvTarget("chat2.example.net.", 5223)
	insecure.DANE = trace.DANEInsecure
	tr := &trace.Trace{Started: walked, SRV: &trace.SRV{Name: "_xmpps-client._tcp.example.com.", Targets: []trace.SRVTarget{
		srvTarget("chat1.example.net.", 5223, record(3, 1, 1, leaf.Cert)),
		insecure,
		srvTarget("CHAT1.example.net.", 5223, record(3, 1, 1, leaf.Cert)),
	}}}
	var dialled atomic.Int32
	dane.Check(context.Background(), tr, dane.Config{Timeout: time.Second, Dial: redirect(addr, &dialled)})

	if got := dialled.Load(); got != 1 {
		t.Errorf("dialled %d times, want once", got)
	}
	targets := tr.SRV.Targets
	if len(targets[0].Presented) != 1 || !slices.EqualFunc(targets[0].Presented, targets[2].Presented, func(a, b trace.Presented) bool {
		return a.Addr == b.Addr && a.State == b.State
	}) {
		t.Errorf("presented %+v and %+v, want the same one address", targets[0].Presented, targets[2].Presented)
	}
	if targets[1].Presented != nil {
		t.Errorf("presented %+v for a target DANE does not cover", targets[1].Presented)
	}
}

// TestCheckSRVProvenOnly covers a target one of whose address sets is not
// signed: a client that checks DANE connects only to the addresses DNSSEC
// proved (RFC 7673 3.2), and an IPv4-mapped address the AAAA set gave is not
// proved by the A set.
func TestCheckSRVProvenOnly(t *testing.T) {
	t.Parallel()

	leaf := fakemx.Issue(t, nil, false, walked.AddDate(0, 0, -7), walked.AddDate(0, 3, 0), "chat1.example.net")
	addr := fakemx.ServeOver(t, fakemx.Implicit, fakemx.Honest, leaf.Key, leaf.Cert)
	target := srvTarget("chat1.example.net.", 5223, record(3, 1, 1, leaf.Cert))
	target.IPv6 = &trace.Lookup{DNSSEC: &trace.DNSSECStatus{State: trace.Insecure}}
	target.Addrs = append(target.Addrs, netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("::ffff:192.0.2.11"))
	tr := &trace.Trace{Started: walked, SRV: &trace.SRV{Name: "_xmpps-client._tcp.example.com.", Targets: []trace.SRVTarget{target}}}
	var dialled atomic.Int32
	dane.Check(context.Background(), tr, dane.Config{Timeout: time.Second, Dial: redirect(addr, &dialled)})

	presented := tr.SRV.Targets[0].Presented
	if len(presented) != 1 || presented[0].Addr != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("presented %+v, want 192.0.2.10 alone", presented)
	}
}

// TestCheckSRVAsksForTheServiceDomain covers the name the handshake asks
// for: the service domain, which RFC 7673 4.1 prefers to the target.
func TestCheckSRVAsksForTheServiceDomain(t *testing.T) {
	t.Parallel()

	leaf := fakemx.Issue(t, nil, false, walked.AddDate(0, 0, -7), walked.AddDate(0, 3, 0), "example.com")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	asked := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = tls.Server(conn, &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			asked <- hello.ServerName
			return &tls.Certificate{Certificate: [][]byte{leaf.Cert.Raw}, PrivateKey: leaf.Key}, nil
		}}).Handshake()
	}()

	tr := &trace.Trace{Started: walked, SRV: &trace.SRV{Name: "_xmpps-client._tcp.example.com.", Targets: []trace.SRVTarget{
		srvTarget("chat1.example.net.", 5223, record(3, 1, 1, leaf.Cert)),
	}}}
	var dialled atomic.Int32
	dane.Check(context.Background(), tr, dane.Config{Timeout: time.Second,
		Dial: redirect(netip.MustParseAddrPort(listener.Addr().String()), &dialled)})

	select {
	case name := <-asked:
		if name != "example.com" {
			t.Errorf("asked for %q, want example.com", name)
		}
	default:
		t.Error("the handshake never asked for a name")
	}
}
