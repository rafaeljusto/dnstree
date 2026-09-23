package transport

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
)

// DoH is DNS over HTTPS: the same message, posted to /dns-query.
type DoH struct {
	Config
}

var _ Transport = (*DoH)(nil)

// NewDoH returns a DoH transport.
func NewDoH(cfg Config) *DoH { return &DoH{Config: cfg} }

// Proto implements [Transport].
func (d *DoH) Proto() string { return ProtoDoH }

// Port implements [Transport].
func (d *DoH) Port() uint16 { return d.port(PortDoH) }

// Exchange implements [Transport]. The connection goes to the address the
// delegation gave, while the URL and the certificate are about the name: a
// nameserver is found by address and vouched for by name.
func (d *DoH) Exchange(ctx context.Context, req *dns.Msg, server netip.AddrPort, name string) (*dns.Msg, time.Duration, error) {
	server = netip.AddrPortFrom(server.Addr().Unmap(), server.Port())
	if !server.IsValid() || server.Port() == 0 {
		return nil, 0, fmt.Errorf("%s: not a server address", server)
	}

	timeout, err := queryTimeout(ctx, d.Config)
	if err != nil {
		return nil, 0, err
	}

	host := strings.TrimSuffix(name, ".")
	if host == "" {
		host = server.Addr().String()
	}
	url := "https://" + net.JoinHostPort(host, strconv.Itoa(int(server.Port())))

	// NewRequest packs the message and zeroes its ID, which is what RFC 8484
	// asks for: an HTTPS request needs no identifier of its own.
	req.Data = nil
	request, err := dnshttp.NewRequest(http.MethodPost, url, req)
	if err != nil {
		return nil, 0, fmt.Errorf("doh %s: %w", server, err)
	}

	dialer := &net.Dialer{Timeout: timeout}
	client := &http.Client{
		Timeout: timeout,
		// A redirect would send the query somewhere the delegation never named.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig:   d.tlsConfig(host, dnshttp.NextProtos),
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, dial, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network(dial, server.Addr()), server.String())
			},
		},
	}
	defer client.CloseIdleConnections()

	start := time.Now()
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("doh %s: %w", server, err)
	}
	defer response.Body.Close()

	// The status line's own words are the server's to choose, and they end up
	// drawn; the code is all the reader needs.
	if response.StatusCode != http.StatusOK {
		return nil, time.Since(start), fmt.Errorf("doh %s: %d %s", server,
			response.StatusCode, http.StatusText(response.StatusCode))
	}
	if media, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type")); media != dnshttp.MimeType {
		return nil, time.Since(start), fmt.Errorf("doh %s: the reply is %q, not a DNS message", server, media)
	}
	resp, err := dnshttp.Response(response)
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, fmt.Errorf("doh %s: %w", server, err)
	}
	// The ID is zero both ways here, so the question is all that ties the
	// reply to the query.
	if err := answers(req, resp); err != nil {
		return nil, rtt, fmt.Errorf("doh %s: %w", server, err)
	}
	return inClass(resp), rtt, nil
}
