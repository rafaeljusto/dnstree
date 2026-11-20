package dane

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/textproto"
	"strings"
)

// starter is how a service starts TLS: begin is what is said before the
// handshake, nil for a service that starts TLS at once, and quit what ends
// the session after it.
type starter struct {
	begin func(conn net.Conn, domain string) error
	quit  string
}

var (
	implicit   = starter{}
	startSMTP  = starter{begin: smtp, quit: "QUIT\r\n"}
	xmppClient = starter{begin: func(conn net.Conn, domain string) error { return xmpp(conn, "jabber:client", domain) }}
	xmppServer = starter{begin: func(conn net.Conn, domain string) error { return xmpp(conn, "jabber:server", domain) }}
)

// services are how the services an SRV set may be for start TLS, by their
// label, and ports how the usual ports do where the label says nothing.
var (
	services = map[string]starter{
		"_submission": startSMTP, "_xmpp-client": xmppClient, "_xmpp-server": xmppServer,
		"_submissions": implicit, "_imaps": implicit, "_pop3s": implicit, "_xmpps-client": implicit,
		"_xmpps-server": implicit, "_sips": implicit, "_ldaps": implicit,
	}
	ports = map[uint16]starter{
		25: startSMTP, 587: startSMTP, 5222: xmppClient, 5269: xmppServer,
		443: implicit, 465: implicit, 636: implicit, 853: implicit, 993: implicit, 995: implicit,
		5061: implicit, 5223: implicit,
	}
)

// starterFor is how the service starts TLS on port, and whether it is known:
// by the service's label first, then by the port.
func starterFor(service string, port uint16) (starter, bool) {
	if start, ok := services[service]; ok {
		return start, true
	}
	start, ok := ports[port]
	return start, ok
}

// smtp greets the server and asks it to start TLS. The exchange is made by
// hand rather than through net/smtp, which falls back to HELO when EHLO is
// refused and would then read as a server without STARTTLS.
func smtp(conn net.Conn, _ string) error {
	text := textproto.NewConn(conn)
	if _, _, err := text.ReadResponse(220); err != nil {
		return fmt.Errorf("the greeting: %w", err)
	}
	if err := text.PrintfLine("EHLO %s", literal(conn.LocalAddr())); err != nil {
		return err
	}
	_, extensions, err := text.ReadResponse(250)
	if err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}
	if !offers(extensions, "STARTTLS") {
		return &noSTARTTLS{"it does not offer STARTTLS"}
	}
	if err := text.PrintfLine("STARTTLS"); err != nil {
		return err
	}
	if _, _, err := text.ReadResponse(220); err != nil {
		if _, ok := errors.AsType[*textproto.Error](err); ok {
			return &noSTARTTLS{"it refuses STARTTLS (" + err.Error() + ")"}
		}
		return fmt.Errorf("STARTTLS: %w", err)
	}
	return nil
}

// literal is the address an SMTP client introduces itself by where it has no
// name to give (RFC 5321 4.1.3).
func literal(addr net.Addr) string {
	ip, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return "[127.0.0.1]"
	}
	if ip.Addr().Unmap().Is4() {
		return "[" + ip.Addr().Unmap().String() + "]"
	}
	return "[IPv6:" + ip.Addr().WithZone("").String() + "]"
}

// offers reports whether an EHLO reply lists the extension: its lines after
// the first, each a keyword and its parameters.
func offers(reply, extension string) bool {
	lines := strings.Split(reply, "\n")
	for _, line := range lines[1:] {
		keyword, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		if strings.EqualFold(keyword, extension) {
			return true
		}
	}
	return false
}

// The namespaces of an XMPP stream and of its TLS negotiation (RFC 6120).
const (
	streams = "http://etherx.jabber.org/streams"
	xmppTLS = "urn:ietf:params:xml:ns:xmpp-tls"
)

// xmpp opens a stream to domain in namespace ns and asks the server to start
// TLS (RFC 6120 5.4). The server sends nothing after it proceeds until the
// handshake begins, so what the decoder read ahead holds nothing of it.
func xmpp(rw io.ReadWriter, ns, domain string) error {
	var to strings.Builder
	_ = xml.EscapeText(&to, []byte(strings.TrimSuffix(domain, ".")))
	if _, err := fmt.Fprintf(rw, "<?xml version='1.0'?><stream:stream xmlns='%s' xmlns:stream='%s' to='%s' version='1.0'>",
		ns, streams, to.String()); err != nil {
		return err
	}
	decoder := xml.NewDecoder(rw)
	offered, err := features(decoder)
	if err != nil {
		return fmt.Errorf("the stream: %w", err)
	}
	if !offered {
		return &noSTARTTLS{"it does not offer STARTTLS"}
	}
	if _, err := fmt.Fprintf(rw, "<starttls xmlns='%s'/>", xmppTLS); err != nil {
		return err
	}
	return proceeds(decoder)
}

// features reads the stream header and the features the server offers, and
// reports whether STARTTLS is one of them.
func features(decoder *xml.Decoder) (bool, error) {
	header, err := next(decoder)
	if err != nil {
		return false, err
	}
	if header.Name != (xml.Name{Space: streams, Local: "stream"}) {
		return false, fmt.Errorf("the server opened no stream, but <%s>", header.Name.Local)
	}
	element, err := next(decoder)
	if err != nil {
		return false, err
	}
	switch element.Name {
	case xml.Name{Space: streams, Local: "error"}:
		return false, errors.New("the server closed the stream with an error")
	case xml.Name{Space: streams, Local: "features"}:
	default:
		return false, fmt.Errorf("the server sent <%s> where its features belong", element.Name.Local)
	}
	offered := false
	for {
		token, err := decoder.Token()
		if err != nil {
			return false, err
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name == (xml.Name{Space: xmppTLS, Local: "starttls"}) {
				offered = true
			}
			if err := decoder.Skip(); err != nil {
				return false, err
			}
		case xml.EndElement:
			return offered, nil
		}
	}
}

// proceeds reads the server's answer to STARTTLS.
func proceeds(decoder *xml.Decoder) error {
	element, err := next(decoder)
	if err != nil {
		return fmt.Errorf("STARTTLS: %w", err)
	}
	switch element.Name {
	case xml.Name{Space: xmppTLS, Local: "proceed"}:
		return nil
	case xml.Name{Space: xmppTLS, Local: "failure"}:
		return &noSTARTTLS{"it refuses STARTTLS"}
	}
	return fmt.Errorf("STARTTLS: the server sent <%s>", element.Name.Local)
}

// next is the next element the decoder opens, past text, comments and the
// declaration.
func next(decoder *xml.Decoder) (xml.StartElement, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		if start, ok := token.(xml.StartElement); ok {
			return start, nil
		}
	}
}
