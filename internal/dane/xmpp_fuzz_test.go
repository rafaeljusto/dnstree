package dane

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// FuzzXMPP holds the reading of an XMPP server's stream to its properties:
// TLS starts only where the server offered STARTTLS in the TLS namespace and
// then proceeded, a refusal is read only from a <failure/>, and whatever it
// sends, the reader does not panic.
func FuzzXMPP(f *testing.F) {
	header := "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
	f.Add([]byte(header + "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>" +
		"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"))
	f.Add([]byte(header + "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>" +
		"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"))
	f.Add([]byte(header + "<stream:features><starttls xmlns='urn:other'/></stream:features><proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"))
	f.Add([]byte(header + "<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>"))
	f.Add([]byte(header + "<stream:features><a><b><c/></b></a></stream:features>"))
	f.Add([]byte("220 mx.example.com ESMTP\r\n"))

	f.Fuzz(func(t *testing.T, sent []byte) {
		reader := bytes.NewReader(sent)
		err := xmpp(struct {
			io.Reader
			io.Writer
		}{reader, io.Discard}, "jabber:client", "example.com.")
		if err != nil {
			refused, ok := errors.AsType[*noSTARTTLS](err)
			if ok && refused.why == "it refuses STARTTLS" && !bytes.Contains(sent, []byte("failure")) {
				t.Errorf("read a refusal of STARTTLS into %q", sent)
			}
			return
		}
		if !bytes.Contains(sent, []byte(xmppTLS)) || !bytes.Contains(sent, []byte("starttls")) || !bytes.Contains(sent, []byte("proceed")) {
			t.Errorf("started TLS on %q", sent)
		}
	})
}
