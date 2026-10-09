// Package fakemx runs mail servers that offer STARTTLS on the loopback, with
// certificates made for the test, so --tlsa can be tested without port 25.
package fakemx

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Issued is a certificate and the key it was made for.
type Issued struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Issue makes a certificate valid from from until until for names, signed by
// parent, or by itself where parent is nil.
func Issue(tb testing.TB, parent *Issued, ca bool, from, until time.Time, names ...string) Issued {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		tb.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "test"},
		NotBefore: from, NotAfter: until, DNSNames: names,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        ca, BasicConstraintsValid: true,
	}
	if len(names) > 0 {
		template.Subject.CommonName = names[0]
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		tb.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return Issued{Cert: cert, Key: key}
}

// Digest is the TLSA association data of cert under selector and matching,
// in hex.
func Digest(cert *x509.Certificate, selector, matching uint8) string {
	data := cert.Raw
	if selector == 1 {
		data = cert.RawSubjectPublicKeyInfo
	}
	switch matching {
	case 1:
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	case 2:
		sum := sha512.Sum512(data)
		return hex.EncodeToString(sum[:])
	}
	return hex.EncodeToString(data)
}

// Mode is how a server misbehaves.
type Mode int

// The ways a server can behave.
const (
	Honest   Mode = iota
	Plain         // offers no STARTTLS
	Stall         // never greets
	Flood         // greets without end
	Picky         // refuses EHLO, and takes HELO
	Rambling      // turns the connection away at length
)

// Serve runs a mail server that presents the leaf, made for key, and the
// rest of the chain after STARTTLS. It stops with the test.
func Serve(tb testing.TB, how Mode, key *ecdsa.PrivateKey, chain ...*x509.Certificate) netip.AddrPort {
	tb.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = listener.Close() })

	certificate := tls.Certificate{PrivateKey: key}
	for _, cert := range chain {
		certificate.Certificate = append(certificate.Certificate, cert.Raw)
	}
	config := &tls.Config{Certificates: []tls.Certificate{certificate}}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go converse(conn, how, config)
		}
	}()
	return netip.MustParseAddrPort(listener.Addr().String())
}

func converse(conn net.Conn, how Mode, config *tls.Config) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	switch how {
	case Stall:
		_, _ = conn.Read(make([]byte, 1))
		return
	case Flood:
		line := []byte("220-" + strings.Repeat("x", 1000) + "\r\n")
		for {
			if _, err := conn.Write(line); err != nil {
				return
			}
		}
	case Rambling:
		_, _ = conn.Write([]byte(strings.Repeat("554-"+strings.Repeat("x", 1000)+"\r\n", 200) + "554 go away\r\n"))
		return
	}
	_, _ = conn.Write([]byte("220 mx.example.com ESMTP\r\n"))
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		switch verb := strings.ToUpper(strings.TrimSpace(line)); {
		case strings.HasPrefix(verb, "HELO"):
			_, _ = conn.Write([]byte("250 mx.example.com\r\n"))
		case strings.HasPrefix(verb, "EHLO"):
			switch how {
			case Picky:
				_, _ = conn.Write([]byte("550 introduce yourself properly\r\n"))
			case Plain:
				_, _ = conn.Write([]byte("250-mx.example.com\r\n250 8BITMIME\r\n"))
			default:
				_, _ = conn.Write([]byte("250-mx.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n"))
			}
		case verb == "STARTTLS":
			_, _ = conn.Write([]byte("220 go ahead\r\n"))
			secured := tls.Server(conn, config)
			if secured.Handshake() != nil {
				return
			}
			conn, reader = secured, bufio.NewReader(secured)
		case verb == "QUIT":
			_, _ = conn.Write([]byte("221 bye\r\n"))
			return
		default:
			_, _ = conn.Write([]byte("502 no\r\n"))
		}
	}
}
