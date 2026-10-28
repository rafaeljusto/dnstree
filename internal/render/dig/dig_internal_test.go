package dig

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// FuzzCommand reads a command back the way a POSIX shell splits it, and the
// name in it the way dig reads one. Whatever a zone named, the line is one
// line of printable ASCII, the shell finds nothing in it to run or expand,
// the name comes back as the octets that were asked and never as an option,
// and the comment above it stays one line too.
func FuzzCommand(f *testing.F) {
	f.Add("www.example.com.", "A", "a.iana-servers.net.", "retried without EDNS0")
	f.Add("-x.ex'am\"ple\\032$(id);`id`.\n\xff.", "TXT'", "ns.\x1b[2J.", "line\nbreak")
	f.Fuzz(func(t *testing.T, name, rrtype, server, note string) {
		step := &trace.Step{
			Zone:   name,
			Server: trace.Server{Name: server, IP: netip.MustParseAddr("2001:db8::53"), Port: 5353},
			Proto:  "tcp",
			Asked:  trace.Question{Name: name, Type: rrtype},
			Sent:   &trace.Sent{Class: "CH", EDNS: true, UDPSize: 1232, DO: true},
			Kind:   trace.KindError,
			Notes:  []string{note},
			Err:    note,
		}

		line := command(step)
		printable(t, line)
		args := split(t, line)
		at := 6 // dig @server -p port -c class
		if len(args) < at+2 {
			t.Fatalf("%q splits into %q, too few arguments", line, args)
		}
		if got := unescape(args[at]); got != name {
			t.Fatalf("%q reads back as %q", name, got)
		}
		if strings.HasPrefix(args[at], "-") || strings.HasPrefix(args[at], "+") {
			t.Fatalf("%q would be read by dig as an option", args[at])
		}
		if args[at+1] != trace.Shown(rrtype) {
			t.Fatalf("%q splits into %q, want the type back as drawn", line, args)
		}
		printable(t, comment(step, "aside"))
	})
}

// printable fails a line that holds anything but printable ASCII.
func printable(tb testing.TB, line string) {
	tb.Helper()
	if i := strings.IndexFunc(line, func(r rune) bool { return r < ' ' || r > '~' }); i >= 0 {
		tb.Fatalf("%q holds %q at %d", line, line[i], i)
	}
}

// split is a POSIX shell's word splitting of a line made of bare words and
// single quoted ones. Anything the shell would treat specially outside quotes
// fails the test, since it is something the line could make the shell do.
func split(tb testing.TB, line string) []string {
	tb.Helper()
	var (
		args    []string
		word    strings.Builder
		inWord  bool
		quoting bool
	)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quoting:
			if c == '\'' {
				quoting = false
			} else {
				word.WriteByte(c)
			}
		case c == ' ':
			if inWord {
				args = append(args, word.String())
				word.Reset()
				inWord = false
			}
		case c == '\'':
			quoting, inWord = true, true
		case c == '\\' && i+1 < len(line):
			i++
			word.WriteByte(line[i])
			inWord = true
		case strings.IndexByte(safe, c) >= 0:
			word.WriteByte(c)
			inWord = true
		default:
			tb.Fatalf("%q holds %q outside quotes at %d", line, c, i)
		}
	}
	if quoting {
		tb.Fatalf("%q leaves a quote open", line)
	}
	if inWord {
		args = append(args, word.String())
	}
	return args
}

// unescape reads a name as dig does: \DDD is an octet, and a backslash before
// anything else is that character.
func unescape(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		if name[i] != '\\' || i+1 >= len(name) {
			b.WriteByte(name[i])
			continue
		}
		if i+3 < len(name) {
			if n, err := strconv.Atoi(name[i+1 : i+4]); err == nil && n < 256 {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		i++
		b.WriteByte(name[i])
	}
	return b.String()
}

func TestCommand(t *testing.T) {
	server := trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 53}
	tests := map[string]struct {
		step *trace.Step
		want string
	}{
		"a hop of the walk asks without recursion, with the buffer and the DO bit": {
			step: &trace.Step{Server: server, Proto: "udp", Asked: trace.Question{Name: "example.com.", Type: "A"},
				Sent: &trace.Sent{EDNS: true, UDPSize: 1232, DO: true}},
			want: "dig @192.0.2.53 example.com. A +norecurse +bufsize=1232 +dnssec",
		},
		"a query asked again without EDNS0 says so, and carries no EDNS0 option": {
			step: &trace.Step{Server: server, Proto: "udp", Asked: trace.Question{Name: "example.com.", Type: "A"},
				Sent: &trace.Sent{}},
			want: "dig @192.0.2.53 example.com. A +norecurse +noedns",
		},
		"the probe for open recursion asks for it": {
			step: &trace.Step{Server: server, Proto: "udp", Asked: trace.Question{Name: "example.com.", Type: "A"},
				Sent: &trace.Sent{Recursion: true, EDNS: true, UDPSize: 1232}},
			want: "dig @192.0.2.53 example.com. A +bufsize=1232",
		},
		"the question about the server's software is asked in its class": {
			step: &trace.Step{Server: server, Proto: "udp", Asked: trace.Question{Name: "version.bind.", Type: "TXT"},
				Sent: &trace.Sent{Class: "CH", EDNS: true, UDPSize: 1232}},
			want: "dig @192.0.2.53 -c CH version.bind. TXT +norecurse +bufsize=1232",
		},
		"an EDNS test sends the version, flag and option it tests": {
			step: &trace.Step{Server: server, Proto: "udp", Asked: trace.Question{Name: "example.com.", Type: "SOA"},
				Sent: &trace.Sent{EDNS: true, Version: 1, UDPSize: 1232, Flags: 0x40, Options: []uint16{100}}},
			want: "dig @192.0.2.53 example.com. SOA +norecurse +edns=1 +bufsize=1232 +ednsflags=0x40 +ednsopt=100",
		},
		"the options asked for by flag ride along": {
			step: &trace.Step{Server: server, Proto: "udp", Asked: trace.Question{Name: "example.com.", Type: "A"},
				Sent: &trace.Sent{EDNS: true, UDPSize: 1232, NSID: true, Cookie: true,
					Subnet: netip.MustParsePrefix("198.51.100.0/24")}},
			want: "dig @192.0.2.53 example.com. A +norecurse +bufsize=1232 +nsid +cookie +subnet=198.51.100.0/24",
		},
		"DoT on its own port names the transport and no port": {
			step: &trace.Step{Server: trace.Server{IP: netip.MustParseAddr("2001:db8::53"), Port: 853}, Proto: "dot",
				Asked: trace.Question{Name: "example.com.", Type: "AAAA"}, Sent: &trace.Sent{EDNS: true, UDPSize: 1232}},
			want: "dig @2001:db8::53 example.com. AAAA +tls +norecurse +bufsize=1232",
		},
		"a server on a port of its own is asked there": {
			step: &trace.Step{Server: trace.Server{IP: netip.MustParseAddr("192.0.2.53"), Port: 5353}, Proto: "tcp",
				Asked: trace.Question{Name: "example.com.", Type: "A"}, Sent: &trace.Sent{EDNS: true, UDPSize: 1232}},
			want: "dig @192.0.2.53 -p 5353 example.com. A +tcp +norecurse +bufsize=1232",
		},
		"a walk saved before the options were recorded asks with none": {
			step: &trace.Step{Server: server, Proto: "udp", Asked: trace.Question{Name: "example.com.", Type: "A"}},
			want: "dig @192.0.2.53 example.com. A",
		},
		"a name a zone made up is escaped for dig and quoted for the shell": {
			step: &trace.Step{Server: server, Proto: "udp", Asked: trace.Question{Name: "-a b'$(id).example.", Type: "A"},
				Sent: &trace.Sent{}},
			want: `dig @192.0.2.53 '\045a\032b'\''\036\040id\041.example.' A +norecurse +noedns`,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := command(test.step); got != test.want {
				t.Errorf("got\n%s\nwant\n%s", got, test.want)
			}
		})
	}
}
