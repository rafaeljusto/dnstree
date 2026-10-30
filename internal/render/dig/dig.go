// Package dig renders a trace as the dig commands that ask what the walk
// asked, one per query, so that someone without dnstree can repeat it.
package dig

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Render writes a comment and a command for every query the walk made, in the
// order the tree draws them. Options come from what each query was recorded to
// carry and from nothing else.
//
// Unlike the other renderers it reads the trace as the walk kept it, not the
// copy Trace.Shown makes: a command has to name the octets that were asked,
// and Shown leaves a backslash as it is. Every name is escaped for dig and
// quoted for the shell here instead, and the comments go through Shown.
func Render(w io.Writer, tr *trace.Trace) error {
	out := bufio.NewWriter(w)
	if tr != nil {
		var s script
		s.add(tr.Root, "")
		fmt.Fprintf(out, "# dnstree %s %s, as dig commands\n",
			trace.Shown(tr.Question.Name), trace.Shown(tr.Question.Type))
		if s.unrecorded {
			fmt.Fprintln(out, "# a query without options was saved before dnstree recorded what it sent")
		}
		if s.cookie {
			fmt.Fprintln(out, "# +cookie needs dig 9.11 or later")
		}
		if s.encrypted {
			fmt.Fprintln(out, "# +tls and +https need dig 9.18 or later")
		}
		for _, line := range s.lines {
			fmt.Fprintln(out, line)
		}
	}
	return out.Flush()
}

// script is the lines a walk turns into, and what has to be said above them.
type script struct {
	lines                         []string
	unrecorded, cookie, encrypted bool
}

// add writes a step and everything below it. Aside and Apart mark only the
// top of the work they set apart, so what that work is for is carried down to
// every query inside it.
func (s *script) add(step *trace.Step, within string) {
	if step == nil {
		return
	}
	switch {
	case step.Apart:
		within = "a check's own lookup"
	case step.Aside && within == "":
		within = "aside"
	}
	if step.Queried() && step.Server.IP.IsValid() {
		s.unrecorded = s.unrecorded || step.Sent == nil
		s.cookie = s.cookie || step.Sent != nil && step.Sent.EDNS && step.Sent.Cookie
		s.encrypted = s.encrypted || step.Proto == "dot" || step.Proto == "doh"
		s.lines = append(s.lines, "# "+comment(step, within))
		if askable(step) {
			s.lines = append(s.lines, command(step))
		} else {
			s.lines = append(s.lines, "# no command: the type or class saved for it is not one dig reads as such")
		}
	}
	for _, child := range step.Children {
		s.add(child, within)
	}
}

// command is the dig command that asks what one step asked.
func command(step *trace.Step) string {
	args := []string{"dig", "@" + step.Server.IP.String()}
	if port := step.Server.Port; port != 0 && port != ports[step.Proto] {
		args = append(args, "-p", strconv.Itoa(int(port)))
	}
	if sent := step.Sent; sent != nil && sent.Class != "" {
		args = append(args, "-c", trace.Shown(sent.Class))
	}
	args = append(args, presentation(step.Asked.Name), trace.Shown(step.Asked.Type))
	args = append(args, options(step)...)

	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = quote(arg)
	}
	return strings.Join(quoted, " ")
}

// askable reports whether the type and class a step saved can go on a command
// line. A walk only ever records mnemonics, but a file read with --from says
// what it likes, and a bare -f/etc/passwd is an option to dig.
func askable(step *trace.Step) bool {
	values := []string{step.Asked.Type}
	if step.Sent != nil && step.Sent.Class != "" {
		values = append(values, step.Sent.Class)
	}
	for _, value := range values {
		if value == "" || value[0] < 'A' || value[0] > 'Z' ||
			strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != "" {
			return false
		}
	}
	return true
}

// ports are where each transport is asked when nothing says otherwise, for
// dnstree and dig alike.
var ports = map[string]uint16{"udp": 53, "tcp": 53, "dot": 853, "doh": 443}

func options(step *trace.Step) []string {
	var opts []string
	switch step.Proto {
	case "tcp":
		opts = append(opts, "+tcp")
	case "dot":
		opts = append(opts, "+tls")
	case "doh":
		opts = append(opts, "+https")
	}

	sent := step.Sent
	if sent == nil {
		return opts
	}
	if !sent.Recursion {
		opts = append(opts, "+norecurse")
	}
	if !sent.EDNS {
		return append(opts, "+noedns")
	}
	if sent.Version > 0 {
		opts = append(opts, "+edns="+strconv.Itoa(int(sent.Version)))
	}
	opts = append(opts, "+bufsize="+strconv.Itoa(int(sent.UDPSize)))
	if sent.DO {
		opts = append(opts, "+dnssec")
	}
	if sent.Flags > 0 {
		opts = append(opts, fmt.Sprintf("+ednsflags=0x%x", sent.Flags))
	}
	if sent.NSID {
		opts = append(opts, "+nsid")
	}
	if sent.Cookie {
		opts = append(opts, "+cookie")
	}
	if sent.Subnet.IsValid() {
		opts = append(opts, "+subnet="+sent.Subnet.String())
	}
	for _, code := range sent.Options {
		opts = append(opts, "+ednsopt="+strconv.Itoa(int(code)))
	}
	return opts
}

// comment says where a query went, what for where it was not the walk's own,
// and what came of it. The notes already say when a hop was minimised, and to
// what.
func comment(step *trace.Step, within string) string {
	server := step.Server.Name
	if server == "" {
		server = step.Server.IP.String()
	}
	var what []string
	if within != "" {
		what = append(what, within)
	}
	what = append(what, outcome(step))
	what = append(what, step.Notes...)
	return trace.Shown(step.Zone + " at " + server + ": " + strings.Join(what, ", "))
}

func outcome(step *trace.Step) string {
	switch step.Kind {
	case trace.KindReferral:
		if step.Delegation != nil {
			return "referral to " + step.Delegation.Zone
		}
		return "referral"
	case trace.KindAnswer:
		return "answer"
	case trace.KindCNAME:
		return "alias"
	case trace.KindNoData:
		return "no records of that type"
	case trace.KindNXDomain:
		return "no such name"
	case trace.KindLame:
		return "lame"
	case trace.KindFiltered:
		return "filtered"
	case trace.KindTimeout:
		return "no answer"
	case trace.KindError:
		if step.Err != "" {
			return "failed: " + step.Err
		}
		return "failed"
	}
	return string(step.Kind)
}

// presentation is a name as dig reads it: every octet that is not a printable
// letter of its own, and the backslash, as \DDD. A leading + or - is escaped
// too, or dig would take the name for an option. A dot inside a label cannot
// be told from the dot between two, here or anywhere else the codec hands
// names over.
func presentation(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c > '~' || strings.IndexByte(special, c) >= 0 || i == 0 && (c == '+' || c == '-') {
			fmt.Fprintf(&b, "\\%03d", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// special are the octets that mean something in a name's text form.
const special = `\"();@$`

// quote is an argument as a POSIX shell reads it back whole: bare where every
// character is one no shell treats specially, and otherwise single quoted,
// inside which nothing is special but the quote itself.
func quote(arg string) string {
	if arg != "" && strings.Trim(arg, safe) == "" {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

const safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-"
