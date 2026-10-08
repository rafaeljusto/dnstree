// Package spf reads the sender policy a domain publishes (RFC 7208) into the
// tree of lookups a receiving mail server makes to check it, and counts them
// against the limits a check is held to. It asks through whatever lookup it is
// handed, and never speaks the wire itself.
package spf

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Lookup asks a recursive server for name and qtype. Nil means it could not be
// asked at all.
type Lookup func(ctx context.Context, name, qtype string) *trace.Resolver

// Check follows the policy at name through every term a check can come to,
// asking no more than budget queries. A ctx cancelled with DeadlineExceeded
// as its cause is the check running out of time, and any other an interruption. It always comes back with a policy:
// whatever went wrong is its result, and the term it went wrong at says so.
func Check(ctx context.Context, name string, lookup Lookup, budget int) *trace.SPF {
	c := &checker{
		ctx:    ctx,
		lookup: lookup,
		budget: budget,
		spf:    &trace.SPF{Name: fqdn(name), Result: trace.SPFOK},
	}
	found := c.policy(c.spf.Name)
	switch {
	case c.spf.Cut:
	case found.result == trace.SPFNone:
		c.spf.Result, c.spf.Why = trace.SPFNone, c.spf.Name+" publishes no SPF policy"
	case found.result != trace.SPFOK:
		c.spf.Result, c.spf.Why = found.result, found.why
	default:
		c.spf.Record = found.record
		c.spf.Terms = c.terms(found.record, c.spf.Name, []string{canonical(c.spf.Name)}, true)
	}
	switch {
	case c.stopped && (c.spf.Result == trace.SPFOK || c.spf.Result == trace.SPFUndecided && c.spf.Why == ""):
		c.spf.Result = trace.SPFUndecided
		c.spf.Why = "the check was interrupted before the policy was followed to its end"
		if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			c.spf.Why = "the check ran out of time before the policy was followed to its end; ask another resolver with --resolver"
		}
	case c.spf.Cut && c.spf.Result == trace.SPFOK:
		c.spf.Result = trace.SPFUndecided
		c.spf.Why = fmt.Sprintf("the budget of %d queries ran out before the policy was followed to its end; raise --max-queries", budget)
	}
	return c.spf
}

type checker struct {
	ctx     context.Context
	lookup  Lookup
	budget  int
	queries int
	stopped bool // ctx is done, which cuts the check short like the budget
	spf     *trace.SPF
}

// ask spends a query of the budget, and is nil once there is none left, or no
// time.
func (c *checker) ask(name, qtype string) *trace.Resolver {
	if c.queries >= c.budget || c.ctx.Err() != nil {
		c.spf.Cut = true
		c.stopped = c.ctx.Err() != nil
		return nil
	}
	c.queries++
	answer := c.lookup(c.ctx, name, qtype)
	if c.ctx.Err() != nil && (answer == nil || answer.Err != "") {
		c.spf.Cut, c.stopped = true, true
		return nil
	}
	if answer == nil {
		return &trace.Resolver{Err: "the resolver could not be asked"}
	}
	return answer
}

// failure is why a lookup did not come back with an answer, empty where it
// did. A name that is not there is an answer: RFC 7208 counts it as void.
func failure(answer *trace.Resolver) string {
	switch {
	case answer.Err != "":
		return answer.Err
	case answer.Rcode != "NOERROR" && answer.Rcode != "NXDOMAIN":
		return answer.Rcode
	}
	return ""
}

// found is what the TXT set at a name came to.
type found struct {
	record string
	void   bool
	result trace.SPFResult
	why    string
}

// policy looks up the one policy a name publishes (RFC 7208 4.5).
func (c *checker) policy(name string) found {
	answer := c.ask(name, "TXT")
	if answer == nil {
		return found{result: trace.SPFUndecided}
	}
	if why := failure(answer); why != "" {
		return found{result: trace.SPFTempError, why: "the TXT lookup of " + name + " failed: " + why}
	}

	var texts, policies []string
	for _, record := range answer.Records {
		if record.Type == "TXT" {
			texts = append(texts, unquote(record.Data))
		}
	}
	for _, text := range texts {
		lower := strings.ToLower(text)
		if lower == "v=spf1" || strings.HasPrefix(lower, "v=spf1 ") {
			policies = append(policies, text)
		}
	}
	void := len(texts) == 0
	switch len(policies) {
	case 0:
		return found{void: void, result: trace.SPFNone, why: name + " publishes no SPF policy"}
	case 1:
		if n := len(fieldsOf(policies[0])) - 1; n > maxTerms {
			return found{result: trace.SPFUndecided,
				why: fmt.Sprintf("%s publishes a policy of %d terms, past the %d dnstree reads", name, n, maxTerms)}
		}
		return found{record: policies[0], result: trace.SPFOK}
	}
	return found{result: trace.SPFPermError,
		why: fmt.Sprintf("%s publishes %d SPF policies, where a check needs exactly one", name, len(policies))}
}

// maxTerms is far past any policy in use: one that fits the 512 octets RFC
// 7208 3.4 asks for holds a few dozen. A longer one only spends the memory of
// the check and of every renderer after it.
const maxTerms = 512

// fieldsOf are the terms of a policy and its version. Only a space parts them
// (RFC 7208 4.6.1): any other blank is part of a term, which then does not
// parse.
func fieldsOf(record string) []string {
	return slices.DeleteFunc(strings.Split(record, " "), func(field string) bool { return field == "" })
}

// term is one term of a policy, read.
type term struct {
	mechanism string // empty for a modifier
	modifier  string
	qualifier byte
	domain    string // the domain-spec, empty where it takes the policy's own
	problem   string // why it does not parse
}

// terms follows a policy at domain. path are the domains being followed
// already, which an include or a redirect may not come back to; final is
// whether the policy decides the check, rather than answering an include.
func (c *checker) terms(record, domain string, path []string, final bool) []trace.SPFTerm {
	fields := fieldsOf(record)[1:]
	parsed := make([]term, len(fields))
	terms := make([]trace.SPFTerm, len(fields))
	broken := false
	redirects, explanations := 0, 0
	for i, field := range fields {
		parsed[i] = parse(field)
		terms[i].Term = field
		if parsed[i].problem == "" {
			terms[i].Kind = cmp.Or(parsed[i].mechanism, parsed[i].modifier)
		}
		switch parsed[i].modifier {
		case "redirect":
			redirects++
			if redirects > 1 && parsed[i].problem == "" {
				parsed[i].problem = "a second redirect, where a policy may have one"
			}
		case "exp":
			explanations++
			if explanations > 1 && parsed[i].problem == "" {
				parsed[i].problem = "a second exp, where a policy may have one"
			}
		}
		if parsed[i].problem != "" {
			c.fail(&terms[i], trace.SPFPermError, parsed[i].problem)
			broken = true
		}
	}
	// A policy that does not parse fails before anything in it is looked up.
	if broken {
		return terms
	}

	all, redirect := false, -1
	for i := range terms {
		t, p := &terms[i], parsed[i]
		if all {
			t.Unreached = true
			continue
		}
		switch {
		case p.modifier == "redirect":
			redirect = i
		case p.mechanism != "":
			all = p.mechanism == "all"
			c.mechanism(t, p, domain, path, final)
		}
	}
	// A redirect is followed once every mechanism has failed to match, and
	// never beside an all, which always matches (RFC 7208 6.1).
	if redirect >= 0 {
		if all {
			terms[redirect].Unreached = true
		} else {
			c.follow(&terms[redirect], parsed[redirect].domain, path, final)
		}
	}
	return terms
}

func (c *checker) mechanism(t *trace.SPFTerm, p term, domain string, path []string, final bool) {
	switch p.mechanism {
	case "all":
		switch {
		case p.qualifier == '+':
			c.warn(t, "it lets anyone send mail as "+c.spf.Name+"; end the policy with ~all or -all")
		case p.qualifier == '?' && final:
			c.warn(t, "it leaves every sender the policy does not name neutral, which receivers treat as no policy; end it with ~all or -all once every sender is listed")
		}
	case "include":
		c.follow(t, p.domain, path, false)
	case "a":
		c.addresses(t, cmp.Or(p.domain, domain), "A", "AAAA")
	case "exists":
		c.addresses(t, p.domain, "A")
	case "mx":
		c.exchangers(t, cmp.Or(p.domain, domain))
	case "ptr":
		c.count(t)
		t.Sender = true
		c.warn(t, "it rests on the sender's reverse zone, which is slow and unreliable, and RFC 7208 5.5 says not to use it; list the senders' addresses instead")
	}
}

// count spends one of the lookups a check is allowed.
func (c *checker) count(t *trace.SPFTerm) {
	c.spf.Lookups++
	t.Lookup = c.spf.Lookups
	if c.spf.Lookups == trace.SPFLookupLimit+1 {
		c.fail(t, trace.SPFPermError, fmt.Sprintf("lookup %d, past the limit of %d; drop an include, or list the addresses it stands for instead",
			c.spf.Lookups, trace.SPFLookupLimit))
	}
}

// empty marks a lookup that found nothing.
func (c *checker) empty(t *trace.SPFTerm) {
	t.Void = true
	c.spf.Void++
	if c.spf.Void == trace.SPFVoidLimit+1 {
		c.fail(t, trace.SPFPermError, fmt.Sprintf("lookup %d to find nothing, past the limit of %d", c.spf.Void, trace.SPFVoidLimit))
	}
}

// target is the name a term looks up, or false where it depends on the sender
// and is counted without being asked.
func target(t *trace.SPFTerm, spec string) (string, bool) {
	if strings.Contains(spec, "%{") {
		t.Target, t.Sender = spec, true
		return "", false
	}
	t.Target = fqdn(spec)
	return t.Target, true
}

// follow is an include or a redirect: the policy of another domain, checked in
// turn.
func (c *checker) follow(t *trace.SPFTerm, spec string, path []string, final bool) {
	c.count(t)
	name, ok := target(t, spec)
	if !ok {
		return
	}
	if slices.Contains(path, canonical(name)) {
		c.fail(t, trace.SPFPermError, name+" is already being checked, so the check never ends")
		return
	}

	found := c.policy(name)
	if found.void {
		c.empty(t)
	}
	switch found.result {
	case trace.SPFUndecided:
		// Without a reason it is the budget, or ctx, which Check says once.
		if found.why != "" {
			c.fail(t, found.result, found.why)
		}
	case trace.SPFOK:
		t.Record = found.record
		t.Terms = c.terms(found.record, name, append(slices.Clone(path), canonical(name)), final)
	case trace.SPFNone:
		// What a check found nothing to follow to is an error in the policy
		// that pointed there (RFC 7208 5.2, 6.1).
		c.fail(t, trace.SPFPermError, found.why)
	default:
		c.fail(t, found.result, found.why)
	}
}

// addresses is an a or an exists. Which family an a asks for depends on how
// the sender connected, so it finds nothing only where neither has anything.
func (c *checker) addresses(t *trace.SPFTerm, spec string, qtypes ...string) {
	c.count(t)
	name, ok := target(t, spec)
	if !ok {
		return
	}
	for _, qtype := range qtypes {
		answer := c.ask(name, qtype)
		if answer == nil {
			return
		}
		if why := failure(answer); why != "" {
			c.fail(t, trace.SPFTempError, "the "+qtype+" lookup of "+name+" failed: "+why)
			return
		}
		for _, record := range answer.Records {
			if record.Type == qtype {
				t.Found = append(t.Found, record.Data)
			}
		}
	}
	if len(t.Found) == 0 {
		c.empty(t)
	}
}

// exchangers is an mx. Each of the mail servers is one more address lookup a
// check makes, which RFC 7208 4.6.4 caps at ten rather than counting.
func (c *checker) exchangers(t *trace.SPFTerm, spec string) {
	c.count(t)
	name, ok := target(t, spec)
	if !ok {
		return
	}
	answer := c.ask(name, "MX")
	if answer == nil {
		return
	}
	if why := failure(answer); why != "" {
		c.fail(t, trace.SPFTempError, "the MX lookup of "+name+" failed: "+why)
		return
	}

	type exchanger struct {
		preference int
		host       string
	}
	var found []exchanger
	for _, record := range answer.Records {
		if record.Type != "MX" {
			continue
		}
		preference, host, _ := strings.Cut(record.Data, " ")
		n, _ := strconv.Atoi(preference)
		found = append(found, exchanger{n, host})
	}
	slices.SortStableFunc(found, func(a, b exchanger) int { return a.preference - b.preference })
	for _, e := range found {
		t.Found = append(t.Found, e.host)
	}

	switch {
	case len(found) == 0:
		c.empty(t)
	case len(found) > trace.SPFLookupLimit:
		c.fail(t, trace.SPFPermError, fmt.Sprintf("%s has %d mail servers, past the limit of %d", name, len(found), trace.SPFLookupLimit))
	}
}

// fail is a problem that ends the check. Only the first one a check comes to
// decides its result; the others are drawn where they are.
func (c *checker) fail(t *trace.SPFTerm, result trace.SPFResult, why string) {
	c.note(t, why)
	t.Fatal = true
	if c.spf.Result == trace.SPFOK {
		c.spf.Result, c.spf.Why = result, t.Term+": "+why
	}
}

// warn is a problem that does not end the check.
func (c *checker) warn(t *trace.SPFTerm, why string) {
	c.note(t, why)
}

func (c *checker) note(t *trace.SPFTerm, why string) {
	if t.Problem != "" {
		t.Problem += "; "
	}
	t.Problem += why
}

// parse reads one term (RFC 7208 4.6.1, 12).
func parse(text string) term {
	if i := strings.IndexAny(text, "=:/"); i > 0 && text[i] == '=' && modifierName(text[:i]) {
		t := term{modifier: strings.ToLower(text[:i]), domain: text[i+1:]}
		if t.modifier == "redirect" || t.modifier == "exp" {
			t.problem = domainSpec(t.domain)
		}
		return t
	}

	var t term
	rest := text
	if rest != "" && strings.IndexByte("+-~?", rest[0]) >= 0 {
		t.qualifier, rest = rest[0], rest[1:]
	}
	if t.qualifier == 0 {
		t.qualifier = '+'
	}
	name, args := rest, ""
	if i := strings.IndexAny(rest, ":/"); i >= 0 {
		name, args = rest[:i], rest[i:]
	}
	// strings.ToLower would read U+0130 as an i, and so İnclude as an include.
	t.mechanism = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, name)

	switch t.mechanism {
	case "all":
		if args != "" {
			t.problem = "all takes nothing after it"
		}
	case "include", "exists":
		domain, ok := strings.CutPrefix(args, ":")
		t.domain = domain
		if !ok || domain == "" {
			t.problem = t.mechanism + " needs a domain after a colon"
		} else {
			t.problem = domainSpec(domain)
		}
	case "a", "mx":
		domain, cidr := args, ""
		if i := strings.IndexByte(args, '/'); i >= 0 {
			domain, cidr = args[:i], args[i:]
		}
		if domain != "" {
			t.domain = strings.TrimPrefix(domain, ":")
			t.problem = domainSpec(t.domain)
		}
		if t.problem == "" {
			t.problem = dualCIDR(cidr)
		}
	case "ptr":
		if args != "" {
			domain, ok := strings.CutPrefix(args, ":")
			t.domain = domain
			if !ok {
				t.problem = "ptr takes a domain after a colon, and nothing else"
			} else {
				t.problem = domainSpec(domain)
			}
		}
	case "ip4", "ip6":
		t.problem = network(t.mechanism, args)
	default:
		t.problem = name + " is no mechanism RFC 7208 defines"
	}
	return t
}

// modifierName is ALPHA *( ALPHA / DIGIT / "-" / "_" / "." ).
func modifierName(name string) bool {
	for i, r := range name {
		alpha := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		rest := r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
		if !alpha && (i == 0 || !rest) {
			return false
		}
	}
	return name != ""
}

// domainSpec says why a domain-spec does not parse, empty where it does. A
// name with no macro in it has to be one a query can carry, ending in a top
// label that is not all digits.
func domainSpec(spec string) string {
	if spec == "" {
		return "an empty domain"
	}
	for i := 0; i < len(spec); i++ {
		if spec[i] < '!' || spec[i] > '~' {
			return spec + " is no domain a check can look up"
		}
		if spec[i] != '%' {
			continue
		}
		if i+1 == len(spec) {
			return spec + " ends in a lone %"
		}
		switch spec[i+1] {
		case '%', '_', '-':
			i++
		case '{':
			end := strings.IndexByte(spec[i:], '}')
			if end < 3 || !macro(spec[i+2:i+end]) {
				return spec + " has a macro that does not parse"
			}
			i += end
		default:
			return spec + " has a % that starts no macro"
		}
	}
	if strings.Contains(spec, "%{") {
		return ""
	}

	name := strings.TrimSuffix(spec, ".")
	labels := strings.Split(name, ".")
	top := labels[len(labels)-1]
	if len(labels) < 2 || len(name) > 253 || strings.Trim(top, "0123456789") == "" ||
		slices.ContainsFunc(labels, func(label string) bool { return label == "" || len(label) > 63 }) {
		return spec + " is no domain a check can look up"
	}
	return ""
}

// macro is what a macro holds between its braces: a letter, then digits, an r
// and delimiters, each optional (RFC 7208 7.1).
func macro(text string) bool {
	if !strings.ContainsAny(text[:1], "slodiphcrtvSLODIPHCRTV") {
		return false
	}
	rest := strings.TrimLeft(text[1:], "0123456789")
	rest = strings.TrimPrefix(strings.TrimPrefix(rest, "r"), "R")
	return strings.Trim(rest, ".-+,/_=") == ""
}

// dualCIDR checks the /n, //n or /n//n an a or an mx may end in.
func dualCIDR(cidr string) string {
	if cidr == "" {
		return ""
	}
	v4, v6, dual := strings.Cut(cidr[1:], "//")
	if after, ok := strings.CutPrefix(cidr, "//"); ok {
		v6, dual = after, true
	} else if v4 == "" || !prefixLength(v4, 32) {
		return cidr + " is no prefix length"
	}
	if dual && !prefixLength(v6, 128) {
		return cidr + " is no prefix length"
	}
	return ""
}

// network checks an ip4 or ip6 and its prefix length.
func network(mechanism, args string) string {
	text, ok := strings.CutPrefix(args, ":")
	if !ok || text == "" {
		return mechanism + " needs an address after a colon"
	}
	address, length, hasLength := strings.Cut(text, "/")
	addr, err := netip.ParseAddr(address)
	if err != nil || addr.Zone() != "" || mechanism == "ip4" != addr.Is4() {
		return address + " is no " + map[string]string{"ip4": "IPv4", "ip6": "IPv6"}[mechanism] + " address"
	}
	if hasLength && !prefixLength(length, addr.BitLen()) {
		return "/" + length + " is no prefix length for " + mechanism
	}
	return ""
}

func prefixLength(text string, most int) bool {
	n, err := strconv.Atoi(text)
	return err == nil && n >= 0 && n <= most && strconv.Itoa(n) == text
}

// unquote joins the strings of a TXT record the way a check reads them, one
// after the other with nothing between, undoing the escapes they were written
// out with.
func unquote(data string) string {
	if !strings.HasPrefix(data, `"`) {
		return data
	}
	var b strings.Builder
	quoted := false
	for i := 0; i < len(data); i++ {
		ch := data[i]
		var code byte
		var isCode bool
		if ch == '\\' && i+3 < len(data) {
			code, isCode = decimal(data[i+1 : i+4])
		}
		switch {
		case ch == '"':
			quoted = !quoted
		case !quoted:
		case isCode:
			b.WriteByte(code)
			i += 3
		case ch == '\\' && i+1 < len(data):
			b.WriteByte(data[i+1])
			i++
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// decimal reads the digits of a \DDD escape. Past 255 it is no escape, and
// the backslash quotes only the first digit.
func decimal(text string) (byte, bool) {
	n, err := strconv.ParseUint(text, 10, 8)
	return byte(n), err == nil
}

func fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func canonical(name string) string {
	return strings.ToLower(fqdn(name))
}
