// Package rdap asks a domain's registry what it holds about it (RFC 9083):
// when the registration runs out, its statuses, and the delegation the TLD is
// told to publish. It is best effort like the AS lookups: nothing here fails a
// resolution, and a registry that cannot be asked is said in one line.
package rdap

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rafaeljusto/dnstree/v2/internal/trace"
)

// Bootstrap is IANA's file of which RDAP service answers for which TLD
// (RFC 9224).
const Bootstrap = "https://data.iana.org/rdap/dns.json"

const (
	// maxBody bounds what one answer may be. The bootstrap file is a few
	// dozen KiB and a domain a few; nothing honest comes near it.
	maxBody = 1 << 20

	// maxRedirects bounds how far a registry may send the question on.
	maxRedirects = 3

	// maxCandidates bounds the zones asked about, shortest first, before the
	// first is taken as unregistered.
	maxCandidates = 3

	// keep is how long an answer is used again, which is what spares a
	// registry the same question from every round of --watch.
	keep = time.Hour

	// The most of each list a registry's answer is read for.
	maxStatus      = 16
	maxNameservers = 32
	maxDS          = 16
)

// Client asks registries over RDAP. One is made per run and shared by every
// walk in it.
type Client struct {
	http      *http.Client
	bootstrap string
	log       *slog.Logger

	mu       sync.Mutex
	done     chan struct{} // closed when the bootstrap fetch in flight ends
	services map[string]string
	failure  error
	cached   map[string]cached
}

type cached struct {
	reg *trace.Registration
	at  time.Time
}

// New returns a client. A nil http client uses one with a timeout, an empty
// bootstrap IANA's file, and a nil log keeps quiet. Whatever client is given,
// it is not let follow a redirect off HTTPS.
func New(client *http.Client, bootstrap string, log *slog.Logger) *Client {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	own := *client
	own.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refused a redirect off https to %s", req.URL.Redacted())
		}
		if len(via) > maxRedirects {
			return fmt.Errorf("refused more than %d redirects", maxRedirects)
		}
		return nil
	}
	if bootstrap == "" {
		bootstrap = Bootstrap
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Client{http: &own, bootstrap: bootstrap, log: log, cached: make(map[string]cached)}
}

// Prepare starts reading the bootstrap file, unless it is read or being read,
// and returns what is closed when it is. Calling it before the walk is the
// point: the file then arrives behind the walk rather than after it. A fetch
// that failed is tried again by the next walk.
func (c *Client) Prepare(ctx context.Context) <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done != nil {
		select {
		case <-c.done:
			if c.services != nil {
				return c.done
			}
		default:
			return c.done
		}
	}

	done := make(chan struct{})
	c.done = done
	go func() {
		defer close(done)
		services, err := c.readBootstrap(ctx)
		c.log.Debug("read the rdap bootstrap file", "services", len(services), "error", err)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.services, c.failure = services, err
	}()
	return done
}

// Check asks the registry about the domain the walk was delegated to below
// the TLD, and holds what it says against the referral the walk was given.
// It waits for the registry only as long as ctx allows.
func (c *Client) Check(ctx context.Context, tr *trace.Trace) *trace.Registration {
	cuts := tr.Delegated()
	var candidates []string
	for _, cut := range cuts {
		candidates = append(candidates, strings.ToLower(cut.Delegation.Zone))
	}
	// A cut can be a suffix that is nobody's registration, such as a co.uk.
	// served apart from uk., so the name one label below the deepest one is
	// asked about too. Where nothing delegated the name, that is the TLD and
	// one label.
	if next, ok := below(tr.Question.Name, candidates); ok {
		candidates = append(candidates, next)
	}
	if len(candidates) == 0 {
		return &trace.Registration{Domain: tr.Question.Name, State: trace.Unpublished,
			Why: "a top-level domain is nobody's registration"}
	}
	candidates = candidates[:min(len(candidates), maxCandidates)]

	select {
	case <-c.Prepare(ctx):
	case <-ctx.Done():
		return &trace.Registration{Domain: candidates[0], State: trace.Unreached,
			Why: "iana's rdap bootstrap file did not arrive in time"}
	}
	c.mu.Lock()
	services, failure := c.services, c.failure
	c.mu.Unlock()
	if services == nil {
		return &trace.Registration{Domain: candidates[0], State: trace.Unreached,
			Why: "could not read iana's rdap bootstrap file: " + reason(failure)}
	}

	base, tld := service(services, candidates[0])
	if base == "" {
		return &trace.Registration{Domain: candidates[0], State: trace.Unpublished,
			Why: "the registry of " + tld + " publishes no rdap service"}
	}

	var found *trace.Registration
	at := -1
	for i, domain := range candidates {
		reg := c.ask(ctx, base, domain)
		if reg.State == trace.Unregistered {
			found = cmp.Or(found, reg)
			continue
		}
		found, at = reg, i
		break
	}
	if at >= 0 && at < len(cuts) {
		compare(found, cuts[at])
	}
	return found
}

// ask fetches one domain from the registry, or the answer it gave in the last
// hour. The copy handed back is the caller's to fill in.
func (c *Client) ask(ctx context.Context, base, domain string) *trace.Registration {
	c.mu.Lock()
	hit, ok := c.cached[domain]
	c.mu.Unlock()
	if ok && time.Since(hit.at) < keep {
		return clone(hit.reg)
	}

	reg := &trace.Registration{Domain: domain, Server: base}
	if !ldh(domain) {
		reg.State, reg.Why = trace.Unregistered, "no registry holds a name written like this one"
		return reg
	}

	var answer object
	address := base + "domain/" + strings.TrimSuffix(domain, ".")
	c.log.Debug("asking a registry", "url", address)
	found, err := c.get(ctx, address, &answer)
	c.log.Debug("asked a registry", "url", address, "found", found, "error", err)
	switch {
	case err != nil && ctx.Err() != nil:
		reg.State, reg.Why = trace.Unreached, "the registry did not answer in time"
		return reg
	case err != nil:
		reg.State, reg.Why = trace.Unreached, "could not ask the registry: "+reason(err)
		return reg
	case !found:
		reg.State, reg.Why = trace.Unregistered, "the registry holds no registration for "+domain
	default:
		reg.State = trace.Registered
		answer.fill(reg)
	}

	c.mu.Lock()
	c.cached[domain] = cached{reg: clone(reg), at: time.Now()}
	c.mu.Unlock()
	return reg
}

func clone(reg *trace.Registration) *trace.Registration {
	copied := *reg
	copied.Status, copied.NS, copied.DS = slices.Clone(reg.Status), slices.Clone(reg.NS), slices.Clone(reg.DS)
	return &copied
}

// readBootstrap reads the bootstrap file into the base URL of each TLD's service.
// Only HTTPS services are kept: an answer that says when a domain runs out is
// worth nothing if anyone on the way can rewrite it.
func (c *Client) readBootstrap(ctx context.Context) (map[string]string, error) {
	var file struct {
		Services [][][]string `json:"services"`
	}
	found, err := c.get(ctx, c.bootstrap, &file)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("it is not there")
	}

	services := make(map[string]string)
	for _, entry := range file.Services {
		if len(entry) != 2 {
			continue
		}
		var base string
		for _, address := range entry[1] {
			if parsed, err := url.Parse(address); err == nil && parsed.Scheme == "https" && parsed.Host != "" {
				base = strings.TrimSuffix(address, "/") + "/"
				break
			}
		}
		if base == "" {
			continue
		}
		for _, tld := range entry[0] {
			services[strings.Trim(strings.ToLower(tld), ".")] = base
		}
	}
	return services, nil
}

// get fetches a JSON document, and reports false for a 404: the one answer
// that says something about the domain rather than the service.
func (c *Client) get(ctx context.Context, address string, into any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode != http.StatusOK:
		return false, fmt.Errorf("%s answered %s", resp.Request.URL.Host, strings.ToLower(resp.Status))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return false, err
	}
	if len(body) > maxBody {
		return false, fmt.Errorf("%s answered with more than %d MiB", resp.Request.URL.Host, maxBody>>20)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return false, fmt.Errorf("%s answered with something that is not rdap", resp.Request.URL.Host)
	}
	return true, nil
}

// reason is an error said without the URL a request error repeats, which the
// line it goes into names already.
func reason(err error) string {
	if err == nil {
		return "nothing came back"
	}
	var request *url.Error
	if errors.As(err, &request) {
		err = request.Err
	}
	return err.Error()
}

// service is the base URL of the service that answers for the domain: the one
// listed for the longest run of its last labels (RFC 9224 section 4).
func service(services map[string]string, domain string) (base, tld string) {
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for i := range labels {
		if base, ok := services[strings.Join(labels[i:], ".")]; ok {
			return base, strings.Join(labels[i:], ".") + "."
		}
	}
	return "", labels[len(labels)-1] + "."
}

// below is the name one label below the deepest of the cuts, or below its
// TLD where there are none, and false where the name goes no deeper.
func below(name string, cuts []string) (string, bool) {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	if labels[0] == "" {
		return "", false
	}
	depth := 1
	if len(cuts) > 0 {
		depth = strings.Count(cuts[len(cuts)-1], ".")
	}
	if len(labels) <= depth {
		return "", false
	}
	return strings.Join(labels[len(labels)-depth-1:], ".") + ".", true
}

// ldh reports whether a name is letters, digits and hyphens between dots,
// the only names a registry holds and the only ones that go into a URL as
// they are.
func ldh(name string) bool {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range []byte(label) {
			switch {
			case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// object is as much of an RDAP domain (RFC 9083 section 5.3) as is read.
type object struct {
	Status []string `json:"status"`
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS *struct {
		DelegationSigned bool `json:"delegationSigned"`
		DSData           []struct {
			KeyTag tag `json:"keyTag"`
		} `json:"dsData"`
	} `json:"secureDNS"`
}

// tag is a key tag, which some registries write as a string.
type tag uint16

func (t *tag) UnmarshalJSON(data []byte) error {
	n, err := strconv.ParseUint(strings.Trim(string(data), `"`), 10, 16)
	if err != nil {
		return fmt.Errorf("a key tag of %s", data)
	}
	*t = tag(n)
	return nil
}

func (o *object) fill(reg *trace.Registration) {
	for _, event := range o.Events {
		when, err := time.Parse(time.RFC3339Nano, event.Date)
		if err != nil {
			continue
		}
		switch strings.ToLower(event.Action) {
		case "expiration":
			reg.Expires = when.UTC()
		case "registration":
			reg.Registered = when.UTC()
		}
	}
	for _, status := range o.Status[:min(len(o.Status), maxStatus)] {
		if status = spaced(strings.TrimSpace(status)); status != "" && len(status) <= 64 {
			reg.Status = append(reg.Status, status)
		}
	}
	for _, ns := range o.Nameservers[:min(len(o.Nameservers), maxNameservers)] {
		if name := strings.ToLower(strings.TrimSuffix(ns.LDHName, ".")); name != "" && len(name) <= 253 {
			reg.NS = append(reg.NS, name+".")
		}
	}
	if o.SecureDNS != nil {
		reg.Signed = o.SecureDNS.DelegationSigned
		for _, ds := range o.SecureDNS.DSData[:min(len(o.SecureDNS.DSData), maxDS)] {
			reg.DS = append(reg.DS, uint16(ds.KeyTag))
		}
	}
}

// spaced is a status in the words RDAP writes it in (RFC 8056), which some
// registries leave in the EPP form it maps: clientHold is client hold.
func spaced(status string) string {
	var b strings.Builder
	for i, c := range status {
		if 'A' <= c && c <= 'Z' {
			if i > 0 && !strings.Contains(status, " ") {
				b.WriteByte(' ')
			}
			c += 'a' - 'A'
		}
		b.WriteRune(c)
	}
	return b.String()
}

// compare holds the delegation the registry holds against the referral the
// walk was handed. The DS are compared only where the walk followed the chain
// of trust, since a referral carries them only then.
func compare(reg *trace.Registration, step *trace.Step) {
	if reg.State != trace.Registered {
		return
	}
	reg.Parent = step.Zone
	parent := make([]string, 0, len(step.Delegation.NS))
	for _, ns := range step.Delegation.NS {
		parent = append(parent, strings.ToLower(ns))
	}
	reg.NSOnlyRegistry, reg.NSOnlyParent = apart(reg.NS, parent)

	if step.DNSSEC == nil {
		return
	}
	reg.DSChecked = true
	var held []uint16
	for _, ds := range step.DNSSEC.DS {
		held = append(held, ds.Tag)
	}
	if len(held) > 0 && len(reg.DS) > 0 {
		reg.DSOnlyRegistry, reg.DSOnlyParent = apart(reg.DS, held)
		return
	}
	reg.DSDiffer = (step.Delegation.DSPresent || len(held) > 0) != (reg.Signed || len(reg.DS) > 0)
}

// apart is what each list has that the other does not, in the order given.
func apart[T comparable](a, b []T) (onlyA, onlyB []T) {
	for _, x := range a {
		if !slices.Contains(b, x) && !slices.Contains(onlyA, x) {
			onlyA = append(onlyA, x)
		}
	}
	for _, x := range b {
		if !slices.Contains(a, x) && !slices.Contains(onlyB, x) {
			onlyB = append(onlyB, x)
		}
	}
	return onlyA, onlyB
}
