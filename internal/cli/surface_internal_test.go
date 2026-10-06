package cli

import (
	"flag"
	"io"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// notWalkFlags are the flags that say how a walk is drawn, read or kept, rather
// than how it is made. Every flag is in this list or in walkFlags, so a new
// one has to be put in one of them.
var notWalkFlags = []string{
	"x", "names", "format", "web-addr", "no-browser", "live", "watch", "explain",
	"propagation", "diff", "expect", "from", "against", "pcap", "color",
	"config", "no-config", "debug", "schema", "version",
}

// defined are the flags Parse defines, in the order it defines them. It swaps
// testHookFlags, which is safe only while no test in this package runs in
// parallel.
func defined(t *testing.T) []string {
	t.Helper()
	var names []string
	testHookFlags = func(flags *flag.FlagSet) {
		flags.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	}
	defer func() { testHookFlags = func(*flag.FlagSet) {} }()
	_, _ = Parse([]string{"--version", "--no-config"}, io.Discard)
	if len(names) == 0 {
		t.Fatal("got no flags, want the ones Parse defines")
	}
	return names
}

// TestFlagsInUsage covers the surface a new flag has to reach: the usage says
// what it does, and it is sorted into the flags that shape a walk or not.
func TestFlagsInUsage(t *testing.T) {
	for _, name := range defined(t) {
		if name != "asn-resolver" { // the older name, kept working and left unsaid
			written := regexp.MustCompile(`(^|[\s,\[])` + regexp.QuoteMeta(dashed(name)) + `([\s,=\]]|$)`)
			if !written.MatchString(Usage) {
				t.Errorf("%s is not in the usage", dashed(name))
			}
		}
		if walkFlags[name] == slices.Contains(notWalkFlags, name) {
			t.Errorf("%s is in walkFlags and notWalkFlags both, or in neither", dashed(name))
		}
	}
}

// TestListsNameFlags covers the lists that name flags by hand, where a flag
// renamed or dropped would be passed over without a word.
func TestListsNameFlags(t *testing.T) {
	names := defined(t)
	var listed []string
	for name := range walkFlags {
		listed = append(listed, name)
	}
	listed = append(listed, askedFor...)
	listed = append(listed, notWalkFlags...)
	for _, group := range groups {
		listed = append(listed, group...)
	}
	for _, name := range listed {
		if !slices.Contains(names, name) {
			t.Errorf("%s is listed, and is not a flag", dashed(name))
		}
	}
}

// TestFormatsInUsage covers the sentence in the usage that lists the formats.
func TestFormatsInUsage(t *testing.T) {
	_, list, ok := strings.Cut(Usage, "FORMAT is one of ")
	if !ok {
		t.Fatal("got no list of formats in the usage")
	}
	list, _, _ = strings.Cut(list, ".\n")
	list = strings.NewReplacer(" (the default)", "", " or ", ", ", "\n", " ").Replace(list)
	if got, want := strings.Split(list, ", "), formatNames(nil); !slices.Equal(got, want) {
		t.Errorf("got %q in the usage, want %q", got, want)
	}
}
