// Package idn turns a name typed in any script into the one the DNS holds.
package idn

import (
	"fmt"

	"golang.org/x/net/idna"
)

// lookup lets underscores through, since _25._tcp and _dmarc labels are names
// a walk is asked about as often as any.
var lookup = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(false))

// ASCII is name in punycode. A name that is ASCII already is returned as it
// was given, case and all: it is what somebody asked for, and the codec is
// left to judge it.
func ASCII(name string) (string, error) {
	for i := range len(name) {
		if name[i] >= 0x80 {
			converted, err := lookup.ToASCII(name)
			if err != nil {
				return "", fmt.Errorf("%q cannot be written in punycode", name)
			}
			return converted, nil
		}
	}
	return name, nil
}
