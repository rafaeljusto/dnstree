// Package dnssec validates the chain of trust one zone cut at a time: DS from
// the parent, DNSKEY from the child, then the signatures over the answer.
package dnssec
