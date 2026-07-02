package ldapserver

import (
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// filterKind mirrors the (deliberately small) subset of RFC 4515 filter
// grammar this server supports: equality, AND, OR, and attribute-present.
// Substrings/ordering/approx/extensible matches are explicitly rejected with
// a clear "unsupported filter" result rather than silently mismatching.
type filterKind int

const (
	filterAnd filterKind = iota
	filterOr
	filterEquality
	filterPresent
)

type filterNode struct {
	kind     filterKind
	attr     string
	value    string
	children []*filterNode
}

// ErrUnsupportedFilter is returned for filter types outside the supported subset.
var ErrUnsupportedFilter = fmt.Errorf("unsupported filter type")

func parseFilter(p *ber.Packet) (*filterNode, error) {
	switch p.Tag {
	case 0: // and
		return parseSet(p, filterAnd)
	case 1: // or
		return parseSet(p, filterOr)
	case 3: // equalityMatch
		if len(p.Children) != 2 {
			return nil, fmt.Errorf("malformed equality filter")
		}
		attr, _ := p.Children[0].Value.(string)
		val := string(p.Children[1].ByteValue)
		return &filterNode{kind: filterEquality, attr: strings.ToLower(attr), value: val}, nil
	case 7: // present
		attr := p.Data.String()
		return &filterNode{kind: filterPresent, attr: strings.ToLower(attr)}, nil
	default:
		return nil, ErrUnsupportedFilter
	}
}

func parseSet(p *ber.Packet, kind filterKind) (*filterNode, error) {
	node := &filterNode{kind: kind}
	for _, child := range p.Children {
		sub, err := parseFilter(child)
		if err != nil {
			return nil, err
		}
		node.children = append(node.children, sub)
	}
	return node, nil
}

// matches evaluates the filter against an entry's attributes (name -> values,
// case-insensitive attribute names, case-insensitive value comparison).
func (f *filterNode) matches(attrs []Attribute) bool {
	switch f.kind {
	case filterAnd:
		for _, c := range f.children {
			if !c.matches(attrs) {
				return false
			}
		}
		return true
	case filterOr:
		for _, c := range f.children {
			if c.matches(attrs) {
				return true
			}
		}
		return false
	case filterPresent:
		return attrValues(attrs, f.attr) != nil
	case filterEquality:
		for _, v := range attrValues(attrs, f.attr) {
			if strings.EqualFold(v, f.value) {
				return true
			}
		}
		return false
	}
	return false
}

func attrValues(attrs []Attribute, name string) []string {
	for _, a := range attrs {
		if strings.EqualFold(a.Name, name) {
			return a.Values
		}
	}
	return nil
}
