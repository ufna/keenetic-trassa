package rules

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type condKind int

const (
	condSuffix condKind = iota // the domain and all its subdomains
	condExact                  // the exact name only
	condSub                    // subdomains only
	condRegex
)

// Cond is a single name condition.
type Cond struct {
	Text string // the condition as written in the rules file
	kind condKind
	name string
	re   *regexp.Regexp
}

// parseCond parses a condition without the leading "!".
func parseCond(tok string) (Cond, error) {
	c := Cond{Text: tok}
	if strings.HasPrefix(tok, "~") {
		if tok == "~" {
			return c, errors.New("empty regular expression")
		}
		for _, r := range tok {
			if r >= 0x80 {
				return c, fmt.Errorf("regular expression %q: names are compared in xn--… form, so the character U+%04X will never match", tok[1:], r)
			}
		}
		// Names are lowercased, so the expression is matched case-insensitively.
		re, err := regexp.Compile("(?i)" + tok[1:])
		if err != nil {
			return c, fmt.Errorf("regular expression %q: %v", tok[1:], err)
		}
		c.kind, c.re = condRegex, re
		return c, nil
	}
	name := tok
	switch {
	case strings.HasPrefix(tok, "="):
		c.kind, name = condExact, tok[1:]
	case strings.HasPrefix(tok, "*."):
		c.kind, name = condSub, tok[2:]
	default:
		c.kind = condSuffix
	}
	if strings.Contains(name, "*") {
		return c, fmt.Errorf("condition %q: an asterisk is allowed only at the start, as in *.example.com", tok)
	}
	if looksNumeric(name) {
		return c, fmt.Errorf("condition %q looks like an address: addresses and subnets are written without =, *. and !", tok)
	}
	n, err := NormalizeName(name)
	if err != nil {
		return c, fmt.Errorf("condition %q: %w", tok, err)
	}
	c.name = n
	return c, nil
}

// Match reports whether the name matches the condition. The name must be normalized with NormalizeName.
func (c Cond) Match(name string) bool {
	switch c.kind {
	case condExact:
		return name == c.name
	case condSuffix:
		return name == c.name || strings.HasSuffix(name, "."+c.name)
	case condSub:
		return strings.HasSuffix(name, "."+c.name)
	case condRegex:
		return c.re.MatchString(name)
	}
	return false
}

// disjoint reports that no name matches both conditions at once.
// The check is conservative: for regular expressions the answer is always "no".
func (a Cond) disjoint(b Cond) bool {
	if a.kind == condRegex || b.kind == condRegex {
		return false
	}
	return a.name != b.name && !strings.HasSuffix(a.name, "."+b.name) && !strings.HasSuffix(b.name, "."+a.name)
}

// covers reports that every name matching b also matches a.
// For regular expressions the answer is always "no": the check is deliberately conservative.
func (a Cond) covers(b Cond) bool {
	if a.kind == condRegex || b.kind == condRegex {
		return false
	}
	same := a.name == b.name
	under := strings.HasSuffix(b.name, "."+a.name)
	switch a.kind {
	case condSuffix:
		return same || under
	case condExact:
		return b.kind == condExact && same
	case condSub:
		if b.kind == condSub {
			return same || under
		}
		return under
	}
	return false
}
