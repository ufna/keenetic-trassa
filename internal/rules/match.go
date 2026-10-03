package rules

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Decision is the result of matching. Rule == nil means the default applied;
// Index is then the number of rules, i.e. lower in precedence than any rule.
type Decision struct {
	Index  int
	Rule   *Rule
	Action Action
}

func (c *Config) defaultDecision() Decision {
	return Decision{Index: len(c.Rules), Action: c.Default}
}

func (r *Rule) matchName(name string) bool {
	if len(r.Pos) == 0 && len(r.Neg) == 0 {
		return false
	}
	ok := len(r.Pos) == 0
	for _, c := range r.Pos {
		if c.Match(name) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	for _, c := range r.Neg {
		if c.Match(name) {
			return false
		}
	}
	return true
}

// Explain explains, from the rules alone and without DNS data, where a name, address or link will go.
func (c *Config) Explain(subject string) (string, error) {
	subj, d, err := c.MatchSubject(subject)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s → %s\n", subj, d.Action)
	if d.Rule != nil {
		fmt.Fprintf(&b, "rule, line %d: %s\n", d.Rule.Line, d.Rule.Text)
	} else {
		fmt.Fprintf(&b, "no rule matched; default applies (line %d)\n", c.DefaultLine)
	}
	if e, found := c.Exit(d.Action.Exit); found {
		fmt.Fprintf(&b, "exit %s: %s\n", e.Name, strings.Join(e.Interfaces, ", "))
	} else {
		b.WriteString("exit direct: straight through the ISP\n")
	}
	b.WriteString(c.DeviceLines(subject, c.ListViews()))
	return b.String(), nil
}

// firstName finds the first rule matching the name among the rules applying to view v, or among
// all rules if all is set.
func (c *Config) firstName(v View, all bool, name string) Decision {
	for i := range c.Rules {
		r := &c.Rules[i]
		if (all || r.AppliesTo(v)) && r.matchName(name) {
			return Decision{Index: i, Rule: r, Action: r.Action}
		}
	}
	return c.defaultDecision()
}

// MatchNameFor finds the first rule matching the name for a device whose lists are v.
// The name must be normalized with NormalizeName.
func (c *Config) MatchNameFor(v View, name string) Decision { return c.firstName(v, false, name) }

// MatchName is MatchNameFor for a device in no list.
func (c *Config) MatchName(name string) Decision { return c.MatchNameFor(0, name) }

// MatchAddrFor finds the first rule applying to view v whose addresses and subnets contain a.
func (c *Config) MatchAddrFor(v View, a netip.Addr) Decision {
	for i := range c.Rules {
		r := &c.Rules[i]
		if !r.AppliesTo(v) {
			continue
		}
		for _, n := range r.Nets {
			if n.Contains(a) {
				return Decision{Index: i, Rule: r, Action: r.Action}
			}
		}
	}
	return c.defaultDecision()
}

// MatchAddr is MatchAddrFor for a device in no list.
func (c *Config) MatchAddr(a netip.Addr) Decision { return c.MatchAddrFor(0, a) }

// subject normalizes whatever a person typed: an address (returned valid) or a domain name. An
// incomplete address or IPv6 is an error, not a name: otherwise the answer would be plausible but wrong.
func subject(s string) (string, netip.Addr, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return "", netip.Addr{}, fmt.Errorf("%q: could not take a domain from the link", s)
		}
		s = u.Hostname()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if !a.Is4() {
			return "", netip.Addr{}, fmt.Errorf("address %s: IPv6 is not supported yet", s)
		}
		return a.String(), a, nil
	}
	if looksNumeric(s) {
		return "", netip.Addr{}, fmt.Errorf("%q looks like an address but is malformed", s)
	}
	name, err := NormalizeName(s)
	if err != nil {
		return "", netip.Addr{}, err
	}
	return name, netip.Addr{}, nil
}

// MatchSubjectFor decides what happens, for a device whose lists are v, to whatever a person typed,
// an address or a name, and returns its normalized form.
func (c *Config) MatchSubjectFor(v View, s string) (string, Decision, error) {
	subj, a, err := subject(s)
	if err != nil {
		return "", Decision{}, err
	}
	if a.IsValid() {
		return subj, c.MatchAddrFor(v, a), nil
	}
	return subj, c.MatchNameFor(v, subj), nil
}

// MatchSubject is MatchSubjectFor for a device in no list.
func (c *Config) MatchSubject(s string) (string, Decision, error) { return c.MatchSubjectFor(0, s) }

func (c *Config) matchChain(v View, all bool, names []string) Decision {
	for _, n := range names {
		if d := c.firstName(v, all, n); d.Rule != nil {
			return d
		}
	}
	return c.defaultDecision()
}

// MatchChainFor decides what happens to a DNS response for a device whose lists are v: names are
// the queried name and its CNAME targets in order. The first name in the chain that has a matching
// rule wins.
func (c *Config) MatchChainFor(v View, names []string) Decision { return c.matchChain(v, false, names) }

// MatchChain is MatchChainFor for a device in no list.
func (c *Config) MatchChain(names []string) Decision { return c.MatchChainFor(0, names) }

// MatchChainAny is MatchChain over all rules, "for" ignored: the earliest rule matching the chain
// for some device. The address memory keeps an answer if any device may need it.
func (c *Config) MatchChainAny(names []string) Decision { return c.matchChain(0, true, names) }

// DeviceLines lists the views whose decision for the subject differs from that of a device in no
// list, one line each: "for tv: vpn (line 7)". Empty if none differs or the subject is malformed.
func (c *Config) DeviceLines(subject string, views []View) string {
	_, common, err := c.MatchSubjectFor(0, subject)
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, v := range views {
		if v == 0 {
			continue
		}
		_, d, _ := c.MatchSubjectFor(v, subject)
		if d.Action == common.Action {
			continue
		}
		where := "default"
		if d.Rule != nil {
			where = fmt.Sprintf("line %d", d.Rule.Line)
		}
		fmt.Fprintf(&b, "for %s: %s (%s)\n", c.ViewName(v), d.Action, where)
	}
	return b.String()
}

// ListViews returns the views of the single device lists, in declaration order: what "why" shows
// without the daemon, which knows nothing of which device is in which lists.
func (c *Config) ListViews() []View {
	var out []View
	for i := range c.Devices {
		if i < MaxDeviceLists {
			out = append(out, 1<<i)
		}
	}
	return out
}
