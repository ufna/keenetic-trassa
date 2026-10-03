package rules

import (
	"fmt"
	"strings"
	"testing"
)

const head = "exit vpn = W\ndefault direct\n"

func problemsOf(t *testing.T, src string) []Problem {
	t.Helper()
	_, ps := Load(src, exampleRead)
	return ps
}

func hasProblem(ps []Problem, sev Severity, line int, msg string) bool {
	for _, p := range ps {
		if p.Severity == sev && p.Line == line && strings.Contains(p.Msg, msg) {
			return true
		}
	}
	return false
}

func TestLoadExampleIsClean(t *testing.T) {
	if ps := problemsOf(t, exampleSrc); len(ps) != 0 {
		t.Errorf("the specification example produced problems: %v", ps)
	}
}

func TestExpectations(t *testing.T) {
	ok := head + "foo.com -> vpn\n1.2.3.0/24 -> vpn\n" +
		"test foo.com = vpn\ntest WWW.Foo.com = vpn\ntest bar.com = direct\ntest 1.2.3.4 = vpn\ntest 8.8.8.8 = direct\n"
	if ps := problemsOf(t, ok); len(ps) != 0 {
		t.Errorf("correct expectations produced problems: %v", ps)
	}

	ps := problemsOf(t, head+"foo.com -> vpn\ntest foo.com = direct\n")
	if !hasProblem(ps, Error, 4, "expectation failed: foo.com goes to vpn (by the rule on line 3), expected direct") {
		t.Errorf("no failed-expectation error: %v", ps)
	}

	ps = problemsOf(t, head+"test bar.com = vpn\n")
	if !hasProblem(ps, Error, 3, "bar.com goes to direct (by default), expected vpn") {
		t.Errorf("no error for default: %v", ps)
	}

	ps = problemsOf(t, head+"test bad..name = direct\n")
	if !hasProblem(ps, Error, 3, "empty label") {
		t.Errorf("no error for an invalid name in test: %v", ps)
	}
}

func TestShadowedRule(t *testing.T) {
	ps := problemsOf(t, head+"google.com -> vpn\nmail.google.com -> direct\n")
	if !hasProblem(ps, Warning, 4, "can never match") || !hasProblem(ps, Warning, 4, "line 3") {
		t.Errorf("no warning about a shadowed rule: %v", ps)
	}

	ps = problemsOf(t, head+"10.0.0.0/8 -> vpn\n10.1.0.0/16 -> direct\n")
	if !hasProblem(ps, Warning, 4, "can never match") {
		t.Errorf("no warning about a shadowed subnet: %v", ps)
	}

	for _, src := range []string{
		head + "google.com !mail.google.com -> vpn\nmail.google.com -> direct\n", // the earlier rule has a negation
		head + "mail.google.com -> direct\ngoogle.com -> vpn\n",                  // narrow before broad
		head + "google.com -> vpn\nmail.google.com example.org -> direct\n",      // only some conditions are covered
		head + "~google -> vpn\nmail.google.com -> direct\n",                     // regular expressions are not judged
		head + "google.com -> vpn\n!*.ru -> vpn\n",                               // a rule with negation is not judged
	} {
		if ps := problemsOf(t, src); len(ps) != 0 {
			t.Errorf("unexpected problems for %q: %v", src, ps)
		}
	}
}

func TestStrictWarnings(t *testing.T) {
	ps := problemsOf(t, head+"!*.ru -> vpn strict\n")
	if !hasProblem(ps, Warning, 3, "strict on a negation rule") {
		t.Errorf("no warning about strict with negation: %v", ps)
	}
	ps = problemsOf(t, "exit vpn = W\ndefault vpn strict\n")
	if !hasProblem(ps, Warning, 2, "strict in default") {
		t.Errorf("no warning about strict in default: %v", ps)
	}
	if HasErrors(ps) {
		t.Errorf("warnings must not count as errors: %v", ps)
	}
	// A negation next to ordinary conditions narrows the rule rather than widening it to the whole internet.
	ps = problemsOf(t, head+"*.com !google.com -> vpn strict\n")
	if hasProblem(ps, Warning, 3, "strict on a negation rule") {
		t.Errorf("a negation among ordinary conditions must not produce a warning: %v", ps)
	}
}

func TestLoadStopsAtParseErrors(t *testing.T) {
	ps := problemsOf(t, "foo.com -> vpn\ntest foo.com = direct\n")
	for _, p := range ps {
		if strings.Contains(p.Msg, "expectation") {
			t.Errorf("expectations were checked despite parse errors: %v", ps)
		}
	}
	if !HasErrors(ps) {
		t.Error("parse errors were lost")
	}
}

func TestShadowedByNegationRule(t *testing.T) {
	ps := problemsOf(t, head+"!*.ru -> vpn\nyoutube.com -> vpn strict\n")
	if !hasProblem(ps, Warning, 4, "can never match") || !hasProblem(ps, Warning, 4, "line 3") {
		t.Errorf("no warning about a rule after a catch-all negation: %v", ps)
	}
	for _, src := range []string{
		head + "!*.com -> vpn\nyoutube.com -> direct\n",          // youtube.com is negated: the earlier rule does not take it
		head + "!mail.google.com -> vpn\ngoogle.com -> direct\n", // some names of the later rule are negated
		head + "!~^a -> vpn\nyoutube.com -> direct\n",            // regular expressions are not judged
		head + "10.0.0.0/8 -> vpn\nyoutube.com -> direct\n",      // an earlier address-only rule takes no names
	} {
		for _, p := range problemsOf(t, src) {
			if strings.Contains(p.Msg, "can never match") {
				t.Errorf("false warning for %q: %v", src, p)
			}
		}
	}
}

func TestExpectationSubjectMustBeValid(t *testing.T) {
	ps := problemsOf(t, head+"!*.ru -> vpn\ntest 149.154.167 = vpn\n")
	if !hasProblem(ps, Error, 4, "looks like an address") {
		t.Errorf("an incomplete address in test was taken for a name: %v", ps)
	}
	ps = problemsOf(t, head+"test 2001:db8::1 = direct\n")
	if !hasProblem(ps, Error, 3, "IPv6") {
		t.Errorf("an IPv6 address in test was not rejected: %v", ps)
	}
}

func TestTooManyExits(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxExits+1; i++ {
		fmt.Fprintf(&b, "exit e%d = W\n", i)
	}
	b.WriteString("default direct\n")
	ps := problemsOf(t, b.String())
	if !hasProblem(ps, Error, MaxExits+1, "at most 28") {
		t.Errorf("the thirtieth exit was not rejected: %v", ps)
	}
	ok := strings.Replace(b.String(), fmt.Sprintf("exit e%d = W\n", MaxExits), "", 1)
	if ps := problemsOf(t, ok); len(ps) != 0 {
		t.Errorf("28 exits produced problems: %v", ps)
	}
}
