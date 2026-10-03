package rules

import (
	"fmt"
	"strings"
	"testing"
)

const catchAll = `exit vpn = W
device direct_devices = 192.168.1.50
device tv = 192.168.1.40
default direct
*.ru -> direct for tv
* -> direct for direct_devices
* -> vpn for tv
youtube.com -> vpn
91.108.4.0/22 -> vpn
`

func TestCatchAllParses(t *testing.T) {
	c := devConfig(t, catchAll)
	if r := c.Rules[1]; !r.All || r.Action.Exit != Direct || fmt.Sprint(r.For) != "[direct_devices]" {
		t.Errorf("rule: %+v", r)
	}
	if c.Rules[0].All {
		t.Error("*.ru is a mask, not *")
	}
}

func TestCatchAllErrors(t *testing.T) {
	const head = "exit vpn = W\ndefault direct\n"
	wantError(t, head+"* youtube.com -> vpn\n", "the condition * stands alone")
	wantError(t, head+"* 1.2.3.0/24 -> vpn\n", "the condition * stands alone")
	wantError(t, head+"* !*.ru -> vpn\n", "the condition * stands alone")
	wantError(t, head+"!* -> vpn\n", "!* would match nothing")
}

func TestCatchAllDecisions(t *testing.T) {
	c := devConfig(t, catchAll)
	const dd, tv View = 1, 2
	cases := []struct {
		v          View
		subj, want string
		line       int
	}{
		{dd, "youtube.com", "direct", 6}, {dd, "91.108.4.7", "direct", 6}, {dd, "example.com", "direct", 6},
		{tv, "yandex.ru", "direct", 5}, {tv, "youtube.com", "vpn", 7}, {tv, "8.8.8.8", "vpn", 7},
		{dd | tv, "youtube.com", "direct", 6}, {dd | tv, "yandex.ru", "direct", 5},
		{0, "youtube.com", "vpn", 8}, {0, "91.108.4.7", "vpn", 9}, {0, "example.com", "direct", 0},
	}
	for _, k := range cases {
		_, d, err := c.MatchSubjectFor(k.v, k.subj)
		line := 0
		if d.Rule != nil {
			line = d.Rule.Line
		}
		if err != nil || d.Action.String() != k.want || line != k.line {
			t.Errorf("view %d, %s: %s (line %d, %v), want %s (line %d)", k.v, k.subj, d.Action, line, err, k.want, k.line)
		}
	}
	// A CNAME chain: no real rule before * for any name, so * decides.
	if d := c.MatchChainFor(dd, []string{"alias.example", "youtube.com"}); d.Action.Exit != Direct || d.Rule.Line != 6 {
		t.Errorf("chain for direct_devices: %+v", d)
	}
	// * is not a rule for the address memory: a name no real rule matches is not kept.
	if d := c.MatchChainAny([]string{"example.com"}); d.Rule != nil {
		t.Errorf("MatchChainAny(example.com) = line %d", d.Rule.Line)
	}
	if d := c.MatchChainAny([]string{"youtube.com"}); d.Rule == nil || d.Rule.Line != 8 {
		t.Errorf("MatchChainAny(youtube.com) = %+v", d)
	}
	if d := c.DefaultFor(dd); d.Rule == nil || d.Rule.Line != 6 {
		t.Errorf("DefaultFor(direct_devices) = %+v", d)
	}
	if d := c.DefaultFor(0); d.Rule != nil || d.Action.Exit != Direct {
		t.Errorf("DefaultFor(0) = %+v", d)
	}
	if text, _ := c.Explain("youtube.com"); !strings.Contains(text, "for direct_devices: direct (line 6)") {
		t.Errorf("explain:\n%s", text)
	}
}

func TestCatchAllShadowing(t *testing.T) {
	const head = "exit vpn = W\ndevice dd = 1.1.1.1\ndefault direct\n"
	cases := []struct {
		rules string
		warn  bool
	}{
		{"* -> direct for dd\nyoutube.com -> vpn for dd\n", true},
		{"* -> direct for dd\n91.108.4.0/22 -> vpn for dd\n", true},
		{"* -> direct for dd\nyoutube.com -> vpn\n", false},
		{"* -> vpn\nx.example -> direct\n", true},
	}
	for _, k := range cases {
		_, ps := Load(head+k.rules, nil)
		if got := strings.Contains(fmt.Sprint(ps), "can never match"); got != k.warn {
			t.Errorf("%q: warning %v, want %v (%v)", k.rules, got, k.warn, ps)
		}
	}
}

func TestCatchAllWarnings(t *testing.T) {
	const head = "exit vpn = W\ndevice kids = 1.1.1.1\ndefault direct\n"
	warn := func(rules, want string) {
		t.Helper()
		_, ps := Load(head+rules, nil)
		got := fmt.Sprint(ps)
		if want == "" && strings.Contains(got, "warning") || want != "" && !strings.Contains(got, want) {
			t.Errorf("%q: %v, want %q", rules, ps, want)
		}
	}
	warn("* -> vpn strict\n", "strict on * for every device")
	warn("* -> none\n", "* -> none for every device")
	warn("allowed.example -> direct for kids\n* -> none for kids\n", "")
	warn("* -> vpn strict for kids\n", "")
}

// Review of *: * in a file of conditions, warnings around *, and rules below a * for everyone.
func TestCatchAllInAFile(t *testing.T) {
	read := func(string) (string, error) { return "youtube.com\n*\n", nil }
	if _, ps := Parse("exit vpn = W\ndefault direct\n@lists/x.txt -> vpn\n", read); !HasErrors(ps) || !strings.Contains(fmt.Sprint(ps), "* cannot be in a file") {
		t.Errorf("* in a file: %v", ps)
	}
}

func TestCatchAllMoreWarnings(t *testing.T) {
	const head = "exit vpn = W\ndevice dd = 1.1.1.1\ndefault direct\n"
	cases := []struct{ rules, want string }{
		{"* -> direct for dd\n* -> vpn for dd\n", "can never match"},
		{"* -> vpn\n* -> direct\n", "can never match"},
		{"* -> vpn\n!*.ru -> direct\n", "can never match"},
		{"* -> none for !dd\n", "* -> none for every device"},
		{"* -> vpn strict for !dd\n", "strict on * for every device"},
	}
	for _, k := range cases {
		if _, ps := Load(head+k.rules, nil); !strings.Contains(fmt.Sprint(ps), k.want) {
			t.Errorf("%q: %v, want %q", k.rules, ps, k.want)
		}
	}
}

func TestRulesBelowAStarForEveryoneMatchNobody(t *testing.T) {
	c := devConfig(t, "exit vpn = W\ndefault direct\n* -> vpn\nx.example -> direct\n")
	if d := c.MatchChainAny([]string{"x.example"}); d.Rule != nil {
		t.Errorf("a rule below * for every device applies to nobody, yet MatchChainAny found line %d", d.Rule.Line)
	}
}
