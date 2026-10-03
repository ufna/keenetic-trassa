package rules

import (
	"net/netip"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Config {
	t.Helper()
	cfg, ps := Parse(src, exampleRead)
	if len(ps) != 0 {
		t.Fatalf("parse problems: %v", ps)
	}
	return cfg
}

func norm(t *testing.T, s string) string {
	t.Helper()
	n, err := NormalizeName(s)
	if err != nil {
		t.Fatalf("NormalizeName(%q): %v", s, err)
	}
	return n
}

func TestMatchName(t *testing.T) {
	cfg := mustParse(t, exampleSrc)
	cases := []struct {
		name string
		line int // 0 means default
		want string
	}{
		{"youtube.com", 5, "vpn strict"},
		{"www.youtube.com", 5, "vpn strict"},
		{"yOuTuBe.CoM.", 5, "vpn strict"},
		{"rr3---sn-4g5ednsd.googlevideo.com", 5, "vpn strict"},
		{"t.me", 6, "vpn"},
		{"yandex.ru", 8, "direct"},
		{"mail.yandex.ru", 8, "direct"},
		{"example.com", 9, "vpn"},
		{"notyoutube.com", 9, "vpn"},
	}
	for _, c := range cases {
		d := cfg.MatchName(norm(t, c.name))
		line := 0
		if d.Rule != nil {
			line = d.Rule.Line
		}
		if line != c.line || d.Action.String() != c.want {
			t.Errorf("%s: line %d, %s; expected line %d, %s", c.name, line, d.Action, c.line, c.want)
		}
	}
}

func TestMatchDefault(t *testing.T) {
	cfg := mustParse(t, "exit vpn = W\ndefault direct\nx.com -> vpn\n10.0.0.0/8 -> vpn\n")
	d := cfg.MatchName("yandex.com")
	if d.Rule != nil || d.Index != len(cfg.Rules) || d.Action.Exit != Direct {
		t.Errorf("yandex.com: %+v, expected default", d)
	}
	if d := cfg.MatchName("a.x.com"); d.Rule == nil || d.Index != 0 {
		t.Errorf("a.x.com: %+v, expected rule 0", d)
	}
}

func TestMatchNegation(t *testing.T) {
	cfg := mustParse(t, "exit vpn = W\ndefault direct\ngoogle.com !mail.google.com !*.corp.google.com -> vpn\n")
	cases := map[string]string{
		"google.com":        "vpn",
		"www.google.com":    "vpn",
		"mail.google.com":   "direct",
		"a.mail.google.com": "direct",
		"x.corp.google.com": "direct",
		"corp.google.com":   "vpn",
		"example.com":       "direct",
	}
	for name, want := range cases {
		if got := cfg.MatchName(name).Action.Exit; got != want {
			t.Errorf("%s → %s, expected %s", name, got, want)
		}
	}
}

func TestMatchOrder(t *testing.T) {
	cfg := mustParse(t, "exit a = W\nexit b = W\ndefault direct\nmail.google.com -> a\ngoogle.com -> b\n")
	if got := cfg.MatchName("mail.google.com").Action.Exit; got != "a" {
		t.Errorf("mail.google.com → %s, expected a", got)
	}
	if got := cfg.MatchName("www.google.com").Action.Exit; got != "b" {
		t.Errorf("www.google.com → %s, expected b", got)
	}
}

func TestMatchAddr(t *testing.T) {
	cfg := mustParse(t, exampleSrc)
	cases := map[string]int{ // address → rule line, 0 means default
		"149.154.167.50": 7,
		"91.108.56.1":    6,
		"91.108.4.200":   7,
		"8.8.8.8":        0,
	}
	for addr, wantLine := range cases {
		d := cfg.MatchAddr(netip.MustParseAddr(addr))
		line := 0
		if d.Rule != nil {
			line = d.Rule.Line
		}
		if line != wantLine {
			t.Errorf("%s: line %d, expected %d", addr, line, wantLine)
		}
	}
}

func TestAddrOnlyRuleIgnoresNames(t *testing.T) {
	cfg := mustParse(t, "exit vpn = W\ndefault direct\n10.0.0.0/8 -> vpn\n")
	if d := cfg.MatchName("anything.example"); d.Rule != nil {
		t.Errorf("an address-only rule matched a name: %+v", d)
	}
}

func TestMatchChain(t *testing.T) {
	cfg := mustParse(t, "exit vpn = W\ndefault direct\nl.google.com -> vpn\n")
	d := cfg.MatchChain([]string{"www.example.org", "wide-youtube.l.google.com"})
	if d.Rule == nil || d.Action.Exit != "vpn" {
		t.Errorf("chain with CNAME: %+v, expected vpn", d)
	}
	if d := cfg.MatchChain([]string{"www.example.org", "cdn.example.net"}); d.Rule != nil {
		t.Errorf("chain without matches: %+v, expected default", d)
	}
	if d := cfg.MatchChain(nil); d.Rule != nil || d.Action.Exit != Direct {
		t.Errorf("empty chain: %+v, expected default", d)
	}
}

func TestMatchCyrillic(t *testing.T) {
	cfg := mustParse(t, "exit vpn = W\ndefault vpn\n*.рф -> direct\n")
	for _, name := range []string{"сайт.рф", "САЙТ.РФ", "xn--80aswg.xn--p1ai"} {
		if got := cfg.MatchName(norm(t, name)).Action.Exit; got != Direct {
			t.Errorf("%s → %s, expected direct", name, got)
		}
	}
	if got := cfg.MatchName("example.com").Action.Exit; got != "vpn" {
		t.Errorf("example.com → %s, expected vpn", got)
	}
}

func TestMatchSubjectAcceptsLinks(t *testing.T) {
	c := mustParse(t, exampleSrc)
	subj, d, err := c.MatchSubject("https://WWW.YouTube.com/watch?v=1")
	if err != nil || subj != "www.youtube.com" || d.Action.Exit != "vpn" {
		t.Errorf("link to a name: %q, %+v, %v", subj, d.Action, err)
	}
	subj, d, err = c.MatchSubject("https://149.154.167.50:443/")
	if err != nil || subj != "149.154.167.50" || d.Rule == nil || d.Rule.Line != 7 {
		t.Errorf("link to an address: %q, %+v, %v", subj, d, err)
	}
	if _, _, err := c.MatchSubject("https:///path"); err == nil {
		t.Error("a link without a domain must be an error")
	}
}

func TestExplain(t *testing.T) {
	c := mustParse(t, exampleSrc)
	cases := map[string]string{
		"www.youtube.com": "www.youtube.com → vpn strict\nrule, line 5: youtube.com googlevideo.com ytimg.com -> vpn strict\nexit vpn: Wireguard2, Wireguard0, Wireguard3\n",
		"ya.ru":           "ya.ru → direct\nrule, line 8: *.ru *.рф *.su -> direct\nexit direct: straight through the ISP\n",
		"8.8.8.8":         "8.8.8.8 → direct\nno rule matched; default applies (line 3)\nexit direct: straight through the ISP\n",
	}
	for subj, want := range cases {
		if got, err := c.Explain(subj); err != nil || got != want {
			t.Errorf("Explain(%q) = %q, %v\nexpected %q", subj, got, err, want)
		}
	}
	if _, err := c.Explain("149.154"); err == nil || !strings.Contains(err.Error(), "looks like an address") {
		t.Errorf("incomplete address: %v", err)
	}
}
