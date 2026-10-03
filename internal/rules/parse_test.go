package rules

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The example from the specification; tests in other files of the package use it too.
const exampleSrc = `# example from the specification
exit vpn = Wireguard2, Wireguard0, Wireguard3
default direct

youtube.com googlevideo.com ytimg.com -> vpn strict
@lists/telegram.txt -> vpn
149.154.160.0/20 91.108.4.0/22 -> vpn
*.ru *.рф *.su -> direct
!*.ru -> vpn
`

func exampleRead(path string) (string, error) {
	if path == "lists/telegram.txt" {
		return "telegram.org\nt.me # short links\n\n91.108.56.0/22\n", nil
	}
	return "", errors.New("no such file")
}

func summary(c *Config) string {
	var b strings.Builder
	for _, e := range c.Exits {
		fmt.Fprintf(&b, "exit %s=%v\n", e.Name, e.Interfaces)
	}
	fmt.Fprintf(&b, "default %s\n", c.Default)
	for _, r := range c.Rules {
		fmt.Fprintf(&b, "%d:", r.Line)
		for _, x := range r.Pos {
			b.WriteString(" " + x.Text)
		}
		for _, x := range r.Neg {
			b.WriteString(" " + x.Text)
		}
		for _, n := range r.Nets {
			b.WriteString(" " + n.String())
		}
		fmt.Fprintf(&b, " -> %s\n", r.Action)
	}
	return b.String()
}

const exampleSummary = `exit vpn=[Wireguard2 Wireguard0 Wireguard3]
default direct
5: youtube.com googlevideo.com ytimg.com -> vpn strict
6: telegram.org t.me 91.108.56.0/22 -> vpn
7: 149.154.160.0/20 91.108.4.0/22 -> vpn
8: *.ru *.рф *.su -> direct
9: !*.ru -> vpn
`

func TestParseExample(t *testing.T) {
	cfg, ps := Parse(exampleSrc, exampleRead)
	if len(ps) != 0 {
		t.Fatalf("unexpected problems: %v", ps)
	}
	if got := summary(cfg); got != exampleSummary {
		t.Errorf("parsed:\n%s\nexpected:\n%s", got, exampleSummary)
	}
	if cfg.DefaultLine != 3 {
		t.Errorf("DefaultLine = %d, expected 3", cfg.DefaultLine)
	}
	if e, ok := cfg.Exit("vpn"); !ok || e.Line != 2 {
		t.Errorf("Exit(vpn) = %+v, %v", e, ok)
	}
	if _, ok := cfg.Exit("nope"); ok {
		t.Error("Exit(nope) was found")
	}
}

func TestParseTolerant(t *testing.T) {
	src := "\uFEFF" + strings.ReplaceAll(strings.ReplaceAll(exampleSrc, " -> ", "\t->\t"), "\n", "\r\n")
	cfg, ps := Parse(src, exampleRead)
	if len(ps) != 0 {
		t.Fatalf("unexpected problems: %v", ps)
	}
	if got := summary(cfg); got != exampleSummary {
		t.Errorf("parsed:\n%s\nexpected:\n%s", got, exampleSummary)
	}
}

func TestParseTests(t *testing.T) {
	cfg, ps := Parse("exit vpn = W\ndefault direct\ntest yandex.ru = direct\ntest 1.2.3.4 = vpn\n", nil)
	if len(ps) != 0 {
		t.Fatalf("unexpected problems: %v", ps)
	}
	want := []Test{{3, "yandex.ru", "direct"}, {4, "1.2.3.4", "vpn"}}
	if len(cfg.Tests) != 2 || cfg.Tests[0] != want[0] || cfg.Tests[1] != want[1] {
		t.Errorf("Tests = %+v, expected %+v", cfg.Tests, want)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		src  string
		line int
		msg  string
	}{
		{"exit vpn = W\nfoo.com -> vpn\n", 0, "no default line"},
		{"default direct\nfoo.com -> vpn\n", 2, "is not declared"},
		{"default direct\nfoo.com vpn\n", 2, "cannot parse the line"},
		{"default direct\n-> direct\n", 2, "no conditions"},
		{"default direct\nfoo.com -> direct strict\n", 2, "strict makes no sense"},
		{"default direct\nfoo.com -> direct extra\n", 2, "expected an exit"},
		{"default direct\ndefault direct\n", 2, "already set"},
		{"exit direct = W\ndefault direct\n", 1, "is reserved"},
		{"exit vpn = W\nexit vpn = W\ndefault direct\n", 2, "already declared"},
		{"exit vpn =\ndefault direct\n", 1, "empty interface name"},
		{"exit Bad Name = W\ndefault direct\n", 1, "exit name"},
		{"default direct\n10.0.0.0/33 -> direct\n", 2, "malformed"},
		{"default direct\n0.0.0.0/0 -> direct\n", 2, "use default"},
		{"default direct\n!10.0.0.0/8 -> direct\n", 2, "negating addresses"},
		{"default direct\n2001:db8::1 -> direct\n", 2, "IPv6"},
		{"default direct\n1.2.3 -> direct\n", 2, "looks like an address"},
		{"default direct\n~( -> direct\n", 2, "regular expression"},
		{"default direct\nfoo.*.com -> direct\n", 2, "asterisk"},
		{"default direct\n@nofile -> direct\n", 2, "nofile"},
		{"default direct\n@ -> direct\n", 2, "file path is needed"},
		{"default direct\ntest foo.com\n", 2, "expected: test"},
		{"default direct\ntest foo.com = nowhere\n", 2, "is not declared"},
	}
	for _, c := range cases {
		_, ps := Parse(c.src, exampleRead)
		found := false
		for _, p := range ps {
			if p.Severity == Error && p.Line == c.line && strings.Contains(p.Msg, c.msg) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: no error on line %d with text %q; got: %v", c.src, c.line, c.msg, ps)
		}
	}
}

func TestParseIncludeProblems(t *testing.T) {
	read := func(path string) (string, error) {
		switch path {
		case "empty":
			return "# comment only\n\n", nil
		case "nested":
			return "foo.com\n@other\n", nil
		case "bad":
			return "foo.com\nbar..com\n", nil
		}
		return "", errors.New("no such file")
	}
	cases := []struct{ file, msg string }{
		{"empty", "is empty"},
		{"nested", "line 2: nested includes"},
		{"bad", "line 2"},
	}
	for _, c := range cases {
		_, ps := Parse("default direct\n@"+c.file+" -> direct\n", read)
		if !HasErrors(ps) || !strings.Contains(ps[0].Msg, c.msg) {
			t.Errorf("@%s: expected an error with text %q, got %v", c.file, c.msg, ps)
		}
	}
	if _, ps := Parse("default direct\n@x -> direct\n", nil); !HasErrors(ps) {
		t.Error("an include without a read function must be an error")
	}
}

func TestProblemString(t *testing.T) {
	if got := (Problem{7, Error, "bad"}).String(); got != "line 7: error: bad" {
		t.Errorf("got %q", got)
	}
	if got := (Problem{0, Warning, "so-so"}).String(); got != "warning: so-so" {
		t.Errorf("got %q", got)
	}
}

func TestParseRejectsNonUTF8(t *testing.T) {
	// "*.рф" saved in Windows-1251.
	_, ps := Parse("exit vpn = W\ndefault direct\n*.\xf0\xf4 -> vpn\n", nil)
	if !HasErrors(ps) || !strings.Contains(ps[0].Msg, "UTF-8") {
		t.Errorf("a non-UTF-8 file was accepted: %v", ps)
	}
	read := func(string) (string, error) { return "\xf0\xf4\n", nil }
	_, ps = Parse("default direct\n@x -> direct\n", read)
	if !HasErrors(ps) || !strings.Contains(ps[0].Msg, "UTF-8") {
		t.Errorf("a non-UTF-8 included file was accepted: %v", ps)
	}
}

func TestParseMisplacedWords(t *testing.T) {
	cases := []struct{ rule, msg string }{
		{"youtube.com strict -> vpn", "strict"},
		{"youtube.com direct -> vpn", "direct"},
		{"youtube.com vpn -> direct", "exit name"},
		{"!vpn -> direct", "exit name"},
	}
	for _, c := range cases {
		_, ps := Parse("exit vpn = W\ndefault direct\n"+c.rule+"\n", nil)
		found := false
		for _, p := range ps {
			if p.Severity == Error && p.Line == 3 && strings.Contains(p.Msg, c.msg) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: no error with text %q; got %v", c.rule, c.msg, ps)
		}
	}
}

func TestParseInterfaceNames(t *testing.T) {
	for _, bad := range []string{"W;reboot", "$(x)", "a=b", "W'x", "W`x`", "Вайргард"} {
		_, ps := Parse("exit vpn = "+bad+"\ndefault direct\n", nil)
		if !HasErrors(ps) || ps[0].Line != 1 || !strings.Contains(ps[0].Msg, "interface") {
			t.Errorf("interface name %q was accepted: %v", bad, ps)
		}
	}
	if _, ps := Parse("exit vpn = GigabitEthernet0/Vlan1, Wireguard2, ISP-2_a.b\ndefault direct\n", nil); len(ps) != 0 {
		t.Errorf("ordinary interface names were rejected: %v", ps)
	}
}

func TestParseLinks(t *testing.T) {
	_, ps := Parse("exit vpn = W\ndefault direct\nhttps://www.youtube.com/watch?v=1 -> vpn\n!http://mail.ru -> vpn\n", nil)
	want := []string{
		`line 3: error: condition "https://www.youtube.com/watch?v=1" is a link, but a domain is needed: www.youtube.com`,
		`line 4: error: condition "http://mail.ru" is a link, but a domain is needed: mail.ru`,
	}
	if len(ps) != len(want) {
		t.Fatalf("problems: %v", ps)
	}
	for i, w := range want {
		if ps[i].String() != w {
			t.Errorf("got %q, expected %q", ps[i].String(), w)
		}
	}
}
