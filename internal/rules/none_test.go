package rules

import (
	"fmt"
	"strings"
	"testing"
)

func TestNone(t *testing.T) {
	c := devConfig(t, `exit vpn = W
device kids = 192.168.1.70
default direct
*.io -> none
tiktok.example -> none for kids
1.2.3.0/24 -> none
test x.io = none
`)
	cases := []struct {
		v          View
		subj, want string
	}{
		{0, "github.io", "none"}, {0, "tiktok.example", "direct"}, {1, "tiktok.example", "none"}, {0, "1.2.3.4", "none"},
	}
	for _, k := range cases {
		if _, d, err := c.MatchSubjectFor(k.v, k.subj); err != nil || d.Action.String() != k.want {
			t.Errorf("view %d, %s: %v (%v), want %s", k.v, k.subj, d.Action, err, k.want)
		}
	}
	text, err := c.Explain("x.io")
	if err != nil || !strings.Contains(text, "x.io → none") || !strings.Contains(text, "blocked: new connections are refused") {
		t.Errorf("explain: %v\n%s", err, text)
	}
	if !c.UsesNone() || devConfig(t, "exit vpn = W\ndefault direct\nx.example -> vpn\n").UsesNone() {
		t.Error("UsesNone")
	}
}

func TestNoneProblems(t *testing.T) {
	errs := []struct{ src, want string }{
		{"exit none = W\ndefault direct\n", `name "none" is reserved`},
		{"default direct\nx.example -> none strict\n", "strict makes no sense for none"},
		{"default direct\nnone -> direct\n", `the word "none" is among the conditions`},
	}
	for _, k := range errs {
		if _, ps := Load(k.src, nil); !HasErrors(ps) || !strings.Contains(fmt.Sprint(ps), k.want) {
			t.Errorf("%q: %v, want %q", k.src, ps, k.want)
		}
	}
	warns := []struct{ src, want string }{
		{"default none\nx.example -> direct\n", "default none: everything that matches no rule is blocked"},
		{"default direct\n!*.ru -> none\n", "none on a negation rule"},
	}
	for _, k := range warns {
		_, ps := Load(k.src, nil)
		if HasErrors(ps) || !strings.Contains(fmt.Sprint(ps), k.want) {
			t.Errorf("%q: %v, want warning %q", k.src, ps, k.want)
		}
	}
}
