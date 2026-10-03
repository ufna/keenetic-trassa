package rules

import "testing"

func mustCond(t *testing.T, tok string) Cond {
	t.Helper()
	c, err := parseCond(tok)
	if err != nil {
		t.Fatalf("parseCond(%q): %v", tok, err)
	}
	return c
}

func TestCondMatch(t *testing.T) {
	cases := []struct {
		cond, name string
		want       bool
	}{
		{"x.com", "x.com", true},
		{"x.com", "a.x.com", true},
		{"x.com", "yandex.com", false},
		{"x.com", "x.com.evil.net", false},
		{"=x.com", "x.com", true},
		{"=x.com", "a.x.com", false},
		{"*.x.com", "a.x.com", true},
		{"*.x.com", "a.b.x.com", true},
		{"*.x.com", "x.com", false},
		{"ru", "ru", true},
		{"ru", "yandex.ru", true},
		{"ru", "guru", false},
		{"*.ru", "yandex.ru", true},
		{"*.ru", "example.guru", false},
		{"X.COM", "x.com", true},
		{"~^rr[0-9]+---sn-", "rr3---sn-4g5ednsd.googlevideo.com", true},
		{"~^rr[0-9]+---sn-", "www.youtube.com", false},
		{"~^YouTube\\.com$", "youtube.com", true},
	}
	for _, c := range cases {
		if got := mustCond(t, c.cond).Match(c.name); got != c.want {
			t.Errorf("%q against %q = %v, expected %v", c.cond, c.name, got, c.want)
		}
	}
}

func TestParseCondErrors(t *testing.T) {
	for _, tok := range []string{"~", "~(", "foo.*.com", "*", "=", "*.", "bad name", "=1.2.3.4", "*.10.0.0.1", "~\\.рф$"} {
		if c, err := parseCond(tok); err == nil {
			t.Errorf("parseCond(%q) = %+v, expected an error", tok, c)
		}
	}
}

func TestCondCovers(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"google.com", "google.com", true},
		{"google.com", "mail.google.com", true},
		{"google.com", "=mail.google.com", true},
		{"google.com", "*.google.com", true},
		{"mail.google.com", "google.com", false},
		{"google.com", "notgoogle.com", false},
		{"=google.com", "=google.com", true},
		{"=google.com", "google.com", false},
		{"*.google.com", "mail.google.com", true},
		{"*.google.com", "google.com", false},
		{"*.google.com", "*.google.com", true},
		{"*.google.com", "=google.com", false},
		{"~google", "google.com", false},
		{"google.com", "~google", false},
	}
	for _, c := range cases {
		if got := mustCond(t, c.a).covers(mustCond(t, c.b)); got != c.want {
			t.Errorf("%q covers %q = %v, expected %v", c.a, c.b, got, c.want)
		}
	}
}
