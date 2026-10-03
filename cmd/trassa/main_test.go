package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const good = `exit vpn = Wireguard2, Wireguard0
default direct
youtube.com -> vpn strict
@lists/tg.txt -> vpn
*.ru -> direct
test youtube.com = vpn
`

func write(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "rules.conf")
}

func exec(args ...string) (code int, out, errOut string) {
	var o, e bytes.Buffer
	code = run(args, &o, &e)
	return code, o.String(), e.String()
}

func TestCheckGood(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": good, "lists/tg.txt": "t.me\n149.154.160.0/20\n"})
	code, out, errOut := exec("check", path)
	if code != 0 || errOut != "" {
		t.Fatalf("code %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "no errors") || !strings.Contains(out, "rules: 3") ||
		!strings.Contains(out, "exits: 1") || !strings.Contains(out, "expectations: 1") {
		t.Errorf("output: %q", out)
	}
}

func TestCheckErrors(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": "default direct\nfoo.com -> vpn\n"})
	code, out, _ := exec("check", path)
	if code != 1 || !strings.Contains(out, "line 2: error: exit \"vpn\" is not declared") {
		t.Errorf("code %d, output %q", code, out)
	}
	if strings.Contains(out, "no errors") {
		t.Errorf("printed \"no errors\" despite errors: %q", out)
	}
}

func TestCheckWarningsDoNotFail(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": "exit vpn = W\ndefault direct\na.com -> vpn\nb.a.com -> direct\n"})
	code, out, _ := exec("check", path)
	if code != 0 || !strings.Contains(out, "line 4: warning") || !strings.Contains(out, "warnings: 1") {
		t.Errorf("code %d, output %q", code, out)
	}
}

func TestCheckMissingInclude(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": good})
	code, out, _ := exec("check", path)
	if code != 1 || !strings.Contains(out, "lists/tg.txt") {
		t.Errorf("code %d, output %q", code, out)
	}
}

func TestCheckMissingFile(t *testing.T) {
	code, _, errOut := exec("check", filepath.Join(t.TempDir(), "nope.conf"))
	if code != 1 || !strings.Contains(errOut, "cannot read") {
		t.Errorf("code %d, stderr %q", code, errOut)
	}
}

func TestWhy(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": good, "lists/tg.txt": "t.me\n149.154.160.0/20\n"})
	cases := []struct {
		subject string
		want    []string
	}{
		{"WWW.YouTube.com.", []string{"www.youtube.com → vpn strict", "line 3: youtube.com -> vpn strict", "exit vpn: Wireguard2, Wireguard0"}},
		{"yandex.ru", []string{"yandex.ru → direct", "line 5"}},
		{"example.org", []string{"example.org → direct", "no rule matched", "default applies (line 2)"}},
		{"149.154.167.50", []string{"149.154.167.50 → vpn", "line 4"}},
		{"8.8.8.8", []string{"8.8.8.8 → direct", "no rule matched"}},
		{" 149.154.167.50\r\n", []string{"149.154.167.50 → vpn", "line 4"}}, // pasted with spaces and a line break
	}
	for _, c := range cases {
		code, out, errOut := exec("why", "-f", path, c.subject)
		if code != 0 {
			t.Errorf("%s: code %d, stderr %q", c.subject, code, errOut)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: output lacks %q:\n%s", c.subject, w, out)
			}
		}
	}
}

func TestWhyBadInput(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": "exit vpn = W\ndefault direct\n"})
	if code, _, errOut := exec("why", "-f", path, "bad..name"); code != 1 || !strings.Contains(errOut, "empty label") {
		t.Errorf("bad name: code %d, stderr %q", code, errOut)
	}
	if code, _, errOut := exec("why", "-f", path, "149.154.167.50."); code != 1 || !strings.Contains(errOut, "looks like an address") {
		t.Errorf("address with a trailing dot: code %d, stderr %q", code, errOut)
	}
	if code, _, errOut := exec("why", "-f", path, "2001:db8::1"); code != 1 || !strings.Contains(errOut, "IPv6") {
		t.Errorf("IPv6 address: code %d, stderr %q", code, errOut)
	}
	bad := write(t, map[string]string{"rules.conf": "foo.com -> vpn\n"})
	if code, out, _ := exec("why", "-f", bad, "foo.com"); code != 1 || !strings.Contains(out, "error") {
		t.Errorf("file with errors: code %d, output %q", code, out)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"check"}, {"why"}, {"why", "-f", "x"}, {"status", "x"}, {"reload", "x"}, {"cleanup", "x"}, {"rollback", "x"}, {"web", "x"}, {"web", "-nonsense"}, {"nonsense"}} {
		if code, _, errOut := exec(args...); code != 2 || !strings.Contains(errOut, "Usage") {
			t.Errorf("%v: code %d, stderr %q", args, code, errOut)
		}
	}
}

func TestLiveCommandsWithoutDaemon(t *testing.T) {
	t.Setenv("TRASSA_SOCK", filepath.Join(t.TempDir(), "none.sock"))
	for _, args := range [][]string{{"status"}, {"reload"}, {"why", "youtube.com"}} {
		if code, _, errOut := exec(args...); code != 1 || !strings.Contains(errOut, "trassa daemon is not running") {
			t.Errorf("%v: code %d, stderr %q", args, code, errOut)
		}
	}
}

func TestWebFailsOnBusyAddress(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	code, _, errOut := exec("web", "-listen", l.Addr().String(), "-dir", t.TempDir())
	if code != 1 || !strings.Contains(errOut, "web page") {
		t.Errorf("code %d, stderr %q", code, errOut)
	}
}
