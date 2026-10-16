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

func TestVersion(t *testing.T) {
	defer func(v string) { version = v }(version)
	version = "1.2.3"
	if code, out, errOut := exec("version"); code != 0 || out != "trassa 1.2.3\n" || errOut != "" {
		t.Errorf("code %d, stdout %q, stderr %q", code, out, errOut)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"check"}, {"why"}, {"why", "-f", "x"}, {"status", "x"}, {"reload", "x"}, {"cleanup", "x"}, {"rollback", "x"}, {"enable", "x"}, {"disable", "x"}, {"web", "x"}, {"web", "-nonsense"}, {"version", "x"}, {"nonsense"}} {
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

func TestAuthFallback(t *testing.T) {
	for listen, want := range map[string]string{
		"192.168.1.1:8090": "http://192.168.1.1",
		"10.0.0.1:80":      "http://10.0.0.1",
		"0.0.0.0:8090":     "",
		":8090":            "",
		"nonsense":         "",
		"[fe80::1]:8090":   "",
	} {
		if got := authFallback(listen); got != want {
			t.Errorf("%s: %q, want %q", listen, got, want)
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

// The default config ships with the repository. As it is, it must pass the check and change
// nothing: no exits, no rules. With its examples enabled (lines "#   ..."), they must pass the
// check too, without warnings, so the examples never drift from what trassa accepts.
func TestDefaultRules(t *testing.T) {
	src, err := os.ReadFile("../../rules/rules.conf")
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := exec("check", write(t, map[string]string{"rules.conf": string(src)}))
	if code != 0 || !strings.Contains(out, "rules: 0, exits: 0") {
		t.Errorf("as shipped: code %d, output %q, stderr %q", code, out, errOut)
	}
	var b strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		// An example taking conditions from a file needs that file: it stays a comment.
		if rest, ok := strings.CutPrefix(line, "#   "); ok && !strings.HasPrefix(rest, "@") {
			line = rest
		}
		b.WriteString(line + "\n")
	}
	code, out, errOut = exec("check", write(t, map[string]string{"rules.conf": b.String()}))
	if code != 0 || !strings.Contains(out, "exits: 1") || !strings.Contains(out, "expectations: 2, warnings: 0") {
		t.Errorf("with the examples enabled: code %d, output %q, stderr %q\n%s", code, out, errOut, b.String())
	}
}

func TestDisableEnableCommands(t *testing.T) {
	t.Setenv("TRASSA_SOCK", filepath.Join(t.TempDir(), "none.sock"))
	dir := t.TempDir()
	code, out, errOut := exec("disable", "-dir", dir)
	if _, err := os.Stat(filepath.Join(dir, "disabled")); code != 0 || err != nil || !strings.Contains(out, "turned off") {
		t.Errorf("disable: code %d, output %q, stderr %q, mark %v", code, out, errOut, err)
	}
	code, out, errOut = exec("enable", "-dir", dir)
	if _, err := os.Stat(filepath.Join(dir, "disabled")); code != 0 || err == nil || !strings.Contains(out, "turned on") {
		t.Errorf("enable: code %d, output %q, stderr %q", code, out, errOut)
	}
}
