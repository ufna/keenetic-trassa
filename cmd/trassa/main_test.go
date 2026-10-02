package main

import (
	"bytes"
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
		t.Fatalf("код %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "ошибок нет") || !strings.Contains(out, "правил: 3") ||
		!strings.Contains(out, "выходов: 1") || !strings.Contains(out, "ожиданий: 1") {
		t.Errorf("вывод: %q", out)
	}
}

func TestCheckErrors(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": "default direct\nfoo.com -> vpn\n"})
	code, out, _ := exec("check", path)
	if code != 1 || !strings.Contains(out, "строка 2: ошибка: выход \"vpn\" не объявлен") {
		t.Errorf("код %d, вывод %q", code, out)
	}
	if strings.Contains(out, "ошибок нет") {
		t.Errorf("при ошибках напечатано «ошибок нет»: %q", out)
	}
}

func TestCheckWarningsDoNotFail(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": "exit vpn = W\ndefault direct\na.com -> vpn\nb.a.com -> direct\n"})
	code, out, _ := exec("check", path)
	if code != 0 || !strings.Contains(out, "строка 4: предупреждение") || !strings.Contains(out, "предупреждений: 1") {
		t.Errorf("код %d, вывод %q", code, out)
	}
}

func TestCheckMissingInclude(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": good})
	code, out, _ := exec("check", path)
	if code != 1 || !strings.Contains(out, "lists/tg.txt") {
		t.Errorf("код %d, вывод %q", code, out)
	}
}

func TestCheckMissingFile(t *testing.T) {
	code, _, errOut := exec("check", filepath.Join(t.TempDir(), "nope.conf"))
	if code != 1 || !strings.Contains(errOut, "не могу прочитать") {
		t.Errorf("код %d, stderr %q", code, errOut)
	}
}

func TestWhy(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": good, "lists/tg.txt": "t.me\n149.154.160.0/20\n"})
	cases := []struct {
		subject string
		want    []string
	}{
		{"WWW.YouTube.com.", []string{"www.youtube.com → vpn strict", "строка 3: youtube.com -> vpn strict", "выход vpn: Wireguard2, Wireguard0"}},
		{"yandex.ru", []string{"yandex.ru → direct", "строка 5"}},
		{"example.org", []string{"example.org → direct", "ни одно правило не подошло", "default (строка 2)"}},
		{"149.154.167.50", []string{"149.154.167.50 → vpn", "строка 4"}},
		{"8.8.8.8", []string{"8.8.8.8 → direct", "ни одно правило не подошло"}},
		{" 149.154.167.50\r\n", []string{"149.154.167.50 → vpn", "строка 4"}}, // вставлено с пробелами и переводом строки
	}
	for _, c := range cases {
		code, out, errOut := exec("why", "-f", path, c.subject)
		if code != 0 {
			t.Errorf("%s: код %d, stderr %q", c.subject, code, errOut)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: в выводе нет %q:\n%s", c.subject, w, out)
			}
		}
	}
}

func TestWhyBadInput(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": "exit vpn = W\ndefault direct\n"})
	if code, _, errOut := exec("why", "-f", path, "bad..name"); code != 1 || !strings.Contains(errOut, "пустая метка") {
		t.Errorf("неверное имя: код %d, stderr %q", code, errOut)
	}
	if code, _, errOut := exec("why", "-f", path, "149.154.167.50."); code != 1 || !strings.Contains(errOut, "похоже на адрес") {
		t.Errorf("адрес с лишней точкой: код %d, stderr %q", code, errOut)
	}
	if code, _, errOut := exec("why", "-f", path, "2001:db8::1"); code != 1 || !strings.Contains(errOut, "IPv6") {
		t.Errorf("IPv6-адрес: код %d, stderr %q", code, errOut)
	}
	bad := write(t, map[string]string{"rules.conf": "foo.com -> vpn\n"})
	if code, out, _ := exec("why", "-f", bad, "foo.com"); code != 1 || !strings.Contains(out, "ошибка") {
		t.Errorf("файл с ошибками: код %d, вывод %q", code, out)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"check"}, {"why"}, {"why", "-f", "x"}, {"status", "x"}, {"reload", "x"}, {"cleanup", "x"}, {"nonsense"}} {
		if code, _, errOut := exec(args...); code != 2 || !strings.Contains(errOut, "Использование") {
			t.Errorf("%v: код %d, stderr %q", args, code, errOut)
		}
	}
}

func TestLiveCommandsWithoutDaemon(t *testing.T) {
	t.Setenv("TRASSA_SOCK", filepath.Join(t.TempDir(), "none.sock"))
	for _, args := range [][]string{{"status"}, {"reload"}, {"why", "youtube.com"}} {
		if code, _, errOut := exec(args...); code != 1 || !strings.Contains(errOut, "демон trassa не отвечает") {
			t.Errorf("%v: код %d, stderr %q", args, code, errOut)
		}
	}
}
