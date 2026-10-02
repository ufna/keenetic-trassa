package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trassa/internal/ctl"
	"trassa/internal/engine"
	"trassa/internal/rules"
)

func startDaemonStub(t *testing.T, rulesText string) (rulesPath string) {
	t.Helper()
	rulesPath = write(t, map[string]string{"rules.conf": rulesText})
	cfg, ps, ok := load(rulesPath, os.Stderr)
	if !ok || rules.HasErrors(ps) {
		t.Fatalf("правила: %v", ps)
	}
	eng := engine.New(cfg, nil, func(string, ...any) {}, time.Now())
	sock := filepath.Join(t.TempDir(), "trassa.sock")
	t.Setenv("TRASSA_SOCK", sock)
	srv, err := ctl.Serve(sock, handler(eng, reloader(rulesPath, eng)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return rulesPath
}

const live = "exit vpn = W\ndefault direct\nyoutube.com -> vpn\n"

func TestLiveWhyAndStatus(t *testing.T) {
	startDaemonStub(t, live)
	code, out, errOut := exec("why", "WWW.YouTube.com")
	if code != 0 || !strings.Contains(out, "www.youtube.com → vpn") || !strings.Contains(out, "DNS-ответов для этого имени ещё не было") {
		t.Errorf("why: код %d, вывод %q, stderr %q", code, out, errOut)
	}
	code, out, _ = exec("status")
	if code != 0 || !strings.Contains(out, "режим наблюдения") || !strings.Contains(out, "правил: 1") {
		t.Errorf("status: код %d, вывод %q", code, out)
	}
	if code, _, errOut := exec("why", "149.154.167"); code != 1 || !strings.Contains(errOut, "похоже на адрес") {
		t.Errorf("why с недописанным адресом: код %d, stderr %q", code, errOut)
	}
}

func TestReloadAppliesNewRules(t *testing.T) {
	path := startDaemonStub(t, live)
	if err := os.WriteFile(path, []byte(live+"vimeo.com -> vpn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := exec("reload")
	if code != 0 || !strings.Contains(out, "правила перечитаны: правил 2") {
		t.Fatalf("reload: код %d, вывод %q, stderr %q", code, out, errOut)
	}
	if _, out, _ := exec("why", "vimeo.com"); !strings.Contains(out, "vimeo.com → vpn") {
		t.Errorf("новое правило не действует: %q", out)
	}
}

func TestReloadKeepsOldRulesOnError(t *testing.T) {
	path := startDaemonStub(t, live)
	if err := os.WriteFile(path, []byte("exit vpn = W\ndefault direct\nyoutube.com -> nowhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := exec("reload")
	if code != 1 || !strings.Contains(out, "строка 3: ошибка") || !strings.Contains(errOut, "оставлены прежние правила") {
		t.Fatalf("reload с ошибкой: код %d, вывод %q, stderr %q", code, out, errOut)
	}
	if _, out, _ := exec("why", "youtube.com"); !strings.Contains(out, "youtube.com → vpn") {
		t.Errorf("прежние правила потеряны: %q", out)
	}
	// Файл пропал совсем: то же самое.
	os.Remove(path)
	if code, _, errOut := exec("reload"); code != 1 || !strings.Contains(errOut, "оставлены прежние правила") {
		t.Errorf("reload без файла: код %d, stderr %q", code, errOut)
	}
}

func TestReloadWarningsAreShown(t *testing.T) {
	path := startDaemonStub(t, live)
	if err := os.WriteFile(path, []byte(live+"www.youtube.com -> direct\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := exec("reload")
	if code != 0 || !strings.Contains(out, "предупреждение") || !strings.Contains(out, "правила перечитаны") {
		t.Errorf("reload с предупреждением: код %d, вывод %q", code, out)
	}
}

func TestUnknownControlCommand(t *testing.T) {
	startDaemonStub(t, live)
	if _, err := ctl.Call(os.Getenv("TRASSA_SOCK"), "explode", "", time.Second); err == nil || !strings.Contains(err.Error(), "неизвестная команда") {
		t.Errorf("ошибка %v", err)
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	path := write(t, map[string]string{"rules.conf": live})
	bad := write(t, map[string]string{"rules.conf": "youtube.com -> vpn\n"})
	cases := []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"run", "-only", "не-адрес", "-rules", path}, 2, "-only"},
		{[]string{"run", "-only", "fdbd::1", "-rules", path}, 2, "-only"},
		{[]string{"run", "-queue", "70000", "-rules", path}, 2, "-queue"},
		{[]string{"run", "-rules", path, "лишнее"}, 2, "Использование"},
		{[]string{"run", "-rules", bad}, 1, "демон не запущен"},
		{[]string{"run", "-rules", filepath.Join(t.TempDir(), "nope.conf")}, 1, "не могу прочитать"},
	}
	for _, c := range cases {
		t.Setenv("TRASSA_SOCK", filepath.Join(t.TempDir(), "s.sock"))
		if code, _, errOut := exec(c.args...); code != c.code || !strings.Contains(errOut, c.msg) {
			t.Errorf("%v: код %d, stderr %q; ожидалось %d и %q", c.args, code, errOut, c.code, c.msg)
		}
	}
}
