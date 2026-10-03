package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trassa/internal/store"
)

// fakeRCI отвечает на вопрос о любом интерфейсе как о живом туннеле WireGuard.
func fakeRCI(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"W","index":2,"type":"Wireguard","link":"up","connected":"yes","wireguard":{"peer":[{"online":true}]}}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func noDaemon(t *testing.T) {
	t.Setenv("TRASSA_SOCK", filepath.Join(t.TempDir(), "none.sock"))
}

func TestRollbackCommand(t *testing.T) {
	noDaemon(t)
	path := write(t, map[string]string{"rules.conf": live})
	dir := filepath.Dir(path)
	if res, err := (&store.Store{Dir: dir}).Save(live+"t.me -> vpn\n", false); err != nil || !res.Saved {
		t.Fatalf("%+v, %v", res, err)
	}
	code, out, errOut := exec("rollback", "-dir", dir, "-rci", fakeRCI(t))
	if code != 0 || !strings.Contains(out, "возвращена версия") || !strings.Contains(out, "демон не запущен") {
		t.Errorf("код %d, вывод %q, stderr %q", code, out, errOut)
	}
	if b, _ := os.ReadFile(path); string(b) != live {
		t.Errorf("файл правил: %q", b)
	}
}

func TestRollbackNeedsConfirmForWarnings(t *testing.T) {
	noDaemon(t)
	warn := "exit vpn = W\ndefault vpn strict\n"
	path := write(t, map[string]string{"rules.conf": warn})
	dir := filepath.Dir(path)
	if res, _ := (&store.Store{Dir: dir}).Save(live, false); !res.Saved {
		t.Fatalf("%+v", res)
	}
	code, out, _ := exec("rollback", "-dir", dir, "-rci", fakeRCI(t))
	if code != 1 || !strings.Contains(out, "trassa rollback -y") {
		t.Errorf("без подтверждения: код %d, вывод %q", code, out)
	}
	if code, out, _ = exec("rollback", "-y", "-dir", dir, "-rci", fakeRCI(t)); code != 0 {
		t.Errorf("с подтверждением: код %d, вывод %q", code, out)
	}
	if b, _ := os.ReadFile(path); string(b) != warn {
		t.Errorf("файл правил: %q", b)
	}
}

func TestRollbackWithoutHistory(t *testing.T) {
	noDaemon(t)
	path := write(t, map[string]string{"rules.conf": live})
	code, _, errOut := exec("rollback", "-dir", filepath.Dir(path), "-rci", fakeRCI(t))
	if code != 1 || !strings.Contains(errOut, "в истории нет версии") {
		t.Errorf("код %d, stderr %q", code, errOut)
	}
}
