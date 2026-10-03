package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trassa/internal/ctl"
	"trassa/internal/exits"
	"trassa/internal/rules"
	"trassa/internal/store"
)

const rulesText = "exit vpn = Wireguard2\ndefault direct\nyoutube.com -> vpn\n"

// fakeAuth is a router with login admin and password secret; it counts released challenges.
type fakeAuth struct {
	mu       sync.Mutex
	n        int
	released int
}

func (f *fakeAuth) Release(ctx context.Context, ch *Challenge) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released++
}

func (f *fakeAuth) count() (challenges, released int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n, f.released
}

func (f *fakeAuth) Challenge(ctx context.Context) (*Challenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return &Challenge{Realm: "Netcraze Giga", Nonce: fmt.Sprintf("nonce%d", f.n)}, nil
}

func (f *fakeAuth) Verify(ctx context.Context, ch *Challenge, login, response string) (bool, error) {
	return login == "admin" && response == answer("admin", "secret", ch.Realm, ch.Nonce), nil
}

type env struct {
	t      *testing.T
	srv    *Server
	h      http.Handler
	now    time.Time
	daemon func(cmd, arg string) (string, error)
	cookie *http.Cookie
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, store.RulesFile), []byte(rulesText), 0o644); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	e.daemon = func(cmd, arg string) (string, error) { return "", fmt.Errorf("%w (test)", ctl.ErrNoDaemon) }
	e.srv = &Server{
		Store:  &store.Store{Dir: dir},
		Auth:   &fakeAuth{},
		Daemon: func(cmd, arg string) (string, error) { return e.daemon(cmd, arg) },
		Tunnels: func(ctx context.Context, cfg *rules.Config) []exits.Tunnel {
			return []exits.Tunnel{{Exit: "vpn", Name: cfg.Exits[0].Interfaces[0], Description: "tunnel-a", Up: true}}
		},
		Now: func() time.Time { return e.now },
	}
	e.h = e.srv.Handler()
	return e
}

// do performs a request with a JSON body (or none) and the page header, as app.js does.
func (e *env) do(method, path string, body any) (int, []byte, *http.Response) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("X-Trassa", "1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if e.cookie != nil {
		req.AddCookie(e.cookie)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes(), rec.Result()
}

func decode[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("response %s: %v", b, err)
	}
	return v
}

// login signs in with password and returns the status code of the sign-in.
func (e *env) login(password string) int {
	e.t.Helper()
	code, b, _ := e.do(http.MethodGet, "/api/login", nil)
	if code != http.StatusOK {
		return code
	}
	ch := decode[map[string]string](e.t, b)
	code, _, resp := e.do(http.MethodPost, "/api/login", map[string]string{
		"id": ch["id"], "login": "admin", "response": answer("admin", password, ch["realm"], ch["challenge"])})
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			e.cookie = c
		}
	}
	return code
}

func TestLogin(t *testing.T) {
	e := newEnv(t)
	if code, _, _ := e.do("GET", "/api/state", nil); code != 401 {
		t.Fatalf("not signed in: %d", code)
	}
	if code := e.login("secret"); code != 200 || e.cookie == nil {
		t.Fatalf("sign-in: %d", code)
	}
	if !e.cookie.HttpOnly || e.cookie.SameSite != http.SameSiteStrictMode || e.cookie.MaxAge != int(sessionTTL/time.Second) {
		t.Errorf("cookie: %+v", e.cookie)
	}
	if code, _, _ := e.do("GET", "/api/state", nil); code != 200 {
		t.Errorf("after sign-in: %d", code)
	}
	e.now = e.now.Add(sessionTTL)
	if code, _, _ := e.do("GET", "/api/state", nil); code != 401 {
		t.Errorf("after the session expired: %d", code)
	}
}

func TestLoginWrongPasswordAndLockout(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < maxFailures; i++ {
		if code := e.login("wrong"); code != 401 {
			t.Fatalf("attempt %d: %d", i+1, code)
		}
	}
	if code := e.login("secret"); code != 429 {
		t.Errorf("after %d failures sign-in must be locked: %d", maxFailures, code)
	}
	e.now = e.now.Add(failWindow)
	if code := e.login("secret"); code != 200 {
		t.Errorf("after a pause: %d", code)
	}
}

func TestChallengeIsSingleUse(t *testing.T) {
	e := newEnv(t)
	_, b, _ := e.do("GET", "/api/login", nil)
	ch := decode[map[string]string](t, b)
	body := map[string]string{"id": ch["id"], "login": "admin", "response": answer("admin", "secret", ch["realm"], ch["challenge"])}
	if code, _, _ := e.do("POST", "/api/login", body); code != 200 {
		t.Fatalf("first time: %d", code)
	}
	if code, _, _ := e.do("POST", "/api/login", body); code != 400 {
		t.Errorf("same challenge again: %d", code)
	}
}

func TestDataNeedsSession(t *testing.T) {
	e := newEnv(t)
	for _, rq := range [][2]string{
		{"GET", "/api/state"}, {"GET", "/api/rules"}, {"POST", "/api/check"}, {"POST", "/api/save"},
		{"GET", "/api/history"}, {"GET", "/api/version?id=x"}, {"POST", "/api/rollback"}, {"POST", "/api/why"},
	} {
		if code, _, _ := e.do(rq[0], rq[1], map[string]string{}); code != 401 {
			t.Errorf("%s %s not signed in: %d", rq[0], rq[1], code)
		}
	}
}

// A foreign page can make the browser send a request, but not with the X-Trassa header.
func TestPostNeedsPageHeader(t *testing.T) {
	e := newEnv(t)
	e.login("secret")
	req := httptest.NewRequest("POST", "/api/save", strings.NewReader(`{"text":"default direct\n"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(e.cookie)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("no header: %d", rec.Code)
	}
	if text, _ := e.srv.Store.Current(); text != rulesText {
		t.Error("rules changed by a foreign request")
	}
}

func TestHostIsChecked(t *testing.T) {
	e := newEnv(t)
	e.srv.Hosts = []string{"192.168.1.1:8090"}
	e.h = e.srv.Handler()
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest("GET", "http://evil.example/", nil))
	if rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("foreign host name: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest("GET", "http://192.168.1.1:8090/", nil))
	if rec.Code != 200 {
		t.Errorf("own address: %d", rec.Code)
	}
}

func TestPageIsServed(t *testing.T) {
	e := newEnv(t)
	code, b, resp := e.do("GET", "/", nil)
	if code != 200 || !strings.Contains(string(b), "<title>trassa</title>") {
		t.Fatalf("status %d, page %.200s", code, b)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP: %q", csp)
	}
	for _, f := range []string{"/app.js", "/hash.js", "/style.css"} {
		if code, _, _ := e.do("GET", f, nil); code != 200 {
			t.Errorf("%s: %d", f, code)
		}
	}
}

func TestCheckAndSave(t *testing.T) {
	e := newEnv(t)
	e.login("secret")
	code, b, _ := e.do("POST", "/api/check", map[string]any{"text": "default direct\nfoo.com -> vpn\n"})
	chk := decode[checkJSON](t, b)
	if code != 200 || len(chk.Problems) != 1 || chk.Problems[0].Severity != "error" || chk.Problems[0].Line != 2 {
		t.Errorf("check with an error: %d %s", code, b)
	}
	warn := "exit vpn = Wireguard2\ndefault vpn strict\n"
	_, b, _ = e.do("POST", "/api/save", map[string]any{"text": warn})
	if res := decode[resultJSON](t, b); res.Saved || !res.NeedConfirm || res.Problems[0].Severity != "warning" {
		t.Errorf("warning without confirmation: %s", b)
	}
	_, b, _ = e.do("POST", "/api/save", map[string]any{"text": warn, "confirm": true})
	if res := decode[resultJSON](t, b); !res.Saved || res.Applied != "not-running" || res.Exits != 1 || res.Message == "" {
		t.Errorf("with confirmation: %s", b)
	}
	_, b, _ = e.do("GET", "/api/rules", nil)
	if got := decode[map[string]string](t, b)["text"]; got != warn {
		t.Errorf("rules in effect: %q", got)
	}
}

func TestHistoryAndRollback(t *testing.T) {
	e := newEnv(t)
	e.login("secret")
	e.do("POST", "/api/save", map[string]any{"text": rulesText + "t.me -> vpn\n"})
	_, b, _ := e.do("GET", "/api/history", nil)
	h := decode[[]store.Version](t, b)
	if len(h) != 2 || h[0].Kind != "page" || !h[0].Current || h[1].Kind != "outside" {
		t.Fatalf("history: %s", b)
	}
	_, b, _ = e.do("GET", "/api/version?id="+h[1].ID, nil)
	if decode[map[string]string](t, b)["text"] != rulesText {
		t.Errorf("version: %s", b)
	}
	_, b, _ = e.do("POST", "/api/rollback", map[string]any{"id": h[1].ID})
	if res := decode[resultJSON](t, b); !res.Saved {
		t.Errorf("restore: %s", b)
	}
	if text, _ := e.srv.Store.Current(); text != rulesText {
		t.Errorf("after restore: %q", text)
	}
	if code, _, _ := e.do("POST", "/api/rollback", map[string]any{"id": "../../etc/passwd"}); code != 400 {
		t.Errorf("foreign path: %d", code)
	}
}

func TestWhy(t *testing.T) {
	e := newEnv(t)
	e.login("secret")
	_, b, _ := e.do("POST", "/api/why", map[string]any{"subject": "https://www.youtube.com/watch?v=1"})
	out := decode[map[string]string](t, b)
	if out["source"] != "file" || !strings.HasPrefix(out["text"], "www.youtube.com → vpn\n") {
		t.Errorf("without the daemon: %s", b)
	}
	e.daemon = func(cmd, arg string) (string, error) {
		return arg + " → vpn\nexit vpn: now via Wireguard2\n", nil
	}
	_, b, _ = e.do("POST", "/api/why", map[string]any{"subject": "t.me"})
	if out = decode[map[string]string](t, b); out["source"] != "daemon" || !strings.Contains(out["text"], "now via") {
		t.Errorf("from the daemon: %s", b)
	}
	e.daemon = func(cmd, arg string) (string, error) {
		return "", errors.New(`"149.154" looks like an address but is malformed`)
	}
	if code, b, _ := e.do("POST", "/api/why", map[string]any{"subject": "149.154"}); code != 400 || !strings.Contains(string(b), "looks like an address") {
		t.Errorf("daemon error: %d %s", code, b)
	}
}

func TestState(t *testing.T) {
	e := newEnv(t)
	e.login("secret")
	_, b, _ := e.do("GET", "/api/state", nil)
	st := decode[stateJSON](t, b)
	if st.Daemon != nil || !strings.Contains(st.DaemonError, "not running") || len(st.Tunnels) != 1 || st.Tunnels[0].Name != "Wireguard2" {
		t.Errorf("without the daemon: %s", b)
	}
	e.daemon = func(cmd, arg string) (string, error) {
		b, _ := json.Marshal(ctl.State{Mode: "route", Rules: 1})
		return string(b), nil
	}
	_, b, _ = e.do("GET", "/api/state", nil)
	if st = decode[stateJSON](t, b); st.Daemon == nil || st.Daemon.Mode != "route" || st.DaemonError != "" {
		t.Errorf("with the daemon: %s", b)
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	e.login("secret")
	if code, _, _ := e.do("POST", "/api/logout", nil); code != 200 {
		t.Fatal(code)
	}
	if code, _, _ := e.do("GET", "/api/state", nil); code != 401 {
		t.Errorf("after sign-out: %d", code)
	}
}

// Each login challenge opens a firmware session: a foreign page must not be able to request them
// (with an image or a link), and our own page no more often than a person needs.
func TestChallengeNeedsPageHeaderAndIsRateLimited(t *testing.T) {
	e := newEnv(t)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/login", nil))
	if n, _ := e.srv.Auth.(*fakeAuth).count(); rec.Code != 403 || n != 0 {
		t.Errorf("no header: status %d, firmware challenges %d", rec.Code, n)
	}
	for i := 0; i < challengeBurst; i++ {
		if code, _, _ := e.do("GET", "/api/login", nil); code != 200 {
			t.Fatalf("challenge %d: %d", i+1, code)
		}
	}
	if code, _, _ := e.do("GET", "/api/login", nil); code != 429 {
		t.Errorf("beyond the allowance: %d", code)
	}
	e.now = e.now.Add(challengeEvery)
	if code, _, _ := e.do("GET", "/api/login", nil); code != 200 {
		t.Errorf("after a pause: %d", code)
	}
}

// A challenge that was not answered (evicted or expired) is closed at the firmware.
func TestStaleChallengesAreReleased(t *testing.T) {
	e := newEnv(t)
	auth := e.srv.Auth.(*fakeAuth)
	for i := 0; i < maxPending+1; i++ {
		e.now = e.now.Add(challengeEvery)
		e.do("GET", "/api/login", nil)
	}
	waitReleased := func(want int) {
		t.Helper()
		for i := 0; i < 100; i++ {
			if _, r := auth.count(); r == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		_, r := auth.count()
		t.Errorf("released challenges %d, want %d", r, want)
	}
	waitReleased(1)
	_, b, _ := e.do("GET", "/api/login", nil) // evicts one more
	ch := decode[map[string]string](t, b)
	e.now = e.now.Add(pendingTTL)
	code, _, _ := e.do("POST", "/api/login", map[string]string{
		"id": ch["id"], "login": "admin", "response": answer("admin", "secret", ch["realm"], ch["challenge"])})
	if code != 400 {
		t.Errorf("expired challenge: %d", code)
	}
	waitReleased(3)
}
