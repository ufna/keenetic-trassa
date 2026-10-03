package web

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// answer считает ответ на вызов роутера так же, как его собственная страница.
func answer(login, password, realm, nonce string) string {
	m := md5.Sum([]byte(login + ":" + realm + ":" + password))
	s := sha256.Sum256([]byte(nonce + hex.EncodeToString(m[:])))
	return hex.EncodeToString(s[:])
}

// fakeRouter изображает веб-сервер прошивки: вызов привязан к cookie сеанса, пароль admin — secret.
type fakeRouter struct {
	mu      sync.Mutex
	nonces  map[string]string // сеанс → вызов
	authed  map[string]bool
	logouts int
	broken  bool
}

func (f *fakeRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.broken {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sid := ""
	if c, err := r.Cookie("sid"); err == nil {
		sid = c.Value
	}
	switch r.Method {
	case http.MethodGet:
		if f.authed[sid] {
			return
		}
		sid = fmt.Sprintf("s%d", len(f.nonces)+1)
		f.nonces[sid] = "nonce-" + sid
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/"})
		w.Header().Set("X-NDM-Realm", "Netcraze Giga")
		w.Header().Set("X-NDM-Challenge", f.nonces[sid])
		w.WriteHeader(http.StatusUnauthorized)
	case http.MethodPost:
		var in struct{ Login, Password string }
		json.NewDecoder(r.Body).Decode(&in)
		nonce, ok := f.nonces[sid]
		if !ok || in.Login != "admin" || in.Password != answer("admin", "secret", "Netcraze Giga", nonce) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.authed[sid] = true
	case http.MethodDelete:
		delete(f.authed, sid)
		delete(f.nonces, sid)
		f.logouts++
	}
}

func TestRouterAuth(t *testing.T) {
	fr := &fakeRouter{nonces: map[string]string{}, authed: map[string]bool{}}
	srv := httptest.NewServer(fr)
	defer srv.Close()
	a := RouterAuth{Base: srv.URL}
	ctx := context.Background()

	ch, err := a.Challenge(ctx)
	if err != nil || ch.Realm != "Netcraze Giga" || ch.Nonce == "" {
		t.Fatalf("вызов: %+v, %v", ch, err)
	}
	if ok, err := a.Verify(ctx, ch, "admin", answer("admin", "secret", ch.Realm, ch.Nonce)); !ok || err != nil {
		t.Fatalf("верный пароль: %v, %v", ok, err)
	}
	fr.mu.Lock()
	if fr.logouts != 1 || len(fr.authed) != 0 || len(fr.nonces) != 0 {
		t.Errorf("сеанс прошивки не закрыт: выходов %d, открытых сеансов %d", fr.logouts, len(fr.nonces))
	}
	fr.mu.Unlock()

	ch, _ = a.Challenge(ctx)
	if ok, err := a.Verify(ctx, ch, "admin", answer("admin", "wrong", ch.Realm, ch.Nonce)); ok || err != nil {
		t.Errorf("неверный пароль: %v, %v", ok, err)
	}
	// Ответ на чужой вызов не подходит: вызов привязан к сеансу.
	ch1, _ := a.Challenge(ctx)
	ch2, _ := a.Challenge(ctx)
	if ok, _ := a.Verify(ctx, ch2, "admin", answer("admin", "secret", ch1.Realm, ch1.Nonce)); ok {
		t.Error("ответ на чужой вызов принят")
	}
	// Вызов, на который так и не ответили, закрывается отдельно.
	a.Release(ctx, ch1)
	fr.mu.Lock()
	if len(fr.nonces) != 0 {
		t.Errorf("после неудачных входов и отказа от вызова у прошивки остались открытые сеансы: %d", len(fr.nonces))
	}
	fr.mu.Unlock()

	fr.mu.Lock()
	fr.broken = true
	fr.mu.Unlock()
	if _, err := a.Challenge(ctx); err == nil {
		t.Error("прошивка ответила ошибкой — вызова быть не должно")
	}
	if _, err := a.Verify(ctx, ch, "admin", "x"); err == nil {
		t.Error("прошивка ответила ошибкой — это не «неверный пароль», а сбой")
	}
}
