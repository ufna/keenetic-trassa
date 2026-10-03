package web

import (
	"testing"
	"time"
)

var g0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func TestSessionsAreLimited(t *testing.T) {
	var g gate
	first := g.newSession(g0)
	for i := 1; i < maxSessions+5; i++ {
		g.newSession(g0.Add(time.Duration(i) * time.Second))
	}
	if len(g.sessions) != maxSessions {
		t.Errorf("сеансов %d", len(g.sessions))
	}
	if g.valid(first, g0.Add(time.Minute)) {
		t.Error("самый старый сеанс должен быть вытеснен")
	}
}

func TestSessionExpires(t *testing.T) {
	var g gate
	tok := g.newSession(g0)
	if !g.valid(tok, g0.Add(sessionTTL-time.Second)) || g.valid(tok, g0.Add(sessionTTL)) || g.valid("чужой", g0) {
		t.Error("срок сеанса")
	}
	g.drop(tok)
	if g.valid(tok, g0) {
		t.Error("сеанс после выхода")
	}
}

func TestPendingIsSingleUseAndLimited(t *testing.T) {
	var g gate
	id := g.addPending(&Challenge{Nonce: "n"}, g0)
	if ch, ok := g.takePending(id, g0); !ok || ch.Nonce != "n" {
		t.Error("вызов не выдан")
	}
	if _, ok := g.takePending(id, g0); ok {
		t.Error("вызов выдан дважды")
	}
	id = g.addPending(&Challenge{}, g0)
	if _, ok := g.takePending(id, g0.Add(pendingTTL)); ok {
		t.Error("устаревший вызов выдан")
	}
	for i := 0; i < maxPending+5; i++ {
		g.addPending(&Challenge{}, g0)
	}
	if len(g.pending) != maxPending {
		t.Errorf("вызовов %d", len(g.pending))
	}
}

func TestLockout(t *testing.T) {
	var g gate
	for i := 0; i < maxFailures-1; i++ {
		g.fail(g0)
	}
	if _, locked := g.locked(g0); locked {
		t.Fatal("закрыто раньше времени")
	}
	g.fail(g0)
	if wait, locked := g.locked(g0); !locked || wait != lockout {
		t.Errorf("после %d неудач: %v, %v", maxFailures, wait, locked)
	}
	if _, locked := g.locked(g0.Add(lockout)); locked {
		t.Error("пауза не кончилась")
	}
}

func TestOldFailuresAndSuccessResetCount(t *testing.T) {
	var g gate
	for i := 0; i < maxFailures-1; i++ {
		g.fail(g0)
	}
	g.fail(g0.Add(failWindow + time.Second))
	if _, locked := g.locked(g0.Add(failWindow + time.Second)); locked {
		t.Error("неудачи старше окна считаются")
	}
	var h gate
	for i := 0; i < maxFailures-1; i++ {
		h.fail(g0)
	}
	h.newSession(g0)
	h.fail(g0)
	if _, locked := h.locked(g0); locked {
		t.Error("после удачного входа счёт неудач начинается заново")
	}
}
