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
	id, stale := g.addPending(&Challenge{Nonce: "n"}, g0)
	if len(stale) != 0 {
		t.Errorf("лишние устаревшие: %d", len(stale))
	}
	if ch, fresh := g.takePending(id, g0); !fresh || ch.Nonce != "n" {
		t.Error("вызов не выдан")
	}
	if ch, _ := g.takePending(id, g0); ch != nil {
		t.Error("вызов выдан дважды")
	}
	id, _ = g.addPending(&Challenge{Nonce: "old"}, g0)
	// Устаревший вызов не годится для входа, но отдаётся — чтобы закрыть его сеанс у прошивки.
	if ch, fresh := g.takePending(id, g0.Add(pendingTTL)); fresh || ch == nil || ch.Nonce != "old" {
		t.Errorf("устаревший вызов: %v, %v", ch, fresh)
	}
	dropped := 0
	for i := 0; i < maxPending+5; i++ {
		_, stale := g.addPending(&Challenge{}, g0)
		dropped += len(stale)
	}
	if len(g.pending) != maxPending || dropped != 5 {
		t.Errorf("вызовов %d, вытеснено %d", len(g.pending), dropped)
	}
	if _, stale := g.addPending(&Challenge{}, g0.Add(pendingTTL)); len(stale) != maxPending {
		t.Errorf("просроченные при добавлении: %d", len(stale))
	}
}

func TestLockout(t *testing.T) {
	var g gate
	for i := 0; i < maxFailures-1; i++ {
		g.fail(g0.Add(time.Duration(i) * time.Minute))
	}
	if _, locked := g.locked(g0.Add(10 * time.Minute)); locked {
		t.Fatal("закрыто раньше времени")
	}
	g.fail(g0.Add(10 * time.Minute))
	// Ждать — пока самая старая неудача не выйдет из окна.
	if wait, locked := g.locked(g0.Add(10 * time.Minute)); !locked || wait != failWindow-10*time.Minute {
		t.Errorf("после %d неудач: %v, %v", maxFailures, wait, locked)
	}
	if _, locked := g.locked(g0.Add(failWindow)); locked {
		t.Error("старейшая неудача вышла из окна — вход должен открыться")
	}
}

func TestSuccessResetsFailures(t *testing.T) {
	var g gate
	for i := 0; i < maxFailures-1; i++ {
		g.fail(g0)
	}
	g.newSession(g0)
	g.fail(g0)
	if _, locked := g.locked(g0); locked {
		t.Error("после удачного входа счёт неудач начинается заново")
	}
}

// Каждый вызов открывает сеанс у прошивки: выдавать их часто нельзя.
func TestChallengeRate(t *testing.T) {
	var g gate
	for i := 0; i < challengeBurst; i++ {
		if !g.allowChallenge(g0) {
			t.Fatalf("вызов %d отклонён", i+1)
		}
	}
	if g.allowChallenge(g0) {
		t.Error("сверх запаса — без паузы")
	}
	if !g.allowChallenge(g0.Add(challengeEvery)) || g.allowChallenge(g0.Add(challengeEvery)) {
		t.Error("за паузу добавляется ровно один вызов")
	}
}
