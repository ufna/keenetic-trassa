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
		t.Errorf("sessions: %d", len(g.sessions))
	}
	if g.valid(first, g0.Add(time.Minute)) {
		t.Error("the oldest session must be evicted")
	}
}

func TestSessionExpires(t *testing.T) {
	var g gate
	tok := g.newSession(g0)
	if !g.valid(tok, g0.Add(sessionTTL-time.Second)) || g.valid(tok, g0.Add(sessionTTL)) || g.valid("someone-else", g0) {
		t.Error("session lifetime")
	}
	g.drop(tok)
	if g.valid(tok, g0) {
		t.Error("session after sign-out")
	}
}

func TestPendingIsSingleUseAndLimited(t *testing.T) {
	var g gate
	id, stale := g.addPending(&Challenge{Nonce: "n"}, g0)
	if len(stale) != 0 {
		t.Errorf("unexpected stale challenges: %d", len(stale))
	}
	if ch, fresh := g.takePending(id, g0); !fresh || ch.Nonce != "n" {
		t.Error("challenge not handed out")
	}
	if ch, _ := g.takePending(id, g0); ch != nil {
		t.Error("challenge handed out twice")
	}
	id, _ = g.addPending(&Challenge{Nonce: "old"}, g0)
	// An expired challenge is no good for sign-in but is still returned so its firmware session can be closed.
	if ch, fresh := g.takePending(id, g0.Add(pendingTTL)); fresh || ch == nil || ch.Nonce != "old" {
		t.Errorf("expired challenge: %v, %v", ch, fresh)
	}
	dropped := 0
	for i := 0; i < maxPending+5; i++ {
		_, stale := g.addPending(&Challenge{}, g0)
		dropped += len(stale)
	}
	if len(g.pending) != maxPending || dropped != 5 {
		t.Errorf("challenges %d, evicted %d", len(g.pending), dropped)
	}
	if _, stale := g.addPending(&Challenge{}, g0.Add(pendingTTL)); len(stale) != maxPending {
		t.Errorf("expired on add: %d", len(stale))
	}
}

func TestLockout(t *testing.T) {
	var g gate
	for i := 0; i < maxFailures-1; i++ {
		g.fail(g0.Add(time.Duration(i) * time.Minute))
	}
	if _, locked := g.locked(g0.Add(10 * time.Minute)); locked {
		t.Fatal("locked too early")
	}
	g.fail(g0.Add(10 * time.Minute))
	// The wait lasts until the oldest failure leaves the window.
	if wait, locked := g.locked(g0.Add(10 * time.Minute)); !locked || wait != failWindow-10*time.Minute {
		t.Errorf("after %d failures: %v, %v", maxFailures, wait, locked)
	}
	if _, locked := g.locked(g0.Add(failWindow)); locked {
		t.Error("the oldest failure left the window — sign-in must reopen")
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
		t.Error("after a successful sign-in the failure count starts over")
	}
}

// Each challenge opens a firmware session, so they must not be issued often.
func TestChallengeRate(t *testing.T) {
	var g gate
	for i := 0; i < challengeBurst; i++ {
		if !g.allowChallenge(g0) {
			t.Fatalf("challenge %d refused", i+1)
		}
	}
	if g.allowChallenge(g0) {
		t.Error("beyond the allowance without a pause")
	}
	if !g.allowChallenge(g0.Add(challengeEvery)) || g.allowChallenge(g0.Add(challengeEvery)) {
		t.Error("a pause adds exactly one challenge")
	}
}
