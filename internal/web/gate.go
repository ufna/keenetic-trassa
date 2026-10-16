package web

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	sessionTTL  = 8 * time.Hour   // how long a sign-in lasts
	pendingTTL  = 2 * time.Minute // how long a login challenge waits for a response
	maxSessions = 32
	maxPending  = 16
	// At most maxFailures failed sign-ins per failWindow. All page sign-ins reach the firmware from
	// the router itself (127.0.0.1, or its home network address when the firmware refuses 127.0.0.1),
	// and the firmware has its own per-address lockout: ours is well below it.
	maxFailures = 4
	failWindow  = 15 * time.Minute
	// Each challenge opens a firmware session: at most challengeBurst in a row, then one
	// per challengeEvery.
	challengeBurst = 5
	challengeEvery = time.Second
	cookieName     = "trassa_session"
)

// gate keeps sessions and login challenges and prevents password guessing.
type gate struct {
	mu       sync.Mutex
	sessions map[string]time.Time // token → when it expires
	pending  map[string]pendingLogin
	failures []time.Time // failed sign-ins within the last failWindow, oldest first
	tokens   int         // how many challenges can be issued right away
	refilled time.Time   // when the challenge allowance was last refilled
}

type pendingLogin struct {
	ch      *Challenge
	expires time.Time
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // without randomness sessions are not secure — better not to run at all
	}
	return hex.EncodeToString(b)
}

// evict removes expired entries and, while there is still no room, the one that expires first.
// It returns what was removed.
func evict[V any](m map[string]V, expires func(V) time.Time, now time.Time, limit int) []V {
	var gone []V
	for k, v := range m {
		if !now.Before(expires(v)) {
			gone = append(gone, v)
			delete(m, k)
		}
	}
	for len(m) >= limit {
		first := ""
		for k, v := range m {
			if first == "" || expires(v).Before(expires(m[first])) {
				first = k
			}
		}
		gone = append(gone, m[first])
		delete(m, first)
	}
	return gone
}

// addPending stores a challenge. It returns the challenge id and the challenges evicted or expired:
// their firmware sessions must be closed.
func (g *gate) addPending(ch *Challenge, now time.Time) (string, []*Challenge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pending == nil {
		g.pending = map[string]pendingLogin{}
	}
	var stale []*Challenge
	for _, p := range evict(g.pending, func(p pendingLogin) time.Time { return p.expires }, now, maxPending) {
		stale = append(stale, p.ch)
	}
	id := newToken()
	g.pending[id] = pendingLogin{ch, now.Add(pendingTTL)}
	return id, stale
}

// takePending hands out a challenge once. fresh == false means there is no challenge (ch == nil) or it
// has expired: an expired one is still returned so that its firmware session can be closed.
func (g *gate) takePending(id string, now time.Time) (ch *Challenge, fresh bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.pending[id]
	delete(g.pending, id)
	if !ok {
		return nil, false
	}
	return p.ch, now.Before(p.expires)
}

// allowChallenge decides whether another challenge may be issued now.
func (g *gate) allowChallenge(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refilled.IsZero() {
		g.tokens, g.refilled = challengeBurst, now
	}
	if add := int(now.Sub(g.refilled) / challengeEvery); add > 0 {
		g.tokens = min(challengeBurst, g.tokens+add)
		g.refilled = g.refilled.Add(time.Duration(add) * challengeEvery)
	}
	if g.tokens == 0 {
		return false
	}
	g.tokens--
	return true
}

// dropOldFailures forgets failures older than failWindow. Called with g.mu held.
func (g *gate) dropOldFailures(now time.Time) {
	kept := g.failures[:0]
	for _, t := range g.failures {
		if now.Sub(t) < failWindow {
			kept = append(kept, t)
		}
	}
	g.failures = kept
}

// locked reports whether sign-in is closed after failed attempts and how long to wait: until the
// oldest failure in the window expires.
func (g *gate) locked(now time.Time) (time.Duration, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.dropOldFailures(now)
	if len(g.failures) >= maxFailures {
		return g.failures[0].Add(failWindow).Sub(now), true
	}
	return 0, false
}

func (g *gate) fail(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.dropOldFailures(now)
	g.failures = append(g.failures, now)
}

// newSession opens a session after a successful sign-in; the failure count starts over.
func (g *gate) newSession(now time.Time) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sessions == nil {
		g.sessions = map[string]time.Time{}
	}
	evict(g.sessions, func(t time.Time) time.Time { return t }, now, maxSessions)
	g.failures = nil
	tok := newToken()
	g.sessions[tok] = now.Add(sessionTTL)
	return tok
}

func (g *gate) valid(tok string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.sessions[tok]
	return ok && now.Before(exp)
}

func (g *gate) drop(tok string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.sessions, tok)
}
