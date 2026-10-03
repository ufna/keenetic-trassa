package web

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	sessionTTL  = 8 * time.Hour   // сколько живёт вход
	pendingTTL  = 2 * time.Minute // сколько ждёт ответа вызов на вход
	maxSessions = 32
	maxPending  = 16
	maxFailures = 5 // столько неудачных входов за failWindow — и вход закрыт на lockout
	failWindow  = 5 * time.Minute
	lockout     = time.Minute
	cookieName  = "trassa_session"
)

// gate хранит сеансы и вызовы на вход и не даёт подбирать пароль.
type gate struct {
	mu         sync.Mutex
	sessions   map[string]time.Time // токен → когда истекает
	pending    map[string]pendingLogin
	failures   []time.Time
	lockedTill time.Time
}

type pendingLogin struct {
	ch      *Challenge
	expires time.Time
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // без случайных чисел сеансы не защищены — лучше не работать вовсе
	}
	return hex.EncodeToString(b)
}

// evict удаляет просроченные записи и, пока места нет, ту, что истекает раньше всех.
func evict[V any](m map[string]V, expires func(V) time.Time, now time.Time, limit int) {
	for k, v := range m {
		if !now.Before(expires(v)) {
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
		delete(m, first)
	}
}

func (g *gate) addPending(ch *Challenge, now time.Time) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pending == nil {
		g.pending = map[string]pendingLogin{}
	}
	evict(g.pending, func(p pendingLogin) time.Time { return p.expires }, now, maxPending)
	id := newToken()
	g.pending[id] = pendingLogin{ch, now.Add(pendingTTL)}
	return id
}

// takePending выдаёт вызов один раз.
func (g *gate) takePending(id string, now time.Time) (*Challenge, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.pending[id]
	delete(g.pending, id)
	if !ok || !now.Before(p.expires) {
		return nil, false
	}
	return p.ch, true
}

// locked сообщает, закрыт ли вход после неудачных попыток, и сколько ещё ждать.
func (g *gate) locked(now time.Time) (time.Duration, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.Before(g.lockedTill) {
		return g.lockedTill.Sub(now), true
	}
	return 0, false
}

func (g *gate) fail(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	kept := g.failures[:0]
	for _, t := range g.failures {
		if now.Sub(t) < failWindow {
			kept = append(kept, t)
		}
	}
	g.failures = append(kept, now)
	if len(g.failures) >= maxFailures {
		g.lockedTill, g.failures = now.Add(lockout), nil
	}
}

// newSession открывает сеанс после удачного входа; счёт неудач начинается заново.
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
