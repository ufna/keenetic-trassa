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
	// Не больше maxFailures неудачных входов за failWindow. Все входы страницы приходят к прошивке
	// с одного адреса 127.0.0.1, а у прошивки своя блокировка по адресу: наш предел — заметно ниже.
	maxFailures = 4
	failWindow  = 15 * time.Minute
	// Каждый вызов открывает сеанс у прошивки: не больше challengeBurst подряд, дальше — по одному
	// за challengeEvery.
	challengeBurst = 5
	challengeEvery = time.Second
	cookieName     = "trassa_session"
)

// gate хранит сеансы и вызовы на вход и не даёт подбирать пароль.
type gate struct {
	mu       sync.Mutex
	sessions map[string]time.Time // токен → когда истекает
	pending  map[string]pendingLogin
	failures []time.Time // неудачные входы за последние failWindow, от старых к новым
	tokens   int         // сколько вызовов можно выдать сразу
	refilled time.Time   // когда запас вызовов пополнялся
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
// Возвращает удалённое.
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

// addPending запоминает вызов. Возвращает его номер и вызовы, вытесненные или устаревшие:
// их сеансы у прошивки нужно закрыть.
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

// takePending выдаёт вызов один раз. fresh == false — вызова нет (ch == nil) или он устарел:
// устаревший тоже отдаётся, чтобы закрыть его сеанс у прошивки.
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

// allowChallenge решает, можно ли сейчас выдать ещё один вызов.
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

// dropOldFailures забывает неудачи старше failWindow. Вызывается под g.mu.
func (g *gate) dropOldFailures(now time.Time) {
	kept := g.failures[:0]
	for _, t := range g.failures {
		if now.Sub(t) < failWindow {
			kept = append(kept, t)
		}
	}
	g.failures = kept
}

// locked сообщает, закрыт ли вход после неудачных попыток, и сколько ещё ждать: пока самая
// старая неудача в окне не устареет.
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
