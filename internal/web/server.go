package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/ufna/keenetic-trassa/internal/exits"
	"github.com/ufna/keenetic-trassa/internal/rules"
	"github.com/ufna/keenetic-trassa/internal/store"
)

//go:embed static
var staticFiles embed.FS

// Server is the trassa page and its HTTP API.
type Server struct {
	Store *store.Store
	Auth  Authenticator
	// Daemon sends a command to the daemon over the control socket.
	Daemon func(cmd, arg string) (string, error)
	// Tunnels reports what the firmware knows about the exit interfaces; nil means do not ask.
	Tunnels func(ctx context.Context, cfg *rules.Config) []exits.Tunnel
	// Hosts are the allowed Host header values; empty means any. Protects against DNS rebinding.
	Hosts []string
	Now   func() time.Time
	Logf  func(format string, args ...any)

	gate gate
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Handler returns the handler for all requests: the page and its HTTP API.
func (s *Server) Handler() http.Handler {
	files, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	static := http.FileServerFS(files)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		static.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /api/login", s.guard(false, s.loginChallenge))
	mux.HandleFunc("POST /api/login", s.guard(false, s.login))
	mux.HandleFunc("POST /api/logout", s.guard(false, s.logout))
	mux.HandleFunc("GET /api/state", s.guard(true, s.state))
	mux.HandleFunc("GET /api/rules", s.guard(true, s.rulesText))
	mux.HandleFunc("POST /api/check", s.guard(true, s.check))
	mux.HandleFunc("POST /api/save", s.guard(true, s.save))
	mux.HandleFunc("GET /api/history", s.guard(true, s.history))
	mux.HandleFunc("GET /api/version", s.guard(true, s.version))
	mux.HandleFunc("POST /api/rollback", s.guard(true, s.rollback))
	mux.HandleFunc("POST /api/why", s.guard(true, s.why))
	mux.HandleFunc("POST /api/power", s.guard(true, s.power))
	mux.HandleFunc("GET /api/answers", s.guard(true, s.answers))
	return s.secure(mux)
}

// secure sets protective headers and rejects requests addressed to a foreign host name.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if len(s.Hosts) > 0 && !slices.Contains(s.Hosts, r.Host) {
			http.Error(w, "the trassa page is at http://"+s.Hosts[0]+"/", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// guard lets requests reach data only with a valid session. Any API request is accepted only from
// the trassa page: a foreign page (form, image, link) cannot set the X-Trassa header without the
// server's permission, and the server never grants it.
func (s *Server) guard(needSession bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Header.Get("X-Trassa") != "1" {
			writeError(w, http.StatusForbidden, "the request did not come from the trassa page")
			return
		}
		if needSession && !s.signedIn(r) {
			writeError(w, http.StatusUnauthorized, "sign-in required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, store.MaxSize+64<<10)
		next(w, r)
	}
}

func (s *Server) signedIn(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	return err == nil && s.gate.valid(c.Value, s.now())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// readJSON decodes the request body; on error it writes the response itself and returns false.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "cannot parse the request: "+err.Error())
		return false
	}
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func lockedMessage(wait time.Duration) string {
	return fmt.Sprintf("too many failed sign-in attempts — wait %d s", int(wait/time.Second)+1)
}

// release closes the firmware sessions of unanswered challenges; the page response does not wait for it.
func (s *Server) release(chs ...*Challenge) {
	for _, ch := range chs {
		go func(ch *Challenge) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.Auth.Release(ctx, ch)
		}(ch)
	}
}

func (s *Server) loginChallenge(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	if wait, locked := s.gate.locked(now); locked {
		writeError(w, http.StatusTooManyRequests, lockedMessage(wait))
		return
	}
	if !s.gate.allowChallenge(now) {
		writeError(w, http.StatusTooManyRequests, "sign-in attempts are too frequent — wait a second")
		return
	}
	ch, err := s.Auth.Challenge(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "the router did not issue a login challenge: "+err.Error())
		return
	}
	id, stale := s.gate.addPending(ch, now)
	s.release(stale...)
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "realm": ch.Realm, "challenge": ch.Nonce})
}

type loginRequest struct {
	ID       string `json:"id"`
	Login    string `json:"login"`
	Response string `json:"response"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in loginRequest
	if !readJSON(w, r, &in) {
		return
	}
	now := s.now()
	if wait, locked := s.gate.locked(now); locked {
		writeError(w, http.StatusTooManyRequests, lockedMessage(wait))
		return
	}
	ch, fresh := s.gate.takePending(in.ID, now)
	if !fresh {
		if ch != nil {
			s.release(ch)
		}
		writeError(w, http.StatusBadRequest, "the login challenge has expired — try again")
		return
	}
	if in.Login == "" || len(in.Login) > 64 || len(in.Response) != 64 {
		s.release(ch)
		writeError(w, http.StatusBadRequest, "a login and a challenge response are required")
		return
	}
	good, err := s.Auth.Verify(r.Context(), ch, in.Login, in.Response)
	if err != nil {
		writeError(w, http.StatusBadGateway, "the router could not check the sign-in: "+err.Error())
		return
	}
	if !good {
		s.gate.fail(now)
		s.logf("failed page sign-in: %s, login %q", clientIP(r), in.Login)
		writeError(w, http.StatusUnauthorized, "wrong login or password")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.gate.newSession(now), Path: "/",
		MaxAge: int(sessionTTL / time.Second), HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.logf("page sign-in: %s, login %q", clientIP(r), in.Login)
	writeJSON(w, http.StatusOK, map[string]string{"login": in.Login})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.gate.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]string{})
}
