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

	"trassa/internal/exits"
	"trassa/internal/rules"
	"trassa/internal/store"
)

//go:embed static
var staticFiles embed.FS

// Server — страница trassa и её HTTP-интерфейс.
type Server struct {
	Store *store.Store
	Auth  Authenticator
	// Daemon передаёт команду демону через сокет управления.
	Daemon func(cmd, arg string) (string, error)
	// Tunnels сообщает, что прошивка знает об интерфейсах выходов; nil — не спрашивать.
	Tunnels func(ctx context.Context, cfg *rules.Config) []exits.Tunnel
	// Hosts — допустимые значения заголовка Host; пусто — любые. Защищает от подмены имени в DNS.
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

// Handler возвращает обработчик всех запросов: страницу и её HTTP-интерфейс.
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
	return s.secure(mux)
}

// secure ставит заголовки защиты и отклоняет запросы на чужое имя.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if len(s.Hosts) > 0 && !slices.Contains(s.Hosts, r.Host) {
			http.Error(w, "страница trassa открывается по адресу http://"+s.Hosts[0]+"/", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// guard пропускает к данным только с действующим сеансом. Изменяющий запрос принимается только
// со страницы trassa: заголовок X-Trassa чужая страница поставить не может без разрешения сервера,
// а сервер такого разрешения не даёт.
func (s *Server) guard(needSession bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Header.Get("X-Trassa") != "1" {
			writeError(w, http.StatusForbidden, "запрос пришёл не со страницы trassa")
			return
		}
		if needSession && !s.signedIn(r) {
			writeError(w, http.StatusUnauthorized, "нужно войти")
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

// readJSON разбирает тело запроса; при ошибке отвечает сам и возвращает false.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "запрос не разобран: "+err.Error())
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
	return fmt.Sprintf("слишком много неудачных попыток входа — подождите %d с", int(wait/time.Second)+1)
}

func (s *Server) loginChallenge(w http.ResponseWriter, r *http.Request) {
	if wait, locked := s.gate.locked(s.now()); locked {
		writeError(w, http.StatusTooManyRequests, lockedMessage(wait))
		return
	}
	ch, err := s.Auth.Challenge(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "роутер не выдал вызов на вход: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": s.gate.addPending(ch, s.now()), "realm": ch.Realm, "challenge": ch.Nonce})
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
	ch, ok := s.gate.takePending(in.ID, now)
	if !ok {
		writeError(w, http.StatusBadRequest, "вызов на вход устарел — попробуйте ещё раз")
		return
	}
	if in.Login == "" || len(in.Login) > 64 || len(in.Response) != 64 {
		writeError(w, http.StatusBadRequest, "нужны логин и ответ на вызов")
		return
	}
	good, err := s.Auth.Verify(r.Context(), ch, in.Login, in.Response)
	if err != nil {
		writeError(w, http.StatusBadGateway, "роутер не проверил вход: "+err.Error())
		return
	}
	if !good {
		s.gate.fail(now)
		s.logf("неудачный вход на страницу: %s, логин %q", clientIP(r), in.Login)
		writeError(w, http.StatusUnauthorized, "неверный логин или пароль")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.gate.newSession(now), Path: "/",
		MaxAge: int(sessionTTL / time.Second), HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.logf("вход на страницу: %s, логин %q", clientIP(r), in.Login)
	writeJSON(w, http.StatusOK, map[string]string{"login": in.Login})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.gate.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, map[string]string{})
}
