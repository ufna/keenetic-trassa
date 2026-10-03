package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"trassa/internal/ctl"
	"trassa/internal/exits"
	"trassa/internal/rules"
	"trassa/internal/store"
)

type problemJSON struct {
	Line     int    `json:"line"`
	Severity string `json:"severity"` // error или warning
	Msg      string `json:"msg"`
}

func problemsJSON(ps []rules.Problem) []problemJSON {
	out := make([]problemJSON, 0, len(ps))
	for _, p := range ps {
		sev := "error"
		if p.Severity == rules.Warning {
			sev = "warning"
		}
		out = append(out, problemJSON{p.Line, sev, p.Msg})
	}
	return out
}

type checkJSON struct {
	Problems []problemJSON `json:"problems"`
	Rules    int           `json:"rules"`
	Exits    int           `json:"exits"`
	Tests    int           `json:"tests"`
}

type resultJSON struct {
	checkJSON
	NeedConfirm bool   `json:"needConfirm"`
	Unchanged   bool   `json:"unchanged"`
	Saved       bool   `json:"saved"`
	Applied     string `json:"applied"`
	Message     string `json:"message"`
}

func toResult(res store.Result) resultJSON {
	return resultJSON{
		checkJSON:   checkJSON{problemsJSON(res.Problems), res.Rules, res.Exits, res.Tests},
		NeedConfirm: res.NeedConfirm, Unchanged: res.Unchanged, Saved: res.Saved,
		Applied: res.Applied.String(), Message: res.Message,
	}
}

type stateJSON struct {
	Daemon      *ctl.State     `json:"daemon"` // nil — демон не отвечает
	DaemonError string         `json:"daemonError,omitempty"`
	Tunnels     []exits.Tunnel `json:"tunnels"`
	Now         time.Time      `json:"now"`
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	out := stateJSON{Tunnels: []exits.Tunnel{}, Now: s.now()}
	text, err := s.Daemon("state", "")
	if err == nil {
		var st ctl.State
		if err = json.Unmarshal([]byte(text), &st); err == nil {
			out.Daemon = &st
		}
	}
	if err != nil {
		out.DaemonError = err.Error()
	}
	if s.Tunnels != nil {
		if cur, err := s.Store.Current(); err == nil {
			if cfg, ps := store.Load(s.Store.Dir, cur); !rules.HasErrors(ps) {
				if t := s.Tunnels(r.Context(), cfg); t != nil {
					out.Tunnels = t
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) rulesText(w http.ResponseWriter, r *http.Request) {
	text, err := s.Store.Current()
	if err != nil {
		writeError(w, http.StatusNotFound, "файл правил не прочитан: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"text": text})
}

type textRequest struct {
	Text    string `json:"text"`
	Confirm bool   `json:"confirm"`
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	var in textRequest
	if !readJSON(w, r, &in) {
		return
	}
	cfg, ps := s.Store.Check(in.Text)
	out := checkJSON{Problems: problemsJSON(ps)}
	if cfg != nil {
		out.Rules, out.Exits, out.Tests = len(cfg.Rules), len(cfg.Exits), len(cfg.Tests)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) save(w http.ResponseWriter, r *http.Request) {
	var in textRequest
	if !readJSON(w, r, &in) {
		return
	}
	res, err := s.Store.Save(in.Text, in.Confirm)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "правила не сохранены: "+err.Error())
		return
	}
	if res.Saved || res.Applied == store.Rejected {
		s.logf("правила сохранены со страницы (%s): %s — %s", clientIP(r), res.Applied, res.Message)
	}
	writeJSON(w, http.StatusOK, toResult(res))
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	h, err := s.Store.History()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "история не прочитана: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	text, err := s.Store.Version(r.URL.Query().Get("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"text": text})
}

type rollbackRequest struct {
	ID      string `json:"id"`
	Confirm bool   `json:"confirm"`
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	var in rollbackRequest
	if !readJSON(w, r, &in) {
		return
	}
	res, err := s.Store.Rollback(in.ID, in.Confirm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if res.Saved || res.Applied == store.Rejected {
		s.logf("возврат версии %s со страницы (%s): %s — %s", in.ID, clientIP(r), res.Applied, res.Message)
	}
	writeJSON(w, http.StatusOK, toResult(res))
}

type whyRequest struct {
	Subject string `json:"subject"`
}

func (s *Server) why(w http.ResponseWriter, r *http.Request) {
	var in whyRequest
	if !readJSON(w, r, &in) {
		return
	}
	if in.Subject == "" || len(in.Subject) > 2048 {
		writeError(w, http.StatusBadRequest, "введите имя, адрес или ссылку")
		return
	}
	text, err := s.Daemon("why", in.Subject)
	if err == nil {
		writeJSON(w, http.StatusOK, map[string]string{"text": text, "source": "daemon"})
		return
	}
	if !errors.Is(err, ctl.ErrNoDaemon) && !errors.Is(err, ctl.ErrNoReply) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Демон не отвечает — ответ по одному файлу правил, без сведений из DNS.
	cur, err := s.Store.Current()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "файл правил не прочитан: "+err.Error())
		return
	}
	cfg, ps := store.Load(s.Store.Dir, cur)
	if rules.HasErrors(ps) {
		writeError(w, http.StatusConflict, "в файле правил ошибки — сначала исправьте их")
		return
	}
	if text, err = cfg.Explain(in.Subject); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"text": text, "source": "file"})
}
