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
	Severity string `json:"severity"` // error or warning
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
	Daemon      *ctl.State     `json:"daemon"`      // nil means the daemon is not answering
	DaemonState string         `json:"daemonState"` // running, not-running, no-reply or error
	DaemonError string         `json:"daemonError,omitempty"`
	Enabled     bool           `json:"enabled"` // false: trassa is turned off and the daemon is not started
	Tunnels     []exits.Tunnel `json:"tunnels"`
	Now         time.Time      `json:"now"`
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	out := stateJSON{Tunnels: []exits.Tunnel{}, Now: s.now(), Enabled: !s.Store.Disabled()}
	text, err := s.Daemon("state", "")
	if err == nil {
		var st ctl.State
		if err = json.Unmarshal([]byte(text), &st); err == nil {
			out.Daemon = &st
		}
	}
	switch {
	case err == nil:
		out.DaemonState = "running"
	case errors.Is(err, ctl.ErrNoDaemon):
		out.DaemonState = "not-running"
	case errors.Is(err, ctl.ErrNoReply):
		out.DaemonState = "no-reply"
	default:
		out.DaemonState = "error"
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
		writeError(w, http.StatusNotFound, "cannot read the rules file: "+err.Error())
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
		writeError(w, http.StatusInternalServerError, "rules not saved: "+err.Error())
		return
	}
	if res.Saved || res.Applied == store.Rejected {
		s.logf("rules saved from the page (%s): %s — %s", clientIP(r), res.Applied, res.Message)
	}
	writeJSON(w, http.StatusOK, toResult(res))
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	h, err := s.Store.History()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot read the history: "+err.Error())
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
		s.logf("version %s restored from the page (%s): %s — %s", in.ID, clientIP(r), res.Applied, res.Message)
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
		writeError(w, http.StatusBadRequest, "enter a name, address or link")
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
	// The daemon is not answering: answer from the rules file alone, without DNS data.
	cur, err := s.Store.Current()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot read the rules file: "+err.Error())
		return
	}
	cfg, ps := store.Load(s.Store.Dir, cur)
	if rules.HasErrors(ps) {
		writeError(w, http.StatusConflict, "the rules file has errors — fix them first")
		return
	}
	if text, err = cfg.Explain(in.Subject); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"text": text, "source": "file"})
}

// power turns trassa on or off. Off: the mark is written first, then the daemon is asked to stop;
// the init script does not restart it while the mark exists and starts it within seconds once the
// mark is gone.
func (s *Server) power(w http.ResponseWriter, r *http.Request) {
	var in struct {
		On *bool `json:"on"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.On == nil {
		writeError(w, http.StatusBadRequest, "on is required: true or false")
		return
	}
	if *in.On {
		if err := s.Store.Enable(); err != nil {
			writeError(w, http.StatusInternalServerError, "trassa not turned on: "+err.Error())
			return
		}
		s.logf("trassa turned on from the page (%s)", clientIP(r))
		writeJSON(w, http.StatusOK, map[string]any{"enabled": true,
			"message": "trassa is turned on: the daemon starts within a few seconds"})
		return
	}
	if err := s.Store.Disable(); err != nil {
		writeError(w, http.StatusInternalServerError, "trassa not turned off: "+err.Error())
		return
	}
	s.logf("trassa turned off from the page (%s)", clientIP(r))
	msg := "trassa is turned off: the daemon is stopping and removing its routes, traffic goes as without trassa"
	if _, err := s.Daemon("stop", ""); err != nil && !errors.Is(err, ctl.ErrNoDaemon) {
		msg = "trassa is turned off, but the daemon did not confirm the stop: " + err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "message": msg})
}
