package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func supportsNDW4(h http.Header) bool {
	for _, v := range h.Values("WWW-Authenticate") {
		fields := strings.Fields(v)
		if len(fields) > 0 && strings.EqualFold(fields[0], "x-ndw4-interactive") {
			return true
		}
	}
	return false
}

func validProof(s string, n int) bool {
	b, e := base64.StdEncoding.DecodeString(s)
	return e == nil && len(b) == n && base64.StdEncoding.EncodeToString(b) == s
}

func (s *Server) loginNDW4(w http.ResponseWriter, r *http.Request, ch *Challenge, in loginRequest, now time.Time) {
	a, ok := s.Auth.(RouterAuth)
	if !ok {
		s.release(ch)
		writeError(w, 502, "NDW4 unavailable")
		return
	}
	size := 64
	if ch.step == 0 {
		size = 16
	}
	if in.Login == "" || len(in.Login) > 64 || !validProof(in.Response, size) || (ch.step > 0 && ch.login != in.Login) {
		s.release(ch)
		writeError(w, 400, "invalid NDW4 request")
		return
	}
	payload := map[string]string{"login": in.Login}
	switch ch.step {
	case 0:
		payload["nonce"] = in.Response
	case 1:
		payload["nonce"] = ch.serverNonce
		payload["proof"] = in.Response
	case 2:
		payload["nonce"] = ch.serverNonce
		payload["signature-proof"] = in.Response
	default:
		s.release(ch)
		writeError(w, 400, "invalid NDW4 step")
		return
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, a.base(ch)+"/auth", bytes.NewReader(b))
	if err != nil {
		s.release(ch)
		writeError(w, 502, "invalid firmware endpoint")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client(ch.Jar).Do(req)
	if err != nil {
		s.release(ch)
		writeError(w, 502, "firmware did not answer NDW4")
		return
	}
	drain(resp)
	if ch.step == 2 && resp.StatusCode == 200 {
		s.release(ch)
		s.loginSuccess(w, r, in.Login, now)
		return
	}
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		s.release(ch)
		writeError(w, 502, "unexpected firmware reply to NDW4")
		return
	}
	if ch.step == 2 || resp.StatusCode != 401 {
		s.release(ch)
		s.gate.fail(now)
		writeError(w, 401, "Keenetic rejected NDW4 sign-in")
		return
	}
	var d struct {
		Salt      string `json:"salt"`
		Nonce     string `json:"nonce"`
		Iter      int    `json:"iter"`
		Memcost   int    `json:"memcost"`
		Signature string `json:"signature"`
	}
	data, err := base64.StdEncoding.DecodeString(resp.Header.Get("X-NDM-Data"))
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &d) != nil ||
		(ch.step == 0 && (!validProof(d.Salt, 16) || d.Nonce == "" || len(d.Nonce) > 256 || d.Iter < 1 || d.Iter > 20 || d.Memcost < 8 || d.Memcost > 262144)) ||
		(ch.step == 1 && !validProof(d.Signature, 64)) {
		s.release(ch)
		s.gate.fail(now)
		writeError(w, 401, "Keenetic rejected NDW4 sign-in")
		return
	}
	// Count proof submissions even if the browser aborts on a server signature mismatch.
	if ch.step == 1 {
		s.gate.fail(now)
	}
	if ch.step == 0 {
		ch.serverNonce = d.Nonce
		ch.login = in.Login
	}
	ch.step++
	id, stale := s.gate.addPending(ch, now)
	s.release(stale...)
	writeJSON(w, 200, map[string]any{"id": id, "data": d})
}
