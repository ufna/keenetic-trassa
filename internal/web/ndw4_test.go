package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNDW4SessionOnlyAfterFirmwareSuccess(t *testing.T) {
	for _, final := range []int{200, 401} {
		t.Run(http.StatusText(final), func(t *testing.T) {
			nonce := base64.StdEncoding.EncodeToString(make([]byte, 16))
			proof := base64.StdEncoding.EncodeToString(make([]byte, 64))
			fw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					w.Header().Add("WWW-Authenticate", "x-ndw4-interactive endpoint=\"/auth\"")
					w.Header().Set("X-NDM-Realm", "test")
					w.Header().Set("X-NDM-Challenge", "test")
					http.SetCookie(w, &http.Cookie{Name: "firmware", Value: "test"})
					w.WriteHeader(401)
					return
				}
				if r.Method == "DELETE" {
					w.WriteHeader(200)
					return
				}
				if c, e := r.Cookie("firmware"); e != nil || c.Value != "test" {
					w.WriteHeader(403)
					return
				}
				var d map[string]string
				json.NewDecoder(r.Body).Decode(&d)
				if d["signature-proof"] != "" {
					w.WriteHeader(final)
					return
				}
				v := map[string]any{"salt": nonce, "nonce": nonce, "iter": 1, "memcost": 8}
				if d["proof"] != "" {
					v = map[string]any{"signature": proof}
				}
				b, _ := json.Marshal(v)
				w.Header().Set("X-NDM-Data", base64.StdEncoding.EncodeToString(b))
				w.WriteHeader(401)
			}))
			defer fw.Close()
			srv := (&Server{Auth: RouterAuth{Base: fw.URL}}).Handler()
			send := func(method, body string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, "/api/login", strings.NewReader(body))
				r.Header.Set("X-Trassa", "1")
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				srv.ServeHTTP(w, r)
				return w
			}
			w := send("GET", "")
			var d map[string]any
			json.Unmarshal(w.Body.Bytes(), &d)
			if d["protocol"] != "ndw4" {
				t.Fatal(w.Body.String())
			}
			for i, v := range []string{nonce, proof, proof} {
				id := d["id"]
				b, _ := json.Marshal(map[string]any{"id": id, "login": "admin", "response": v})
				w = send("POST", string(b))
				want := 200
				if i == 2 {
					want = final
				}
				if w.Code != want || (w.Header().Get("Set-Cookie") != "") != (i == 2 && final == 200) {
					t.Fatalf("step %d: %d %s", i, w.Code, w.Body.String())
				}
				if i < 2 {
					replay := send("POST", string(b))
					if replay.Code != 400 {
						t.Fatalf("replay accepted: %d", replay.Code)
					}
					d = map[string]any{}
					json.Unmarshal(w.Body.Bytes(), &d)
				}
			}
		})
	}
}
