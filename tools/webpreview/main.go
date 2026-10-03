// webpreview serves the trassa page without a router, for screenshots during development.
// It is not part of the trassa binary.
//
//	go run ./tools/webpreview                                  — demo: rules from rules/rules.conf
//	go run ./tools/webpreview -router http://192.168.1.1:8090  — the real router page
//
// The page opens already signed in: http://127.0.0.1:8091/
package main

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trassa/internal/ctl"
	"trassa/internal/exits"
	"trassa/internal/rules"
	"trassa/internal/store"
	"trassa/internal/web"
)

func answer(login, password, realm, nonce string) string {
	m := md5.Sum([]byte(login + ":" + realm + ":" + password))
	s := sha256.Sum256([]byte(nonce + hex.EncodeToString(m[:])))
	return hex.EncodeToString(s[:])
}

// demoAuth lets in admin with password demo.
type demoAuth struct{}

func (demoAuth) Challenge(ctx context.Context) (*web.Challenge, error) {
	return &web.Challenge{Realm: "Netcraze Giga", Nonce: "DEMO"}, nil
}

func (demoAuth) Verify(ctx context.Context, ch *web.Challenge, login, response string) (bool, error) {
	return login == "admin" && response == answer("admin", "demo", ch.Realm, ch.Nonce), nil
}

func (demoAuth) Release(ctx context.Context, ch *web.Challenge) {}

// signIn signs in to the page and returns the session cookie. do performs a request.
func signIn(do func(*http.Request) (*http.Response, error), base, password string) (*http.Cookie, error) {
	req, _ := http.NewRequest(http.MethodGet, base+"/api/login", nil)
	req.Header.Set("X-Trassa", "1")
	resp, err := do(req)
	if err != nil {
		return nil, err
	}
	var ch map[string]string
	json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()
	body, _ := json.Marshal(map[string]string{"id": ch["id"], "login": "admin",
		"response": answer("admin", password, ch["realm"], ch["challenge"])})
	req, _ = http.NewRequest(http.MethodPost, base+"/api/login", strings.NewReader(string(body)))
	req.Header.Set("X-Trassa", "1")
	req.Header.Set("Content-Type", "application/json")
	if resp, err = do(req); err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == "trassa_session" {
			return c, nil
		}
	}
	b, _ := io.ReadAll(resp.Body)
	return nil, fmt.Errorf("sign-in failed: %s %s", resp.Status, b)
}

// demo is the page with rules from rulesPath and a made-up but plausible daemon state; off starts
// it with trassa turned off.
func demo(rulesPath string, off bool) (http.Handler, error) {
	text, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "trassa-preview-")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, store.RulesFile), text, 0o644); err != nil {
		return nil, err
	}
	st := &store.Store{Dir: dir, Apply: func() (store.Applied, string) { return store.Running, "rules reloaded" }}
	st.Save(string(text)+"# example edit from the page\n", true)
	if off {
		st.Disable()
	}
	now := time.Now()
	state := ctl.State{Mode: "route", Started: now.Add(-124 * time.Minute), Rules: 12, Addrs: 25, Claims: 33,
		Stats: ctl.Stats{Packets: 1140, Answers: 870, Claimed: 31, Changes: 50},
		Exits: []ctl.ExitState{{Name: "vpn", Via: "Wireguard2", Known: true}},
		Recent: []ctl.Observation{
			{At: now.Add(-5 * time.Second), Client: "192.168.1.97", Name: "ps5.np.playstation.net", Action: "direct"},
			{At: now.Add(-20 * time.Second), Client: "192.168.1.94", Name: "www.youtube.com", Action: "vpn", Line: 8},
			{At: now.Add(-41 * time.Second), Client: "fe80::c803:47ff:fe04:97ae", Name: "passport.yandex.by", Action: "direct"},
			{At: now.Add(-63 * time.Second), Client: "192.168.1.94", Name: "t.me", Action: "vpn", Line: 13},
		}}
	desc := map[string]string{"Wireguard0": "tunnel-b", "Wireguard1": "tunnel-c", "Wireguard2": "tunnel-a",
		"Wireguard3": "tunnel-d", "Wireguard4": "tunnel-e"}
	srv := &web.Server{
		Store: st,
		Auth:  demoAuth{},
		Daemon: func(cmd, arg string) (string, error) {
			if cmd == "stop" {
				return "trassa is stopping\n", nil
			}
			if cmd == "state" && !st.Disabled() {
				b, _ := json.Marshal(state)
				return string(b), nil
			}
			return "", fmt.Errorf("%w (demo)", ctl.ErrNoDaemon)
		},
		Tunnels: func(ctx context.Context, cfg *rules.Config) []exits.Tunnel {
			var out []exits.Tunnel
			for _, e := range cfg.Exits {
				for _, n := range e.Interfaces {
					out = append(out, exits.Tunnel{Exit: e.Name, Name: n, ID: n, Description: desc[n], Up: n == "Wireguard2"})
				}
			}
			return out
		},
	}
	return srv.Handler(), nil
}

// withCookie adds the session cookie to every request.
func withCookie(h http.Handler, c *http.Cookie) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie(c.Name); err != nil {
			r.AddCookie(c)
		}
		h.ServeHTTP(w, r)
	})
}

var gif1x1 = []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

// withWait delays the page load event by two seconds: Firefox takes the screenshot on that event,
// while the page fetches its data after parsing — without the delay the screenshot would be empty.
func withWait(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__wait":
			time.Sleep(2 * time.Second)
			w.Header().Set("Content-Type", "image/gif")
			w.Write(gif1x1)
		case "/":
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			for k, v := range rec.Header() {
				if k != "Content-Length" {
					w.Header()[k] = v
				}
			}
			w.WriteHeader(rec.Code)
			io.WriteString(w, strings.Replace(rec.Body.String(), "</body>", `<img src="/__wait" alt="" hidden></body>`, 1))
		default:
			h.ServeHTTP(w, r)
		}
	})
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8091", "address to serve on")
	rulesPath := flag.String("rules", "rules/rules.conf", "rules file for the demo")
	router := flag.String("router", "", "address of the real page, e.g. http://192.168.1.1:8090")
	passFile := flag.String("pass", "backup/.router-pass", "file with the router administrator password")
	off := flag.Bool("off", false, "demo: start with trassa turned off")
	flag.Parse()

	var h http.Handler
	if *router == "" {
		inner, err := demo(*rulesPath, *off)
		if err != nil {
			log.Fatal(err)
		}
		local := func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			inner.ServeHTTP(rec, r)
			return rec.Result(), nil
		}
		c, err := signIn(local, "", "demo")
		if err != nil {
			log.Fatal(err)
		}
		h = withCookie(inner, c)
	} else {
		target, err := url.Parse(*router)
		if err != nil {
			log.Fatal(err)
		}
		pass, err := os.ReadFile(*passFile)
		if err != nil {
			log.Fatal(err)
		}
		c, err := signIn(http.DefaultClient.Do, *router, strings.TrimSpace(string(pass)))
		if err != nil {
			log.Fatal(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		director := proxy.Director
		proxy.Director = func(r *http.Request) { director(r); r.Host = target.Host }
		h = withCookie(proxy, c)
	}
	log.Printf("page: http://%s/", *listen)
	// Only this address: the -router mode carries a live session to the real router, and a page
	// that rebinds its own name to 127.0.0.1 must not reach it.
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != *listen {
			http.Error(w, "open http://"+*listen+"/", http.StatusMisdirectedRequest)
			return
		}
		withWait(h).ServeHTTP(w, r)
	})
	log.Fatal(http.ListenAndServe(*listen, guarded))
}
