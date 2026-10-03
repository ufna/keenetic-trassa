// Package web is the trassa page on the router: rule editing, "why", status and version history.
package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// Authenticator checks an administrator sign-in with the router.
type Authenticator interface {
	// Challenge gets a one-time login challenge from the router.
	Challenge(ctx context.Context) (*Challenge, error)
	// Verify passes the challenge response to the router: true means the login and password are
	// correct. The firmware session opened by the challenge is closed afterwards whatever the outcome.
	Verify(ctx context.Context, ch *Challenge, login, response string) (bool, error)
	// Release closes the firmware session of a challenge that was never answered.
	Release(ctx context.Context, ch *Challenge)
}

// Challenge is a router login challenge. It is bound to a firmware session, and the session to a cookie in Jar.
type Challenge struct {
	Realm string
	Nonce string
	Jar   http.CookieJar
}

// RouterAuth asks the firmware web server with the same /auth request its own page uses.
// The password never reaches trassa: the browser sends sha256(challenge + md5(login:realm:password)).
type RouterAuth struct {
	Base    string        // e.g. http://127.0.0.1:79
	Timeout time.Duration // 0 means 5 seconds
}

func (a RouterAuth) client(jar http.CookieJar) *http.Client {
	t := a.Timeout
	if t == 0 {
		t = 5 * time.Second
	}
	return &http.Client{Jar: jar, Timeout: t}
}

func drain(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

func (a RouterAuth) Challenge(ctx context.Context) (*Challenge, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.Base+"/auth", nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client(jar).Do(req)
	if err != nil {
		return nil, fmt.Errorf("firmware is not responding: %w", err)
	}
	drain(resp)
	ch := &Challenge{Realm: resp.Header.Get("X-NDM-Realm"), Nonce: resp.Header.Get("X-NDM-Challenge"), Jar: jar}
	if resp.StatusCode != http.StatusUnauthorized || ch.Realm == "" || ch.Nonce == "" {
		return nil, fmt.Errorf("firmware did not issue a login challenge (status %d)", resp.StatusCode)
	}
	return ch, nil
}

func (a RouterAuth) Verify(ctx context.Context, ch *Challenge, login, response string) (bool, error) {
	body, err := json.Marshal(map[string]string{"login": login, "password": response})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Base+"/auth", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client(ch.Jar).Do(req)
	if err != nil {
		return false, fmt.Errorf("firmware is not responding: %w", err)
	}
	drain(resp)
	// The firmware session is no longer needed whatever the outcome: the trassa page has its own.
	a.Release(ctx, ch)
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	}
	return false, fmt.Errorf("firmware answered the sign-in with status %d", resp.StatusCode)
}

func (a RouterAuth) Release(ctx context.Context, ch *Challenge) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, a.Base+"/auth", nil)
	if err != nil {
		return
	}
	if resp, err := a.client(ch.Jar).Do(req); err == nil {
		drain(resp)
	}
}
