// Package web — страница trassa на роутере: правка правил, «почему», состояние, история версий.
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

// Authenticator проверяет вход администратора у роутера.
type Authenticator interface {
	// Challenge получает у роутера одноразовый вызов на вход.
	Challenge(ctx context.Context) (*Challenge, error)
	// Verify передаёт роутеру ответ на вызов: true — логин и пароль верны.
	Verify(ctx context.Context, ch *Challenge, login, response string) (bool, error)
}

// Challenge — вызов роутера. Вызов привязан к сеансу прошивки, а сеанс — к cookie в Jar.
type Challenge struct {
	Realm string
	Nonce string
	Jar   http.CookieJar
}

// RouterAuth спрашивает веб-сервер прошивки тем же запросом /auth, что и его собственная страница.
// Пароль до trassa не доходит: браузер присылает sha256(вызов + md5(логин:realm:пароль)).
type RouterAuth struct {
	Base    string        // например http://127.0.0.1:79
	Timeout time.Duration // 0 — 5 секунд
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
		return nil, fmt.Errorf("прошивка не отвечает: %w", err)
	}
	drain(resp)
	ch := &Challenge{Realm: resp.Header.Get("X-NDM-Realm"), Nonce: resp.Header.Get("X-NDM-Challenge"), Jar: jar}
	if resp.StatusCode != http.StatusUnauthorized || ch.Realm == "" || ch.Nonce == "" {
		return nil, fmt.Errorf("прошивка не выдала вызов на вход (код %d)", resp.StatusCode)
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
	c := a.client(ch.Jar)
	resp, err := c.Do(req)
	if err != nil {
		return false, fmt.Errorf("прошивка не отвечает: %w", err)
	}
	drain(resp)
	switch resp.StatusCode {
	case http.StatusOK:
		// Сеанс прошивки больше не нужен: у страницы trassa свой.
		if req, err := http.NewRequestWithContext(ctx, http.MethodDelete, a.Base+"/auth", nil); err == nil {
			if resp, err := c.Do(req); err == nil {
				drain(resp)
			}
		}
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	}
	return false, fmt.Errorf("прошивка ответила на вход кодом %d", resp.StatusCode)
}
