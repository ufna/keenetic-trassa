// Package exits узнаёт у прошивки состояние туннелей и выбирает рабочий интерфейс выхода.
package exits

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"trassa/internal/rules"
)

// Status — что прошивка сообщает об интерфейсе.
type Status struct {
	Name   string // имя в прошивке, например Wireguard2
	Exists bool
	Type   string // тип в прошивке, например Wireguard
	System string // системное имя, например nwg2; пусто, если интерфейс не может быть выходом
	Up     bool
	// Description — описание из настроек прошивки.
	Description string
}

// Source отвечает на вопрос о состоянии интерфейса. В тестах подменяется.
type Source interface {
	Interface(ctx context.Context, name string) (Status, error)
}

// RCI спрашивает прошивку по её локальному адресу.
type RCI struct {
	Base   string // например http://127.0.0.1:79
	Client *http.Client
}

type ifaceJSON struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Index       *int   `json:"index"`
	Type        string `json:"type"`
	Link        string `json:"link"`
	Connected   string `json:"connected"`
	Wireguard   struct {
		Peer []struct {
			Online bool `json:"online"`
		} `json:"peer"`
	} `json:"wireguard"`
}

func (r RCI) Interface(ctx context.Context, name string) (Status, error) {
	st := Status{Name: name}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.Base+"/rci/show/interface/"+url.PathEscape(name), nil)
	if err != nil {
		return st, err
	}
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return st, fmt.Errorf("прошивка не отвечает: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return st, nil
	}
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("прошивка ответила кодом %d", resp.StatusCode)
	}
	var j ifaceJSON
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&j); err != nil {
		return st, fmt.Errorf("ответ прошивки не разобран: %w", err)
	}
	if j.ID == "" {
		return st, nil
	}
	st.Exists, st.Type, st.Description = true, j.Type, j.Description
	if j.Type != "Wireguard" || j.Index == nil {
		return st, nil
	}
	st.System = "nwg" + strconv.Itoa(*j.Index)
	if j.Link == "up" && j.Connected == "yes" {
		for _, p := range j.Wireguard.Peer {
			if p.Online {
				st.Up = true
				break
			}
		}
	}
	return st, nil
}

// Validate проверяет интерфейсы всех выходов: каждый должен существовать и быть туннелем WireGuard.
func Validate(ctx context.Context, cfg *rules.Config, src Source) []rules.Problem {
	var ps []rules.Problem
	bad := func(line int, format string, args ...any) {
		ps = append(ps, rules.Problem{Line: line, Severity: rules.Error, Msg: fmt.Sprintf(format, args...)})
	}
	for _, e := range cfg.Exits {
		for _, name := range e.Interfaces {
			st, err := src.Interface(ctx, name)
			switch {
			case err != nil:
				bad(e.Line, "интерфейс %s: %v", name, err)
			case !st.Exists:
				bad(e.Line, "интерфейс %s не существует на роутере", name)
			case st.System == "":
				bad(e.Line, "интерфейс %s имеет тип %s: выходом может быть только туннель WireGuard", name, st.Type)
			}
		}
	}
	return ps
}

// Choice — интерфейс, выбранный для выхода. Пустой System означает, что живых интерфейсов нет.
type Choice struct {
	Interface string // имя в прошивке
	System    string // системное имя
}

// Active выбирает для каждого выхода первый живой интерфейс по порядку из файла правил.
// Молчание прошивки — не то же самое, что упавший туннель: если живого интерфейса не нашлось,
// но о каком-то интерфейсе выхода прошивка не ответила, за выходом остаётся прежний выбор из prev.
// Ошибка возвращается, только если прошивка не ответила ни на один запрос.
func Active(ctx context.Context, cfg *rules.Config, src Source, prev map[string]Choice) (map[string]Choice, error) {
	out := make(map[string]Choice, len(cfg.Exits))
	asked, answered := 0, 0
	var last error
	for _, e := range cfg.Exits {
		var choice Choice
		silent := false
		for _, name := range e.Interfaces {
			asked++
			st, err := src.Interface(ctx, name)
			if err != nil {
				last, silent = err, true
				continue
			}
			answered++
			if st.Up && choice.System == "" {
				choice = Choice{Interface: name, System: st.System}
			}
		}
		if choice.System == "" && silent {
			choice = prev[e.Name]
		}
		out[e.Name] = choice
	}
	if asked > 0 && answered == 0 {
		return nil, last
	}
	return out, nil
}

// Tunnel — интерфейс выхода и что о нём знает прошивка; для страницы.
type Tunnel struct {
	Exit        string `json:"exit"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Up          bool   `json:"up"`
	Error       string `json:"error,omitempty"`
}

// Tunnels спрашивает прошивку обо всех интерфейсах всех выходов, по порядку из файла правил.
func Tunnels(ctx context.Context, cfg *rules.Config, src Source) []Tunnel {
	out := []Tunnel{}
	for _, e := range cfg.Exits {
		for _, name := range e.Interfaces {
			t := Tunnel{Exit: e.Name, Name: name}
			st, err := src.Interface(ctx, name)
			switch {
			case err != nil:
				t.Error = err.Error()
			case !st.Exists:
				t.Error = "интерфейса нет на роутере"
			default:
				t.Description, t.Up = st.Description, st.Up
			}
			out = append(out, t)
		}
	}
	return out
}
