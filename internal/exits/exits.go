// Package exits asks the firmware about tunnel state and picks a working interface for each exit.
package exits

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"trassa/internal/rules"
)

// Status is what the firmware reports about an interface.
type Status struct {
	Name   string // as written in the rules: a firmware name (Wireguard2) or a description (tunnel-a)
	ID     string // firmware name, e.g. Wireguard2; empty if the interface does not exist
	Exists bool
	Type   string // firmware type, e.g. Wireguard
	System string // system name, e.g. nwg2; empty if the interface cannot be an exit
	Up     bool
	// Description is the description from the firmware settings.
	Description string
}

// Source answers questions about interface state. Tests substitute it.
type Source interface {
	Interface(ctx context.Context, name string) (Status, error)
}

// RCI queries the firmware at its local address. An interface may be named by its firmware
// name (Wireguard2) or by its description in the firmware settings (tunnel-a).
type RCI struct {
	Base   string // e.g. http://127.0.0.1:79
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

func (r RCI) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return http.DefaultClient
}

func (r RCI) Interface(ctx context.Context, name string) (Status, error) {
	st, err := r.byID(ctx, name)
	if err != nil || st.Exists {
		st.Name = name
		return st, err
	}
	id, err := r.byDescription(ctx, name)
	if err != nil || id == "" {
		return Status{Name: name}, err
	}
	st, err = r.byID(ctx, id)
	st.Name = name
	return st, err
}

// byID asks the firmware about the interface with this firmware name.
func (r RCI) byID(ctx context.Context, id string) (Status, error) {
	var st Status
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.Base+"/rci/show/interface/"+url.PathEscape(id), nil)
	if err != nil {
		return st, err
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return st, fmt.Errorf("firmware does not respond: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return st, nil
	}
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("firmware answered with code %d", resp.StatusCode)
	}
	var j ifaceJSON
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&j); err != nil {
		return st, fmt.Errorf("cannot parse firmware answer: %w", err)
	}
	if j.ID == "" {
		return st, nil
	}
	st.ID, st.Exists, st.Type, st.Description = j.ID, true, j.Type, j.Description
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

// byDescription finds the firmware name of the interface with this description; "" if there is
// none. A description shared by several interfaces is an error: the rule would be ambiguous.
func (r RCI) byDescription(ctx context.Context, desc string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.Base+"/rci/show/interface", nil)
	if err != nil {
		return "", err
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("firmware does not respond: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("firmware answered with code %d", resp.StatusCode)
	}
	var all map[string]struct {
		ID          string `json:"id"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&all); err != nil {
		return "", fmt.Errorf("cannot parse firmware answer: %w", err)
	}
	var found []string
	for key, v := range all {
		if v.Description != desc {
			continue
		}
		id := v.ID
		if id == "" {
			id = key
		}
		if !slices.Contains(found, id) {
			found = append(found, id)
		}
	}
	sort.Strings(found)
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		return found[0], nil
	}
	return "", fmt.Errorf("description %q matches several interfaces: %s", desc, strings.Join(found, ", "))
}

// Validate checks the interfaces of all exits: each must exist and be a WireGuard tunnel.
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
				bad(e.Line, "interface %s: %v", name, err)
			case !st.Exists:
				bad(e.Line, "interface %s does not exist on the router", name)
			case st.System == "":
				bad(e.Line, "interface %s has type %s: only a WireGuard tunnel can be an exit", name, st.Type)
			}
		}
	}
	return ps
}

// Choice is the interface chosen for an exit. An empty System means no interface is live.
type Choice struct {
	Interface string // firmware name
	System    string // system name
}

// Active picks, for each exit, the first live interface in rules file order.
// Firmware silence is not the same as a tunnel being down: if no live interface was found
// but the firmware did not answer about some interface of the exit, the exit keeps its previous choice from prev.
// An error is returned only if the firmware answered none of the requests.
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

// Tunnel is an exit interface and what the firmware knows about it; used by the web page.
type Tunnel struct {
	Exit        string `json:"exit"`
	Name        string `json:"name"` // as written in the rules
	ID          string `json:"id"`   // firmware name
	Description string `json:"description"`
	Up          bool   `json:"up"`
	Error       string `json:"error,omitempty"`
}

// Tunnels asks the firmware about every interface of every exit, in rules file order.
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
				t.Error = "no such interface on the router"
			default:
				t.ID, t.Description, t.Up = st.ID, st.Description, st.Up
			}
			out = append(out, t)
		}
	}
	return out
}
