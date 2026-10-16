package exits

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ufna/keenetic-trassa/internal/rules"
)

const (
	wgUp     = `{"id":"Wireguard2","description":"tunnel-a","index":2,"type":"Wireguard","link":"up","connected":"yes","wireguard":{"peer":[{"online":false},{"online":true}]}}`
	wgDown   = `{"id":"Wireguard0","index":0,"type":"Wireguard","link":"down","connected":"no"}`
	wgNoPeer = `{"id":"Wireguard3","index":3,"type":"Wireguard","link":"up","connected":"yes","wireguard":{"peer":[{"online":false}]}}`
	ethernet = `{"id":"GigabitEthernet1","index":1,"type":"GigabitEthernet","link":"up","connected":"yes"}`
)

// ifaceList is "show interface" as the firmware returns it: switch ports appear under numeric keys.
const ifaceList = `{
	"Wireguard2": {"id": "Wireguard2", "description": "tunnel-a", "type": "Wireguard"},
	"Wireguard0": {"id": "Wireguard0", "description": "tunnel-b", "type": "Wireguard"},
	"Wireguard3": {"id": "Wireguard3", "description": "dup", "type": "Wireguard"},
	"GigabitEthernet1": {"id": "GigabitEthernet1", "description": "dup", "type": "GigabitEthernet"},
	"1": {"id": "GigabitEthernet0/0", "description": "", "type": "Port"}
}`

func firmware(t *testing.T) RCI {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/rci/show/interface/") {
		case "Wireguard2":
			w.Write([]byte(wgUp))
		case "Wireguard0":
			w.Write([]byte(wgDown))
		case "Wireguard3":
			w.Write([]byte(wgNoPeer))
		case "GigabitEthernet1":
			w.Write([]byte(ethernet))
		case "Broken":
			w.WriteHeader(http.StatusInternalServerError)
		case "Garbage":
			w.Write([]byte("<html>"))
		case "Empty":
			w.Write([]byte("{}"))
		case "/rci/show/interface": // the whole list, keyed by firmware name
			w.Write([]byte(ifaceList))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return RCI{Base: srv.URL, Client: srv.Client()}
}

func config(t *testing.T, s string) *rules.Config {
	t.Helper()
	cfg, ps := rules.Load(s, nil)
	if rules.HasErrors(ps) {
		t.Fatalf("rules: %v", ps)
	}
	return cfg
}

func TestInterface(t *testing.T) {
	src := firmware(t)
	ctx := context.Background()
	cases := []struct {
		name string
		want Status
	}{
		{"Wireguard2", Status{Name: "Wireguard2", ID: "Wireguard2", Exists: true, Type: "Wireguard", System: "nwg2", Up: true, Description: "tunnel-a"}},
		{"Wireguard0", Status{Name: "Wireguard0", ID: "Wireguard0", Exists: true, Type: "Wireguard", System: "nwg0"}},
		{"Wireguard3", Status{Name: "Wireguard3", ID: "Wireguard3", Exists: true, Type: "Wireguard", System: "nwg3"}},
		{"GigabitEthernet1", Status{Name: "GigabitEthernet1", ID: "GigabitEthernet1", Exists: true, Type: "GigabitEthernet"}},
		{"Nope", Status{Name: "Nope"}},
		{"Empty", Status{Name: "Empty"}},
	}
	for _, c := range cases {
		got, err := src.Interface(ctx, c.name)
		if err != nil || got != c.want {
			t.Errorf("%s: %+v, %v; want %+v", c.name, got, err, c.want)
		}
	}
	for _, name := range []string{"Broken", "Garbage"} {
		if st, err := src.Interface(ctx, name); err == nil {
			t.Errorf("%s: want an error, got %+v", name, st)
		}
	}
	dead := RCI{Base: "http://127.0.0.1:1"}
	if _, err := dead.Interface(ctx, "Wireguard2"); err == nil || !strings.Contains(err.Error(), "firmware does not respond") {
		t.Errorf("unreachable firmware: %v", err)
	}
}

func TestValidate(t *testing.T) {
	src := firmware(t)
	ok := config(t, "exit vpn = Wireguard2, Wireguard0\ndefault direct\n")
	if ps := Validate(context.Background(), ok, src); len(ps) != 0 {
		t.Errorf("valid exits produced problems: %v", ps)
	}
	bad := config(t, "exit vpn = Wireguard2\nexit a = Nope\nexit b = GigabitEthernet1\nexit c = Broken\ndefault direct\n")
	ps := Validate(context.Background(), bad, src)
	want := []struct {
		line int
		msg  string
	}{{2, "Nope does not exist on the router"}, {3, "only a WireGuard tunnel"}, {4, "Broken"}}
	if len(ps) != len(want) {
		t.Fatalf("%d problems: %v", len(ps), ps)
	}
	for i, w := range want {
		if ps[i].Line != w.line || ps[i].Severity != rules.Error || !strings.Contains(ps[i].Msg, w.msg) {
			t.Errorf("problem %d: %v; want line %d with text %q", i, ps[i], w.line, w.msg)
		}
	}
}

func TestActive(t *testing.T) {
	src := firmware(t)
	cfg := config(t, "exit first = Wireguard0, Wireguard3, Wireguard2\nexit dead = Wireguard0\nexit flaky = Broken, Wireguard2\ndefault direct\n")
	got, err := Active(context.Background(), cfg, src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["first"] != (Choice{"Wireguard2", "nwg2"}) {
		t.Errorf("first: %+v; the first live one in order must be chosen", got["first"])
	}
	if got["dead"] != (Choice{}) {
		t.Errorf("dead: %+v; none is live", got["dead"])
	}
	if got["flaky"] != (Choice{"Wireguard2", "nwg2"}) {
		t.Errorf("flaky: %+v; a failure of one interface must not prevent choosing the next", got["flaky"])
	}
	// The firmware never answered: that is an error, not "all tunnels are down".
	if _, err := Active(context.Background(), cfg, RCI{Base: "http://127.0.0.1:1"}, nil); err == nil {
		t.Error("unreachable firmware must be an error")
	}
}

func TestActiveKeepsPreviousWhenFirmwareSilent(t *testing.T) {
	src := firmware(t)
	// The firmware did not answer about the first interface in order; the others are down.
	cfg := config(t, "exit vpn = Broken, Wireguard0\nexit calm = Wireguard0\ndefault direct\n")
	prev := map[string]Choice{"vpn": {"Broken", "nwg9"}, "calm": {"Wireguard0", "nwg0"}}
	got, err := Active(context.Background(), cfg, src, prev)
	if err != nil {
		t.Fatal(err)
	}
	if got["vpn"] != prev["vpn"] {
		t.Errorf("vpn: %+v; firmware silence was taken for a tunnel failure, want the previous choice", got["vpn"])
	}
	if got["calm"] != (Choice{}) {
		t.Errorf("calm: %+v; the firmware said the tunnel is down, so the choice must be cleared", got["calm"])
	}
	// There is no previous choice, so there is nothing to fall back to.
	if got, _ := Active(context.Background(), cfg, src, nil); got["vpn"] != (Choice{}) {
		t.Errorf("vpn without a previous choice: %+v", got["vpn"])
	}
}

func TestTunnels(t *testing.T) {
	cfg := config(t, "exit vpn = Wireguard2, Wireguard0, Ghost, Broken\ndefault direct\n")
	got := Tunnels(context.Background(), cfg, firmware(t))
	want := []Tunnel{
		{Exit: "vpn", Name: "Wireguard2", ID: "Wireguard2", Description: "tunnel-a", Up: true},
		{Exit: "vpn", Name: "Wireguard0", ID: "Wireguard0"},
		{Exit: "vpn", Name: "Ghost", Error: "no such interface on the router"},
		{Exit: "vpn", Name: "Broken", Error: "firmware answered with code 500"},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

// In the rules an interface may be named by its description in the firmware settings.
func TestInterfaceByDescription(t *testing.T) {
	src := firmware(t)
	ctx := context.Background()
	want := Status{Name: "tunnel-a", ID: "Wireguard2", Exists: true, Type: "Wireguard", System: "nwg2", Up: true, Description: "tunnel-a"}
	if got, err := src.Interface(ctx, "tunnel-a"); err != nil || got != want {
		t.Errorf("tunnel-a: %+v, %v; want %+v", got, err, want)
	}
	if got, err := src.Interface(ctx, "tunnel-b"); err != nil || got.ID != "Wireguard0" || got.System != "nwg0" || got.Up {
		t.Errorf("tunnel-b: %+v, %v", got, err)
	}
	if got, err := src.Interface(ctx, "no-such-tunnel"); err != nil || got.Exists {
		t.Errorf("an unknown description: %+v, %v", got, err)
	}
	if _, err := src.Interface(ctx, "dup"); err == nil || !strings.Contains(err.Error(), "several interfaces") || !strings.Contains(err.Error(), "Wireguard3") {
		t.Errorf("a description of two interfaces must be an error: %v", err)
	}
	cfg := config(t, "exit vpn = tunnel-a, tunnel-b\ndefault direct\n")
	if ps := Validate(ctx, cfg, src); len(ps) != 0 {
		t.Errorf("validate: %v", ps)
	}
	active, err := Active(ctx, cfg, src, nil)
	if err != nil || active["vpn"] != (Choice{Interface: "tunnel-a", System: "nwg2"}) {
		t.Errorf("active: %+v, %v", active, err)
	}
}
