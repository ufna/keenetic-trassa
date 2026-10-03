package exits

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trassa/internal/rules"
)

const (
	wgUp     = `{"id":"Wireguard2","description":"tunnel-a","index":2,"type":"Wireguard","link":"up","connected":"yes","wireguard":{"peer":[{"online":false},{"online":true}]}}`
	wgDown   = `{"id":"Wireguard0","index":0,"type":"Wireguard","link":"down","connected":"no"}`
	wgNoPeer = `{"id":"Wireguard3","index":3,"type":"Wireguard","link":"up","connected":"yes","wireguard":{"peer":[{"online":false}]}}`
	ethernet = `{"id":"GigabitEthernet1","index":1,"type":"GigabitEthernet","link":"up","connected":"yes"}`
)

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
		t.Fatalf("правила: %v", ps)
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
		{"Wireguard2", Status{Name: "Wireguard2", Exists: true, Type: "Wireguard", System: "nwg2", Up: true, Description: "tunnel-a"}},
		{"Wireguard0", Status{Name: "Wireguard0", Exists: true, Type: "Wireguard", System: "nwg0"}},
		{"Wireguard3", Status{Name: "Wireguard3", Exists: true, Type: "Wireguard", System: "nwg3"}},
		{"GigabitEthernet1", Status{Name: "GigabitEthernet1", Exists: true, Type: "GigabitEthernet"}},
		{"Nope", Status{Name: "Nope"}},
		{"Empty", Status{Name: "Empty"}},
	}
	for _, c := range cases {
		got, err := src.Interface(ctx, c.name)
		if err != nil || got != c.want {
			t.Errorf("%s: %+v, %v; ожидалось %+v", c.name, got, err, c.want)
		}
	}
	for _, name := range []string{"Broken", "Garbage"} {
		if st, err := src.Interface(ctx, name); err == nil {
			t.Errorf("%s: ожидалась ошибка, получено %+v", name, st)
		}
	}
	dead := RCI{Base: "http://127.0.0.1:1"}
	if _, err := dead.Interface(ctx, "Wireguard2"); err == nil || !strings.Contains(err.Error(), "прошивка не отвечает") {
		t.Errorf("недоступная прошивка: %v", err)
	}
}

func TestValidate(t *testing.T) {
	src := firmware(t)
	ok := config(t, "exit vpn = Wireguard2, Wireguard0\ndefault direct\n")
	if ps := Validate(context.Background(), ok, src); len(ps) != 0 {
		t.Errorf("исправные выходы дали проблемы: %v", ps)
	}
	bad := config(t, "exit vpn = Wireguard2\nexit a = Nope\nexit b = GigabitEthernet1\nexit c = Broken\ndefault direct\n")
	ps := Validate(context.Background(), bad, src)
	want := []struct {
		line int
		msg  string
	}{{2, "Nope не существует на роутере"}, {3, "только туннель WireGuard"}, {4, "Broken"}}
	if len(ps) != len(want) {
		t.Fatalf("проблем %d: %v", len(ps), ps)
	}
	for i, w := range want {
		if ps[i].Line != w.line || ps[i].Severity != rules.Error || !strings.Contains(ps[i].Msg, w.msg) {
			t.Errorf("проблема %d: %v; ожидалась строка %d с текстом %q", i, ps[i], w.line, w.msg)
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
		t.Errorf("first: %+v — должен быть выбран первый живой по порядку", got["first"])
	}
	if got["dead"] != (Choice{}) {
		t.Errorf("dead: %+v — живых нет", got["dead"])
	}
	if got["flaky"] != (Choice{"Wireguard2", "nwg2"}) {
		t.Errorf("flaky: %+v — сбой одного интерфейса не должен мешать выбрать следующий", got["flaky"])
	}
	// Прошивка не ответила ни разу: это ошибка, а не «все туннели упали».
	if _, err := Active(context.Background(), cfg, RCI{Base: "http://127.0.0.1:1"}, nil); err == nil {
		t.Error("недоступная прошивка должна быть ошибкой")
	}
}

func TestActiveKeepsPreviousWhenFirmwareSilent(t *testing.T) {
	src := firmware(t)
	// О первом по порядку интерфейсе прошивка не ответила, остальные выключены.
	cfg := config(t, "exit vpn = Broken, Wireguard0\nexit calm = Wireguard0\ndefault direct\n")
	prev := map[string]Choice{"vpn": {"Broken", "nwg9"}, "calm": {"Wireguard0", "nwg0"}}
	got, err := Active(context.Background(), cfg, src, prev)
	if err != nil {
		t.Fatal(err)
	}
	if got["vpn"] != prev["vpn"] {
		t.Errorf("vpn: %+v — молчание прошивки принято за падение туннеля, ожидался прежний выбор", got["vpn"])
	}
	if got["calm"] != (Choice{}) {
		t.Errorf("calm: %+v — прошивка ответила, что туннель выключен: выбор должен сняться", got["calm"])
	}
	// Прежнего выбора нет — придумывать его не из чего.
	if got, _ := Active(context.Background(), cfg, src, nil); got["vpn"] != (Choice{}) {
		t.Errorf("vpn без прежнего выбора: %+v", got["vpn"])
	}
}

func TestTunnels(t *testing.T) {
	cfg := config(t, "exit vpn = Wireguard2, Wireguard0, Ghost, Broken\ndefault direct\n")
	got := Tunnels(context.Background(), cfg, firmware(t))
	want := []Tunnel{
		{Exit: "vpn", Name: "Wireguard2", Description: "tunnel-a", Up: true},
		{Exit: "vpn", Name: "Wireguard0"},
		{Exit: "vpn", Name: "Ghost", Error: "интерфейса нет на роутере"},
		{Exit: "vpn", Name: "Broken", Error: "прошивка ответила кодом 500"},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %+v, ожидалось %+v", i, got[i], want[i])
		}
	}
}
