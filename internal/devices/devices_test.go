package devices

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"trassa/internal/rules"
)

const hotspot = `{"host":[
 {"mac":"AA:BB:CC:00:00:01","ip":"192.168.1.40","name":"Living room TV","hostname":"tv","active":true,"dhcp":{"expires":3600},"ip6":[]},
 {"mac":"aa:bb:cc:00:00:02","ip":"192.168.1.61","name":"","hostname":"Pixel-7","active":false,"dhcp":{"expires":120}},
 {"mac":"aa:bb:cc:00:00:03","ip":"192.168.1.62","name":"Old phone","active":false},
 {"mac":"aa:bb:cc:00:00:04","ip":"0.0.0.0","name":"Printer","active":true},
 {"mac":"aa:bb:cc:00:00:05","ip":"192.168.1.70","name":"Twin","active":true},
 {"mac":"aa:bb:cc:00:00:06","ip":"192.168.1.71","name":"twin","active":true}
]}`

func serve(t *testing.T, code int, body string) RCI {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rci/show/ip/hotspot" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(code)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return RCI{Base: srv.URL}
}

func hosts(t *testing.T) []Host {
	t.Helper()
	hs, err := serve(t, 200, hotspot).Hosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return hs
}

func config(t *testing.T, src string) *rules.Config {
	t.Helper()
	cfg, ps := rules.Parse(src, nil)
	if rules.HasErrors(ps) {
		t.Fatalf("rules: %v", ps)
	}
	return cfg
}

func TestRCIHosts(t *testing.T) {
	hs := hosts(t)
	if len(hs) != 6 {
		t.Fatalf("hosts: %+v", hs)
	}
	want := []string{
		"aa:bb:cc:00:00:01 192.168.1.40 Living room TV online",
		"aa:bb:cc:00:00:02 192.168.1.61 Pixel-7 online",
		"aa:bb:cc:00:00:03 192.168.1.62 Old phone offline",
		"aa:bb:cc:00:00:04 invalid IP Printer online",
	}
	for i, w := range want {
		h := hs[i]
		state := "offline"
		if h.Online {
			state = "online"
		}
		if got := fmt.Sprintf("%s %s %s %s", h.MAC, h.IP, h.Label(), state); got != w {
			t.Errorf("host %d: %q, want %q", i, got, w)
		}
	}
}

func TestRCIHostsErrors(t *testing.T) {
	if _, err := serve(t, 500, "").Hosts(context.Background()); err == nil || !strings.Contains(err.Error(), "code 500") {
		t.Errorf("code 500: %v", err)
	}
	if _, err := serve(t, 200, "{").Hosts(context.Background()); err == nil || !strings.Contains(err.Error(), "cannot parse") {
		t.Errorf("broken answer: %v", err)
	}
	if _, err := (RCI{Base: "http://127.0.0.1:1"}).Hosts(context.Background()); err == nil || !strings.Contains(err.Error(), "does not respond") {
		t.Errorf("no firmware: %v", err)
	}
}

func TestValidate(t *testing.T) {
	cfg := config(t, `exit vpn = W
default direct
device tv = "living room tv"
device phones = aa:bb:cc:00:00:02, aa:bb:cc:00:00:99
device twins = "Twin"
device ghost = "Nobody"
device office = 192.168.1.50
`)
	got := fmt.Sprint(Validate(cfg, hosts(t)))
	for _, want := range []string{
		`line 4: warning: device aa:bb:cc:00:00:99 has never been seen by the router`,
		`line 5: error: device name "Twin" matches 2 devices`,
		`line 6: error: device "Nobody" is not in the router's device list`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in %s", want, got)
		}
	}
	if strings.Contains(got, "line 3") || strings.Contains(got, "line 7") {
		t.Errorf("a found name or an address must pass: %s", got)
	}
}

type countingSource struct{ calls int }

func (c *countingSource) Hosts(context.Context) ([]Host, error) { c.calls++; return nil, nil }

func TestCheck(t *testing.T) {
	src := &countingSource{}
	if ps := Check(context.Background(), config(t, "exit vpn = W\ndefault direct\n"), src); ps != nil || src.calls != 0 {
		t.Errorf("without device lists the firmware is not asked: %v, %d calls", ps, src.calls)
	}
	ps := Check(context.Background(), config(t, "default direct\ndevice tv = \"Living room TV\"\n"), RCI{Base: "http://127.0.0.1:1"})
	if !rules.HasErrors(ps) || !strings.Contains(fmt.Sprint(ps), "cannot read the router's device list") {
		t.Errorf("firmware unreachable: %v", ps)
	}
}

func TestResolve(t *testing.T) {
	cfg := config(t, `default direct
device tv = "Living room TV", 192.168.1.50
device phones = aa:bb:cc:00:00:02, "Old phone", "Printer"
device both = "Living room TV"
`)
	m := Resolve(cfg, hosts(t))
	ip := netip.MustParseAddr
	wantViews := map[netip.Addr]rules.View{ip("192.168.1.40"): 1 | 4, ip("192.168.1.50"): 1, ip("192.168.1.61"): 2}
	if fmt.Sprint(m.Views) != fmt.Sprint(wantViews) {
		t.Errorf("views %v, want %v", m.Views, wantViews)
	}
	if fmt.Sprint(m.ViewList()) != "[1 2 5]" {
		t.Errorf("ViewList = %v", m.ViewList())
	}
	if got := fmt.Sprint(m.Sources()); got != "map[1:[192.168.1.50] 2:[192.168.1.61] 5:[192.168.1.40]]" {
		t.Errorf("Sources = %s", got)
	}
	if m.Labels[ip("192.168.1.61")] != "Pixel-7" || m.Labels[ip("192.168.1.62")] != "Old phone" {
		t.Errorf("labels: %v", m.Labels)
	}
	var got []string
	for _, mem := range m.Lists[1].Members {
		got = append(got, fmt.Sprintf("%s=%s/%s", mem.Ref, mem.Label, mem.IP))
	}
	if want := `[aa:bb:cc:00:00:02=Pixel-7/192.168.1.61 "Old phone"=Old phone/invalid IP "Printer"=Printer/invalid IP]`; fmt.Sprint(got) != want {
		t.Errorf("list phones: %s, want %s", got, want)
	}
	// Without the firmware's list only addresses written in the rules count.
	if m := Resolve(cfg, nil); fmt.Sprint(m.ViewList()) != "[1]" {
		t.Errorf("no firmware list: views %v", m.ViewList())
	}
}
