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

// Review of task 3: an answer without a device list is a failure, not an empty network: otherwise
// every device named in the rules would drop out of its list until the next good answer.
func TestRCIHostsWithoutList(t *testing.T) {
	for _, body := range []string{`{}`, `{"host":null}`, `{"status":[{"status":"error","message":"no such command"}]}`} {
		if _, err := serve(t, 200, body).Hosts(context.Background()); err == nil || !strings.Contains(err.Error(), "no device list") {
			t.Errorf("%s: %v, want an error", body, err)
		}
	}
	if hs, err := serve(t, 200, `{"host":[]}`).Hosts(context.Background()); err != nil || len(hs) != 0 {
		t.Errorf("an empty list is a valid answer: %v, %v", hs, err)
	}
}

func TestLabelsPreferOnlineHosts(t *testing.T) {
	cfg := config(t, "default direct\ndevice office = 192.168.1.5\n")
	hosts := []Host{
		{MAC: "aa:bb:cc:00:00:10", IP: netip.MustParseAddr("192.168.1.5"), Name: "Current", Online: true},
		{MAC: "aa:bb:cc:00:00:11", IP: netip.MustParseAddr("192.168.1.5"), Name: "Stale"},
	}
	for _, hs := range [][]Host{hosts, {hosts[1], hosts[0]}} {
		m := Resolve(cfg, hs)
		if got := m.Labels[netip.MustParseAddr("192.168.1.5")]; got != "Current" {
			t.Errorf("label %q", got)
		}
	}
}

func TestValidateMessages(t *testing.T) {
	cfg := config(t, "default direct\ndevice a = \"Pixel-7\"\ndevice b = \"Twin\"\n")
	got := fmt.Sprint(Validate(cfg, hosts(t)))
	for _, want := range []string{
		`device "Pixel-7" has no name in the router settings: it calls itself Pixel-7`,
		`aa:bb:cc:00:00:05, aa:bb:cc:00:00:06`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in %s", want, got)
		}
	}
}

func TestRCIHostsLimits(t *testing.T) {
	big := `{"host":[` + strings.Repeat(`{"mac":"aa:bb:cc:00:00:01","ip":"192.168.1.40","name":"`+strings.Repeat("x", 1000)+`"},`, 4500) + `{}]}`
	if _, err := serve(t, 200, big).Hosts(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an oversized answer: %v", err)
	}
	hs, err := serve(t, 200, `{"host":[{"mac":"AA-BB-CC-00-00-01","ip":"192.168.1.40","active":true}]}`).Hosts(context.Background())
	if err != nil || hs[0].MAC != "aa:bb:cc:00:00:01" {
		t.Errorf("MAC with dashes: %+v, %v", hs, err)
	}
}

func TestMemberStates(t *testing.T) {
	cfg := config(t, `default direct
device tv = "Living room TV", "Old phone", "Twin", "Nobody", aa:bb:cc:00:00:99, 192.168.1.50
`)
	var got []string
	for _, m := range Resolve(cfg, hosts(t)).Lists[0].Members {
		got = append(got, m.State)
	}
	want := "[on the network not on the network matches 2 devices in the router's device list not in the router's device list not in the router's device list on the network]"
	if fmt.Sprint(got) != want {
		t.Errorf("states %v\nwant   %s", got, want)
	}
}

func TestCheckAsksOnlyWhenNeeded(t *testing.T) {
	down := RCI{Base: "http://127.0.0.1:1"}
	if ps := Check(context.Background(), config(t, "default direct\ndevice office = 192.168.1.50\n"), down); ps != nil {
		t.Errorf("addresses need no firmware: %v", ps)
	}
	ps := Check(context.Background(), config(t, "default direct\ndevice tv = aa:bb:cc:00:00:01\n"), down)
	if len(ps) != 1 || ps[0].Severity != rules.Warning {
		t.Errorf("MACs only: an unreachable firmware is a warning: %v", ps)
	}
}

func TestRCIHostsWithoutAnIPv4Address(t *testing.T) {
	hs, err := serve(t, 200, `{"host":[{"mac":"aa:bb:cc:00:00:01","name":"a","active":true},{"mac":"aa:bb:cc:00:00:02","ip":"fd00::1","name":"b","active":true},{"mac":"aa:bb:cc:00:00:03","ip":"::ffff:192.168.1.5","name":"c","active":true}]}`).Hosts(context.Background())
	if err != nil || len(hs) != 3 {
		t.Fatalf("%+v, %v", hs, err)
	}
	for _, h := range hs {
		if h.IP.IsValid() {
			t.Errorf("%s: address %s, want none", h.Name, h.IP)
		}
	}
}

// A device that asks DNS over IPv6 is the same device: its IPv6 addresses come from the firmware's
// list and from the router's neighbour table, and an address built from the MAC needs neither.
func TestIPv6AddressesOfDevices(t *testing.T) {
	out := "fe80::c803:47ff:fe04:97ae dev br0 lladdr ca:03:47:04:97:ae router ref 1 used 0/0/0 probes 1 REACHABLE\n" +
		"fdbd:8531::5 dev br0  used 0/0/0 probes 3 FAILED\n" +
		"fe80::1234:5678:9abc:def0 dev br0 lladdr AA-BB-CC-00-00-02 STALE\n"
	n := ParseNeighbors(out)
	if fmt.Sprint(n) != "[{fe80::c803:47ff:fe04:97ae ca:03:47:04:97:ae} {fe80::1234:5678:9abc:def0 aa:bb:cc:00:00:02}]" {
		t.Fatalf("neighbours %v", n)
	}
	ip := netip.MustParseAddr
	hosts := []Host{
		{MAC: "ca:03:47:04:97:ae", IP: ip("192.168.1.40"), Name: "TV", Online: true},
		{MAC: "aa:bb:cc:00:00:02", IP: ip("192.168.1.61"), Hostname: "Pixel-7", Online: true},
		{MAC: "aa:bb:cc:00:00:03", IP: ip("192.168.1.70"), Name: "Laptop", Online: true, IP6: []netip.Addr{ip("fdbd:8531::70")}},
		{MAC: "02:11:22:33:44:55", IP: ip("192.168.1.80"), Name: "Console", Online: true},
	}
	m := Resolve(config(t, "default direct\n"), WithNeighbors(hosts, n))
	cases := map[string]string{
		"fe80::c803:47ff:fe04:97ae": "192.168.1.40", "fe80::1234:5678:9abc:def0": "192.168.1.61", "fdbd:8531::70": "192.168.1.70",
		"fe80::11:22ff:fe33:4455": "192.168.1.80", // built from the MAC, in no table
		"192.168.1.40":            "192.168.1.40", "fe80::9": "fe80::9",
	}
	for a, want := range cases {
		if got := m.Device(ip(a)).String(); got != want {
			t.Errorf("%s: device at %s, want %s", a, got, want)
		}
	}
	hs, err := serve(t, 200, `{"host":[{"mac":"aa:bb:cc:00:00:01","ip":"192.168.1.40","ip6":["fdbd:8531::5","nonsense","10.0.0.1"],"active":true}]}`).Hosts(context.Background())
	if err != nil || fmt.Sprint(hs[0].IP6) != "[fdbd:8531::5]" {
		t.Errorf("ip6 from the firmware: %+v, %v", hs, err)
	}
}

// Review of the IPv6 mapping: an "ip6" field of another shape must not break the device list;
// zones are dropped; an address shared by two devices goes to the one on the network.
func TestIPv6Robustness(t *testing.T) {
	for _, body := range []string{
		`{"host":[{"mac":"aa:bb:cc:00:00:01","ip":"192.168.1.40","name":"TV","active":true,"ip6":[{"addr":"fd00::1"}]}]}`,
		`{"host":[{"mac":"aa:bb:cc:00:00:01","ip":"192.168.1.40","name":"TV","active":true,"ip6":"fd00::1"}]}`,
	} {
		if hs, err := serve(t, 200, body).Hosts(context.Background()); err != nil || len(hs) != 1 || hs[0].Name != "TV" {
			t.Errorf("%s: %+v, %v", body, hs, err)
		}
	}
	ip := netip.MustParseAddr
	hs, _ := serve(t, 200, `{"host":[{"mac":"aa:bb:cc:00:00:01","ip":"192.168.1.40","active":true,"ip6":["fe80::1%br0"]}]}`).Hosts(context.Background())
	if m := Resolve(config(t, "default direct\n"), hs); m.Device(ip("fe80::1")).String() != "192.168.1.40" {
		t.Errorf("an address with a zone: %v", hs[0].IP6)
	}
	hosts := []Host{
		{MAC: "aa:bb:cc:00:00:01", IP: ip("192.168.1.5"), Name: "Current", Online: true, IP6: []netip.Addr{ip("fd00::5")}},
		{MAC: "aa:bb:cc:00:00:02", IP: ip("192.168.1.9"), Name: "Gone", IP6: []netip.Addr{ip("fd00::5")}},
	}
	if m := Resolve(config(t, "default direct\n"), hosts); m.Device(ip("fd00::5")).String() != "192.168.1.5" {
		t.Errorf("an address of two devices: %s", m.Device(ip("fd00::5")))
	}
}
