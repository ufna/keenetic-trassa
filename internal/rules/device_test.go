package rules

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

const withDevices = `exit vpn = W
device tv     = "Living room TV"
device phones = "iPhone, Маши", aa-bb-cc-dd-ee-ff, Pixel
device office = 192.168.1.50, "TV #2" # a comment after the list
default direct
youtube.com -> vpn for tv, phones
instagram.com -> vpn strict for !office
twitch.tv -> vpn for phones, !office
91.108.4.0/22 -> vpn for tv
telegram.org -> vpn
`

const (
	tv     View = 1
	phones View = 2
	office View = 4
)

func devConfig(t *testing.T, src string) *Config {
	t.Helper()
	c, ps := Load(src, nil)
	if HasErrors(ps) {
		t.Fatalf("rules: %v", ps)
	}
	return c
}

func TestDeviceLists(t *testing.T) {
	c := devConfig(t, withDevices)
	want := [][]string{
		{`"Living room TV"`},
		{`"iPhone, Маши"`, "aa:bb:cc:dd:ee:ff", `"Pixel"`},
		{"192.168.1.50", `"TV #2"`},
	}
	if len(c.Devices) != len(want) {
		t.Fatalf("device lists: %+v", c.Devices)
	}
	for i, d := range c.Devices {
		var got []string
		for _, m := range d.Members {
			got = append(got, m.String())
		}
		if fmt.Sprint(got) != fmt.Sprint(want[i]) {
			t.Errorf("list %s: %q, want %q", d.Name, got, want[i])
		}
	}
	if a := c.Devices[2].Members[0].Addr; a != netip.MustParseAddr("192.168.1.50") {
		t.Errorf("address device: %v", a)
	}
	if k, ok := c.DeviceList("phones"); !ok || k != 1 {
		t.Errorf("DeviceList(phones) = %d, %v", k, ok)
	}
}

func TestRuleFor(t *testing.T) {
	c := devConfig(t, withDevices)
	cases := []struct {
		rule int
		view View
		want bool
	}{
		{0, 0, false}, {0, tv, true}, {0, phones, true}, {0, office, false}, {0, tv | office, true},
		{1, 0, true}, {1, tv, true}, {1, office, false}, {1, tv | office, false},
		{2, 0, false}, {2, phones, true}, {2, phones | office, false},
		{3, tv, true}, {3, 0, false},
		{4, 0, true}, {4, office, true}, {4, tv | phones | office, true},
	}
	for _, k := range cases {
		if got := c.Rules[k.rule].AppliesTo(k.view); got != k.want {
			t.Errorf("rule %q, view %d: applies %v, want %v", c.Rules[k.rule].Text, k.view, got, k.want)
		}
	}
	r := c.Rules[1]
	if r.Action != (Action{Exit: "vpn", Strict: true}) || fmt.Sprint(r.NotFor) != "[office]" || len(r.For) != 0 {
		t.Errorf("instagram rule: %+v", r)
	}
	if got := c.ViewName(tv | office); got != "tv, office" {
		t.Errorf("ViewName = %q", got)
	}
	if got := c.ViewName(0); got != "" {
		t.Errorf("ViewName(0) = %q", got)
	}
}

func TestDeviceErrors(t *testing.T) {
	const base = "exit vpn = W\ndefault direct\n"
	cases := []struct{ lines, want string }{
		{"device tv", "expected: device <name> = <device>"},
		{"device TV = 1.2.3.4", "only lowercase Latin letters"},
		{"device for = 1.2.3.4", "only lowercase Latin letters"},
		{"device tv = ", "empty device in the list"},
		{"device tv = 1.2.3.4,", "empty device in the list"},
		{`device tv = ""`, "empty device in the list"},
		{"device tv = 1.2.3.4 5.6.7.8", "a comma is missing"},
		{`device tv = "Living room TV`, "no closing quote"},
		{`device tv = "Living room TV" "Pixel"`, "a comma is missing after device"},
		{"device tv = Living room TV", "a name with spaces goes in double quotes"},
		{"device tv = 1.2.3", "looks like an address but is malformed"},
		{"device tv = 2001:db8::1", "IPv6 is not supported yet"},
		{"device tv = 1.2.3.4\ndevice tv = 5.6.7.8", `device list "tv" is already declared`},
		{"x.example -> vpn for", "for needs device list names"},
		{"x.example -> vpn for tv", `device list "tv" is not declared`},
		{"device tv = 1.2.3.4\nx.example -> vpn for tv,", "empty device list name"},
		{"device tv = 1.2.3.4\nx.example -> vpn for tv tv2", "a comma is missing"},
		{"device tv = 1.2.3.4\nx.example -> vpn for tv, !tv", "named twice"},
		{"device tv = 1.2.3.4\nx.example -> vpn for TV", "only lowercase Latin letters"},
		{"device tv = 1.2.3.4\nx.example -> for tv", "expected an exit"},
		{"device tv = 1.2.3.4\ndefault vpn for tv", "default applies to every device"},
		{"device tv = 1.2.3.4\ntest x.example = vpn for tv", "test checks a device in no list"},
	}
	for _, k := range cases {
		_, ps := Parse(base+k.lines+"\n", nil)
		if !HasErrors(ps) || !strings.Contains(fmt.Sprint(ps), k.want) {
			t.Errorf("%q: problems %v, want %q", k.lines, ps, k.want)
		}
	}
}

func TestDeviceLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString("exit vpn = W\ndefault direct\n")
	for i := 0; i <= MaxDeviceLists; i++ {
		fmt.Fprintf(&b, "device d%d = 10.0.0.%d\n", i, i+1)
	}
	if _, ps := Parse(b.String(), nil); !strings.Contains(fmt.Sprint(ps), "at most 16 are supported") {
		t.Errorf("17 device lists: %v", ps)
	}
	addrs := func(from, n int) string {
		var s []string
		for i := from; i < from+n; i++ {
			s = append(s, fmt.Sprintf("10.0.%d.%d", i/200, i%200+1))
		}
		return strings.Join(s, ", ")
	}
	src := "exit vpn = W\ndefault direct\ndevice a = " + addrs(0, 40) + "\ndevice b = " + addrs(40, 25) + "\n"
	if _, ps := Parse(src, nil); !strings.Contains(fmt.Sprint(ps), "more than 64 devices") {
		t.Errorf("65 devices: %v", ps)
	}
}
func TestMatchForViews(t *testing.T) {
	c := devConfig(t, withDevices)
	cases := []struct {
		v          View
		subj, want string
	}{
		{0, "www.youtube.com", "direct"}, {tv, "www.youtube.com", "vpn"}, {phones, "youtube.com", "vpn"},
		{office, "youtube.com", "direct"}, {tv | office, "youtube.com", "vpn"},
		{0, "instagram.com", "vpn strict"}, {office, "instagram.com", "direct"}, {tv | office, "instagram.com", "direct"},
		{phones, "twitch.tv", "vpn"}, {phones | office, "twitch.tv", "direct"}, {0, "twitch.tv", "direct"},
		{tv, "91.108.4.7", "vpn"}, {0, "91.108.4.7", "direct"},
		{office, "telegram.org", "vpn"},
	}
	for _, k := range cases {
		_, d, err := c.MatchSubjectFor(k.v, k.subj)
		if err != nil || d.Action.String() != k.want {
			t.Errorf("view %d, %s: %v (%v), want %s", k.v, k.subj, d.Action, err, k.want)
		}
	}
	if d := c.MatchChainFor(tv, []string{"r1.googlevideo.example", "youtube.com"}); d.Action.Exit != "vpn" || d.Rule.Line != 6 {
		t.Errorf("chain for tv: %+v", d)
	}
	if d := c.MatchChain([]string{"youtube.com"}); d.Rule != nil {
		t.Errorf("chain for a device in no list matched %q", d.Rule.Text)
	}
	if d := c.MatchChainAny([]string{"youtube.com"}); d.Rule == nil || d.Rule.Line != 6 {
		t.Errorf("chain for any device: %+v", d)
	}
}

func TestShadowingRespectsDevices(t *testing.T) {
	const head = "exit vpn = W\ndevice tv = 1.1.1.1\ndevice phones = 2.2.2.2\ndevice office = 3.3.3.3\ndefault direct\n"
	cases := []struct {
		rules string
		warn  bool
	}{
		{"x.example -> vpn for tv\nx.example -> direct\n", false},
		{"x.example -> vpn\nx.example -> direct for tv\n", true},
		{"x.example -> vpn for tv, phones\nx.example -> direct for tv\n", true},
		{"x.example -> vpn for !office\nx.example -> direct for tv\n", false},
		{"x.example -> vpn for !office\nx.example -> direct for tv, !office\n", true},
		{"1.2.3.0/24 -> vpn for tv\n1.2.3.4 -> direct\n", false},
		{"1.2.3.0/24 -> vpn\n1.2.3.4 -> direct for tv\n", true},
	}
	for _, k := range cases {
		_, ps := Load(head+k.rules, nil)
		if got := strings.Contains(fmt.Sprint(ps), "can never match"); got != k.warn {
			t.Errorf("%q: warning %v, want %v (%v)", k.rules, got, k.warn, ps)
		}
	}
}

func TestExplainShowsDeviceLists(t *testing.T) {
	c := devConfig(t, withDevices)
	text, err := c.Explain("youtube.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"youtube.com → direct", "for tv: vpn (line 6)", "for phones: vpn (line 6)"} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "for office") {
		t.Errorf("office has the same decision as everyone else:\n%s", text)
	}
	if got := c.DeviceLines("instagram.com", []View{tv, office, tv | office}); got != "for office: direct (default)\nfor tv, office: direct (default)\n" {
		t.Errorf("DeviceLines = %q", got)
	}
	if got := c.ListViews(); fmt.Sprint(got) != "[1 2 4]" {
		t.Errorf("ListViews = %v", got)
	}
}

func TestExpectationsUseDevicesInNoList(t *testing.T) {
	_, ps := Load(withDevices+"test youtube.com = direct\ntest instagram.com = vpn\n", nil)
	if HasErrors(ps) {
		t.Errorf("expectations are about devices in no list: %v", ps)
	}
}
