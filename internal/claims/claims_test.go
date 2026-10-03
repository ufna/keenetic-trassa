package claims

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"trassa/internal/rules"
)

const src = `exit vpn = W
exit alt = W
default direct
10.9.0.0/16 -> alt
video.example -> vpn strict
ru -> direct
cdn.example -> alt
10.8.0.0/16 -> alt
`

var (
	t0   = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	ip1  = netip.MustParseAddr("1.1.1.1")
	ip2  = netip.MustParseAddr("2.2.2.2")
	hour = time.Hour
)

func config(t *testing.T, s string) *rules.Config {
	t.Helper()
	cfg, ps := rules.Load(s, nil)
	if rules.HasErrors(ps) {
		t.Fatalf("rules: %v", ps)
	}
	return cfg
}

func show(a *rules.Action) string {
	if a == nil {
		return "-"
	}
	return a.String()
}

func wantChanges(t *testing.T, got []Change, want ...string) {
	t.Helper()
	var s []string
	for _, c := range got {
		s = append(s, c.Addr.String()+" "+show(c.Old)+" => "+show(c.New))
	}
	if len(s) != len(want) {
		t.Fatalf("changes %v, want %v", s, want)
	}
	for i := range s {
		if s[i] != want[i] {
			t.Fatalf("changes %v, want %v", s, want)
		}
	}
}

func TestObserveAddsAndRefreshes(t *testing.T) {
	s := New(config(t, src), hour)
	got := s.Observe(t0, []string{"video.example"}, []netip.Addr{ip1, ip2}, 5*time.Minute)
	wantChanges(t, got, "1.1.1.1 - => vpn strict", "2.2.2.2 - => vpn strict")

	got = s.Observe(t0.Add(time.Minute), []string{"video.example"}, []netip.Addr{ip1}, 5*time.Minute)
	wantChanges(t, got)
	if cs := s.Claims(ip1); len(cs) != 1 || !cs[0].Expires.Equal(t0.Add(time.Minute+hour)) {
		t.Errorf("claim not extended: %+v", cs)
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2", s.Len())
	}
}

func TestDefaultMakesNoClaim(t *testing.T) {
	s := New(config(t, src), hour)
	wantChanges(t, s.Observe(t0, []string{"unknown.example"}, []netip.Addr{ip1}, hour))
	if s.Len() != 0 || s.Effective(ip1) != nil {
		t.Error("a name matched by default created a claim")
	}
	wantChanges(t, s.Observe(t0, nil, []netip.Addr{ip1}, hour))
}

func TestDirectRuleIsAClaim(t *testing.T) {
	s := New(config(t, src), hour)
	wantChanges(t, s.Observe(t0, []string{"yandex.ru"}, []netip.Addr{ip1}, hour), "1.1.1.1 - => direct")
}

func TestMinTTL(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"video.example"}, []netip.Addr{ip1}, 5*time.Second)
	wantChanges(t, s.Expire(t0.Add(30*time.Minute)))
	wantChanges(t, s.Expire(t0.Add(61*time.Minute)), "1.1.1.1 vpn strict => -")
	if s.Len() != 0 {
		t.Errorf("Len = %d after expiry", s.Len())
	}
}

func TestLongTTLIsKept(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"video.example"}, []netip.Addr{ip1}, 3*hour)
	wantChanges(t, s.Expire(t0.Add(2*hour)))
	wantChanges(t, s.Expire(t0.Add(3*hour)), "1.1.1.1 vpn strict => -")
}

func TestEarlierRuleWins(t *testing.T) {
	s := New(config(t, src), hour)
	wantChanges(t, s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip1}, hour), "1.1.1.1 - => alt")
	wantChanges(t, s.Observe(t0, []string{"video.example"}, []netip.Addr{ip1}, hour), "1.1.1.1 alt => vpn strict")
	// An observation for a later rule does not change the winner.
	wantChanges(t, s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip1}, hour))
	if len(s.Claims(ip1)) != 2 {
		t.Errorf("%d claims, want 2", len(s.Claims(ip1)))
	}
}

func TestExpireFallsBackToOtherClaim(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"video.example"}, []netip.Addr{ip1}, hour)
	s.Observe(t0.Add(30*time.Minute), []string{"cdn.example"}, []netip.Addr{ip1}, hour)
	wantChanges(t, s.Expire(t0.Add(61*time.Minute)), "1.1.1.1 vpn strict => alt")
	wantChanges(t, s.Expire(t0.Add(91*time.Minute)), "1.1.1.1 alt => -")
}

func TestStaticSubnetOrder(t *testing.T) {
	s := New(config(t, src), hour)
	early := netip.MustParseAddr("10.9.1.1") // subnet of a rule placed before video.example
	late := netip.MustParseAddr("10.8.1.1")  // subnet of a rule placed after it
	wantChanges(t, s.Observe(t0, []string{"video.example"}, []netip.Addr{early, late}, hour),
		"10.8.1.1 - => vpn strict")
	if s.Effective(early) != nil {
		t.Error("an address from an earlier subnet ended up in a dynamic set")
	}
	if len(s.Claims(early)) != 1 {
		t.Error("a claim on an address from an earlier subnet must be kept for the \"why\" command")
	}
}

func TestSetConfig(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"video.example"}, []netip.Addr{ip1}, hour)
	s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip2}, hour)

	changed := "exit vpn = W\nexit alt = W\ndefault direct\nvideo.example -> alt\n"
	wantChanges(t, s.SetConfig(config(t, changed), nil), "1.1.1.1 vpn strict => alt", "2.2.2.2 alt => -")
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1", s.Len())
	}
	// New observations already follow the new rules.
	wantChanges(t, s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip2}, hour))
}

func TestObserveUsesCNAMEChain(t *testing.T) {
	s := New(config(t, src), hour)
	got := s.Observe(t0, []string{"www.other.example", "edge.video.example"}, []netip.Addr{ip1}, hour)
	wantChanges(t, got, "1.1.1.1 - => vpn strict")
}

func TestObserveNeverShortensClaim(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"video.example"}, []netip.Addr{ip1}, 24*hour)
	s.Observe(t0.Add(time.Minute), []string{"video.example"}, []netip.Addr{ip1}, time.Minute)
	if cs := s.Claims(ip1); len(cs) != 1 || !cs[0].Expires.Equal(t0.Add(24*hour)) {
		t.Errorf("a new answer with a short TTL shortened the claim: %+v", cs)
	}
}

func TestStoreDoesNotAliasCallerSlices(t *testing.T) {
	s := New(config(t, src), hour)
	names := []string{"video.example"}
	s.Observe(t0, names, []netip.Addr{ip1}, hour)
	names[0] = "unknown.example"
	wantChanges(t, s.SetConfig(config(t, src), nil)) // same rules, so there must be no changes

	s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip1}, 3*hour)
	got := s.Claims(ip1)
	s.Expire(t0.Add(2 * hour))
	if len(got) != 2 || got[0].Names[0] != "video.example" {
		t.Errorf("a slice returned by Claims() changed after the fact: %+v", got)
	}
}

func TestAddrsOf(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"video.example"}, []netip.Addr{ip2, ip1}, hour)
	s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip1}, hour)
	s.Observe(t0, []string{"www.other.example", "edge.video.example"}, []netip.Addr{netip.MustParseAddr("3.3.3.3")}, hour)

	got := s.AddrsOf("video.example")
	if len(got) != 2 || got[0] != ip1 || got[1] != ip2 {
		t.Errorf("AddrsOf(video.example) = %v, want [1.1.1.1 2.2.2.2]", got)
	}
	if got := s.AddrsOf("www.other.example"); len(got) != 1 {
		t.Errorf("AddrsOf for the queried name of a chain = %v", got)
	}
	if got := s.AddrsOf("edge.video.example"); len(got) != 0 {
		t.Errorf("AddrsOf for a CNAME target must be empty: %v", got)
	}
	if got := s.AddrsOf("nobody.example"); len(got) != 0 {
		t.Errorf("AddrsOf(nobody.example) = %v", got)
	}
}

func TestLimits(t *testing.T) {
	s := New(config(t, src), hour)
	s.SetLimits(3, 2) // three claims in total, at most two per address
	ip3 := netip.MustParseAddr("3.3.3.3")

	// At most two per address: a third claim from the same rule is dropped.
	s.Observe(t0, []string{"a.cdn.example"}, []netip.Addr{ip1}, hour)
	s.Observe(t0, []string{"b.cdn.example"}, []netip.Addr{ip1}, hour)
	s.Observe(t0, []string{"c.cdn.example"}, []netip.Addr{ip1}, hour)
	if len(s.Claims(ip1)) != 2 || s.Dropped() != 1 || s.Total() != 2 {
		t.Fatalf("per-address cap: %d claims, %d dropped, %d total", len(s.Claims(ip1)), s.Dropped(), s.Total())
	}
	// A claim from an earlier rule evicts the worst one instead of being dropped.
	wantChanges(t, s.Observe(t0, []string{"video.example"}, []netip.Addr{ip1}, hour), "1.1.1.1 alt => vpn strict")
	if len(s.Claims(ip1)) != 2 || s.Total() != 2 {
		t.Fatalf("eviction: %d claims, %d total", len(s.Claims(ip1)), s.Total())
	}

	// Total cap: the third claim gets in, the fourth does not.
	s.Observe(t0, []string{"x.cdn.example"}, []netip.Addr{ip2}, hour)
	wantChanges(t, s.Observe(t0, []string{"y.cdn.example"}, []netip.Addr{ip3}, hour))
	if s.Total() != 3 || s.Len() != 2 || s.Dropped() != 2 {
		t.Fatalf("total cap: %d total, %d addresses, %d dropped", s.Total(), s.Len(), s.Dropped())
	}
	// Extending an existing claim works even when the store is full.
	s.Observe(t0.Add(30*time.Minute), []string{"x.cdn.example"}, []netip.Addr{ip2}, hour)
	if cs := s.Claims(ip2); len(cs) != 1 || !cs[0].Expires.Equal(t0.Add(90*time.Minute)) {
		t.Errorf("extension with a full store: %+v", cs)
	}
	// Expiry frees up room.
	s.Expire(t0.Add(61 * time.Minute))
	if s.Total() != 1 {
		t.Errorf("after expiry %d total, want 1", s.Total())
	}
	if got := s.Observe(t0.Add(62*time.Minute), []string{"y.cdn.example"}, []netip.Addr{ip3}, hour); len(got) != 1 {
		t.Errorf("claim not accepted after room was freed: %v", got)
	}
	// Changing the rules also recounts the total.
	s.SetConfig(config(t, "exit vpn = W\nexit alt = W\ndefault direct\n"), nil)
	if s.Total() != 0 || s.Len() != 0 {
		t.Errorf("after a rules change %d total, %d addresses", s.Total(), s.Len())
	}
}

func TestEntries(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"video.example"}, []netip.Addr{ip2, netip.MustParseAddr("10.9.1.1")}, hour)
	s.Observe(t0, []string{"yandex.ru"}, []netip.Addr{ip1}, hour)
	got := s.Entries()
	// 10.9.1.1 is in the subnet of an earlier rule, so it is not in the dynamic sets.
	want := []Entry{{Addr: ip1, Action: rules.Action{Exit: "direct"}}, {Addr: ip2, Action: rules.Action{Exit: "vpn", Strict: true}}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Entries = %+v, want %+v", got, want)
	}
}

func TestSaveLoad(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"www.other.example", "edge.video.example"}, []netip.Addr{ip1}, 3*hour)
	s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip1, ip2}, hour)
	var buf bytes.Buffer
	if err := s.Save(&buf); err != nil {
		t.Fatal(err)
	}

	// Restart an hour and a half later: the cdn.example claim (one-hour TTL) has expired, the video one has not.
	fresh := New(config(t, src), hour)
	if n := fresh.Load(bytes.NewReader(buf.Bytes()), t0.Add(90*time.Minute)); n != 1 {
		t.Errorf("%d claims accepted, want 1", n)
	}
	cs := fresh.Claims(ip1)
	if len(cs) != 1 || cs[0].Names[1] != "edge.video.example" || cs[0].Action.Exit != "vpn" || !cs[0].Expires.Equal(t0.Add(3*hour)) {
		t.Errorf("restored claim: %+v", cs)
	}
	if fresh.Total() != 1 || len(fresh.Entries()) != 1 {
		t.Errorf("%d total, %d in sets", fresh.Total(), len(fresh.Entries()))
	}

	// The rules have changed since: the claim is decided again by the new ones.
	changed := New(config(t, "exit vpn = W\nexit alt = W\ndefault direct\nother.example -> alt\n"), hour)
	changed.Load(bytes.NewReader(buf.Bytes()), t0)
	if cs := changed.Claims(ip1); len(cs) != 1 || cs[0].Action.Exit != "alt" || cs[0].Index != 0 {
		t.Errorf("after a rules change: %+v", cs)
	}
}

func TestLoadIgnoresGarbage(t *testing.T) {
	far := t0.Add(1000 * hour).Unix()
	lines := []string{
		"not JSON at all",
		`{"a":"not-an-address","n":["video.example"],"e":` + fmt.Sprint(far) + `}`,
		`{"a":"2001:db8::1","n":["video.example"],"e":` + fmt.Sprint(far) + `}`,
		`{"a":"1.1.1.1","n":[],"e":` + fmt.Sprint(far) + `}`,
		`{"a":"1.1.1.1","n":["video.example"],"e":1}`,
		`{"a":"2.2.2.2","n":["video.example"],"e":` + fmt.Sprint(far) + `}`,
		"",
	}
	s := New(config(t, src), hour)
	if n := s.Load(strings.NewReader(strings.Join(lines, "\n")), t0); n != 1 {
		t.Errorf("%d accepted, want 1", n)
	}
	// An expiry read from the file is capped at one day from now.
	if cs := s.Claims(ip2); len(cs) != 1 || !cs[0].Expires.Equal(t0.Add(24*hour)) {
		t.Errorf("expiry not capped: %+v", cs)
	}
}

func TestUnusableAddressesAreIgnored(t *testing.T) {
	// Blocking DNS servers answer with 0.0.0.0; the kernel address set rejects such an address,
	// and a single such entry would break the whole set rebuild.
	bad := []string{"0.0.0.0", "0.1.2.3", "127.0.0.1", "169.254.1.1", "224.0.0.1", "240.0.0.1", "255.255.255.255"}
	var addrs []netip.Addr
	for _, a := range bad {
		addrs = append(addrs, netip.MustParseAddr(a))
	}
	addrs = append(addrs, ip1)
	s := New(config(t, src), hour)
	wantChanges(t, s.Observe(t0, []string{"video.example"}, addrs, hour), "1.1.1.1 - => vpn strict")
	if s.Len() != 1 || s.Total() != 1 {
		t.Errorf("%d addresses, %d claims: special addresses were stored", s.Len(), s.Total())
	}
	far := fmt.Sprint(t0.Add(10 * hour).Unix())
	var file strings.Builder
	for _, a := range append(bad, "2.2.2.2") {
		file.WriteString(`{"a":"` + a + `","n":["video.example"],"e":` + far + "}\n")
	}
	fresh := New(config(t, src), hour)
	if n := fresh.Load(strings.NewReader(file.String()), t0); n != 1 || fresh.Len() != 1 {
		t.Errorf("%d claims accepted from the file, %d addresses; want one, 2.2.2.2", n, fresh.Len())
	}
}

// Names read from the state file are checked like names from DNS: the file sits on flash and
// outlives the daemon, so it is input like any other.
func TestLoadNormalizesNames(t *testing.T) {
	far := t0.Add(10 * hour).Unix()
	lines := []string{
		`{"a":"1.1.1.1","n":["WWW.Video.Example."],"e":` + fmt.Sprint(far) + `}`,
		`{"a":"2.2.2.2","n":["bad\u001bname.example"],"e":` + fmt.Sprint(far) + `}`,
	}
	s := New(config(t, src), hour)
	if n := s.Load(strings.NewReader(strings.Join(lines, "\n")), t0); n != 1 {
		t.Errorf("%d accepted, want 1", n)
	}
	if cs := s.Claims(ip1); len(cs) != 1 || cs[0].Names[0] != "www.video.example" || cs[0].Action.Exit != "vpn" {
		t.Errorf("normalized claim: %+v", cs)
	}
	if cs := s.Claims(ip2); len(cs) != 0 {
		t.Errorf("a name with a control character was loaded: %+v", cs)
	}
}

const devSrc = `exit vpn = W
device tv = 192.168.1.40
device office = 192.168.1.50
default direct
youtube.example -> vpn for tv
instagram.example -> vpn for !office
10.9.0.0/16 -> direct for tv
lan.example -> vpn
`

const (
	tv     rules.View = 1
	office rules.View = 2
)

func wantViewChanges(t *testing.T, got []Change, want ...string) {
	t.Helper()
	var s []string
	for _, c := range got {
		s = append(s, fmt.Sprintf("[%d] %s %s => %s", c.View, c.Addr, show(c.Old), show(c.New)))
	}
	if fmt.Sprint(s) != fmt.Sprint(want) {
		t.Fatalf("changes %q, want %q", s, want)
	}
}

func TestClaimsPerView(t *testing.T) {
	s := New(config(t, devSrc), hour)
	wantViewChanges(t, s.SetViews([]rules.View{office, tv}))
	if fmt.Sprint(s.Views()) != "[1 2]" {
		t.Fatalf("views %v", s.Views())
	}
	wantViewChanges(t, s.Observe(t0, []string{"youtube.example"}, []netip.Addr{ip1}, hour), "[1] 1.1.1.1 - => vpn")
	if s.Effective(ip1) != nil || s.EffectiveFor(office, ip1) != nil || show(s.EffectiveFor(tv, ip1)) != "vpn" {
		t.Error("youtube.example must be in the TV's set only")
	}
	if len(s.Claims(ip1)) != 0 || len(s.ClaimsFor(tv, ip1)) != 1 || s.ClaimsFor(tv, ip1)[0].Action.Exit != "vpn" || !s.Known(ip1) {
		t.Errorf("claims for views: %+v / %+v", s.Claims(ip1), s.ClaimsFor(tv, ip1))
	}
	wantViewChanges(t, s.Observe(t0, []string{"instagram.example"}, []netip.Addr{ip2}, hour),
		"[0] 2.2.2.2 - => vpn", "[1] 2.2.2.2 - => vpn")
	// A subnet rule for the TV is older than the name rule: the TV's static set serves the address.
	lan := netip.MustParseAddr("10.9.1.1")
	wantViewChanges(t, s.Observe(t0, []string{"lan.example"}, []netip.Addr{lan}, hour),
		"[0] 10.9.1.1 - => vpn", "[2] 10.9.1.1 - => vpn")
	got := fmt.Sprint(s.Entries())
	for _, want := range []string{"{0 2.2.2.2 vpn}", "{1 1.1.1.1 vpn}", "{2 10.9.1.1 vpn}"} {
		if !strings.Contains(got, want) {
			t.Errorf("entries %s: no %s", got, want)
		}
	}
	wantViewChanges(t, s.Expire(t0.Add(2*hour)),
		"[0] 2.2.2.2 vpn => -", "[0] 10.9.1.1 vpn => -", "[1] 1.1.1.1 vpn => -", "[1] 2.2.2.2 vpn => -", "[2] 10.9.1.1 vpn => -")
}

func TestSetViewsDecidesNewViews(t *testing.T) {
	s := New(config(t, devSrc), hour)
	// No TV is known yet, but the answer is kept: a TV may join later.
	wantViewChanges(t, s.Observe(t0, []string{"youtube.example"}, []netip.Addr{ip1}, hour))
	if s.Len() != 1 || !s.Known(ip1) {
		t.Fatal("an answer for a device list's rule must be kept")
	}
	wantViewChanges(t, s.SetViews([]rules.View{tv}), "[1] 1.1.1.1 - => vpn")
	wantViewChanges(t, s.SetViews(nil))
	if s.EffectiveFor(tv, ip1) != nil {
		t.Error("a view no longer tracked has no set")
	}
}

func TestSetConfigWithViews(t *testing.T) {
	s := New(config(t, devSrc), hour)
	s.SetViews([]rules.View{tv})
	s.Observe(t0, []string{"youtube.example"}, []netip.Addr{ip1}, hour)
	// The lists swap places: list tv is now bit 2.
	swapped := strings.Replace(devSrc, "device tv = 192.168.1.40\ndevice office = 192.168.1.50", "device office = 192.168.1.50\ndevice tv = 192.168.1.40", 1)
	wantViewChanges(t, s.SetConfig(config(t, swapped), []rules.View{2}), "[2] 1.1.1.1 - => vpn")
}

func TestLoadDecidesForViews(t *testing.T) {
	s := New(config(t, devSrc), hour)
	s.Observe(t0, []string{"youtube.example"}, []netip.Addr{ip1}, hour)
	var buf bytes.Buffer
	if err := s.Save(&buf); err != nil {
		t.Fatal(err)
	}
	r := New(config(t, devSrc), hour)
	r.SetViews([]rules.View{tv})
	if n := r.Load(&buf, t0); n != 1 || show(r.EffectiveFor(tv, ip1)) != "vpn" {
		t.Errorf("loaded %d, tv: %s", n, show(r.EffectiveFor(tv, ip1)))
	}
}

// Review of task 4: the expiry tick runs under the engine's lock every 30 seconds. An address none
// of whose claims expired cannot change, so it must cost nothing, whatever the number of views.
func TestExpireSkipsAddressesWithNothingExpired(t *testing.T) {
	s := New(config(t, devSrc), hour)
	s.SetViews([]rules.View{tv, office, tv | office})
	for i := 0; i < 500; i++ {
		a := netip.AddrFrom4([4]byte{5, 5, byte(i / 250), byte(i%250 + 1)})
		s.Observe(t0, []string{"instagram.example"}, []netip.Addr{a}, hour)
	}
	if allocs := testing.AllocsPerRun(5, func() { s.Expire(t0) }); allocs > 5 {
		t.Errorf("an expiry tick with nothing expired made %.0f allocations", allocs)
	}
}

// Final review: a listed device joining or leaving changes the tracked views, under the engine's
// lock. Only the added view is decided, and an answer whose rule applies to every device needs no
// rule scan at all; the views already tracked are not decided again.
func TestSetViewsDecidesOnlyAddedViews(t *testing.T) {
	s := New(config(t, devSrc), hour)
	s.SetViews([]rules.View{tv})
	const n = 2000
	for i := 0; i < n; i++ {
		a := netip.AddrFrom4([4]byte{5, 5, byte(i / 250), byte(i%250 + 1)})
		s.Observe(t0, []string{"instagram.example"}, []netip.Addr{a}, hour)
	}
	before := fmt.Sprint(s.Entries())
	allocs := testing.AllocsPerRun(1, func() {
		s.SetViews([]rules.View{tv, office})
		s.SetViews([]rules.View{tv})
	})
	// One new decision slice per answer and view change, and one action per answer in the added
	// view's set: about 3 per answer for the round trip. Deciding every view again costs far more.
	if allocs > 3.5*n {
		t.Errorf("adding and removing a view made %.0f allocations for %d answers", allocs, n)
	}
	if after := fmt.Sprint(s.Entries()); after != before {
		t.Error("adding and removing a view changed the sets")
	}
}

// Review of task 4: with a cap per address, a new claim may evict only a claim of a newer rule.
// The rank of a claim is the earliest rule it gets for any view, not the rule the first matching
// name hits: here devices in no list take b.example's rule 0.
func TestEvictionRankIsTheEarliestRuleForAnyView(t *testing.T) {
	s := New(config(t, "exit vpn = W\nexit alt = W\ndevice tv = 192.168.1.40\ndefault direct\nb.example -> alt\nc.example -> vpn\na.example -> vpn for tv\n"), hour)
	s.SetLimits(0, 1)
	s.Observe(t0, []string{"a.example", "b.example"}, []netip.Addr{ip1}, hour)
	s.Observe(t0, []string{"c.example"}, []netip.Addr{ip1}, hour)
	if got := show(s.Effective(ip1)); got != "alt" {
		t.Errorf("devices in no list: %s, want alt (rule 0 must not be evicted by rule 1)", got)
	}
}

func TestViewsDivergeAlongTheCNAMEChain(t *testing.T) {
	s := New(config(t, "exit vpn = W\nexit alt = W\ndevice tv = 192.168.1.40\ndefault direct\nalias.example -> vpn for tv\ncdn.example -> alt\n"), hour)
	s.SetViews([]rules.View{tv})
	s.Observe(t0, []string{"alias.example", "cdn.example"}, []netip.Addr{ip1}, hour)
	if a, b := show(s.Effective(ip1)), show(s.EffectiveFor(tv, ip1)); a != "alt" || b != "vpn" {
		t.Errorf("no list: %s, tv: %s; want alt and vpn", a, b)
	}
	want := "[{0 1.1.1.1 alt} {1 1.1.1.1 vpn}]"
	if got := fmt.Sprint(s.Entries()); got != want {
		t.Errorf("entries %s, want %s", got, want)
	}
}

// Final review: blocking by name never closes private networks (a NAS, an office behind a tunnel),
// as default none does not; another rule for the same address still applies. A subnet written in
// the rules is another matter: that is the user's explicit choice.
func TestNoneSkipsPrivateAddresses(t *testing.T) {
	s := New(config(t, "exit vpn = W\ndefault direct\n*.io -> none\nnas.example -> vpn\n"), hour)
	nas, cgnat, public := netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("100.64.1.1"), netip.MustParseAddr("5.5.5.5")
	s.Observe(t0, []string{"nas.io"}, []netip.Addr{nas, cgnat, public}, hour)
	if s.Effective(nas) != nil || s.Effective(cgnat) != nil || show(s.Effective(public)) != "none" {
		t.Errorf("nas %s, cgnat %s, public %s", show(s.Effective(nas)), show(s.Effective(cgnat)), show(s.Effective(public)))
	}
	s.Observe(t0, []string{"nas.example"}, []netip.Addr{nas}, hour)
	if got := show(s.Effective(nas)); got != "vpn" {
		t.Errorf("another rule for a private address: %s", got)
	}
}
