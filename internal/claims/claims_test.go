package claims

import (
	"net/netip"
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
		t.Fatalf("правила: %v", ps)
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
		t.Fatalf("изменения %v, ожидалось %v", s, want)
	}
	for i := range s {
		if s[i] != want[i] {
			t.Fatalf("изменения %v, ожидалось %v", s, want)
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
		t.Errorf("претензия не продлена: %+v", cs)
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d, ожидалось 2", s.Len())
	}
}

func TestDefaultMakesNoClaim(t *testing.T) {
	s := New(config(t, src), hour)
	wantChanges(t, s.Observe(t0, []string{"unknown.example"}, []netip.Addr{ip1}, hour))
	if s.Len() != 0 || s.Effective(ip1) != nil {
		t.Error("имя по default создало претензию")
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
		t.Errorf("Len = %d после истечения", s.Len())
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
	// Наблюдение по более позднему правилу победителя не меняет.
	wantChanges(t, s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip1}, hour))
	if len(s.Claims(ip1)) != 2 {
		t.Errorf("претензий %d, ожидалось 2", len(s.Claims(ip1)))
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
	early := netip.MustParseAddr("10.9.1.1") // подсеть правила, стоящего раньше video.example
	late := netip.MustParseAddr("10.8.1.1")  // подсеть правила, стоящего позже
	wantChanges(t, s.Observe(t0, []string{"video.example"}, []netip.Addr{early, late}, hour),
		"10.8.1.1 - => vpn strict")
	if s.Effective(early) != nil {
		t.Error("адрес из более ранней подсети попал в динамический список")
	}
	if len(s.Claims(early)) != 1 {
		t.Error("претензия на адрес из ранней подсети должна сохраняться для команды «почему»")
	}
}

func TestSetConfig(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"video.example"}, []netip.Addr{ip1}, hour)
	s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip2}, hour)

	changed := "exit vpn = W\nexit alt = W\ndefault direct\nvideo.example -> alt\n"
	wantChanges(t, s.SetConfig(config(t, changed)), "1.1.1.1 vpn strict => alt", "2.2.2.2 alt => -")
	if s.Len() != 1 {
		t.Errorf("Len = %d, ожидалось 1", s.Len())
	}
	// Новые наблюдения идут уже по новым правилам.
	wantChanges(t, s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip2}, hour))
}

func TestObserveUsesCNAMEChain(t *testing.T) {
	s := New(config(t, src), hour)
	got := s.Observe(t0, []string{"www.other.example", "edge.video.example"}, []netip.Addr{ip1}, hour)
	wantChanges(t, got, "1.1.1.1 - => vpn strict")
}
