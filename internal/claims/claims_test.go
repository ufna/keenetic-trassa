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

func TestObserveNeverShortensClaim(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"video.example"}, []netip.Addr{ip1}, 24*hour)
	s.Observe(t0.Add(time.Minute), []string{"video.example"}, []netip.Addr{ip1}, time.Minute)
	if cs := s.Claims(ip1); len(cs) != 1 || !cs[0].Expires.Equal(t0.Add(24*hour)) {
		t.Errorf("новый ответ с коротким сроком укоротил претензию: %+v", cs)
	}
}

func TestStoreDoesNotAliasCallerSlices(t *testing.T) {
	s := New(config(t, src), hour)
	names := []string{"video.example"}
	s.Observe(t0, names, []netip.Addr{ip1}, hour)
	names[0] = "unknown.example"
	wantChanges(t, s.SetConfig(config(t, src))) // правила те же — изменений быть не должно

	s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip1}, 3*hour)
	got := s.Claims(ip1)
	s.Expire(t0.Add(2 * hour))
	if len(got) != 2 || got[0].Names[0] != "video.example" {
		t.Errorf("срез, полученный из Claims(), изменился задним числом: %+v", got)
	}
}

func TestAddrsOf(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"video.example"}, []netip.Addr{ip2, ip1}, hour)
	s.Observe(t0, []string{"cdn.example"}, []netip.Addr{ip1}, hour)
	s.Observe(t0, []string{"www.other.example", "edge.video.example"}, []netip.Addr{netip.MustParseAddr("3.3.3.3")}, hour)

	got := s.AddrsOf("video.example")
	if len(got) != 2 || got[0] != ip1 || got[1] != ip2 {
		t.Errorf("AddrsOf(video.example) = %v, ожидалось [1.1.1.1 2.2.2.2]", got)
	}
	if got := s.AddrsOf("www.other.example"); len(got) != 1 {
		t.Errorf("AddrsOf по запрошенному имени цепочки = %v", got)
	}
	if got := s.AddrsOf("edge.video.example"); len(got) != 0 {
		t.Errorf("AddrsOf по CNAME-цели должен быть пуст: %v", got)
	}
	if got := s.AddrsOf("nobody.example"); len(got) != 0 {
		t.Errorf("AddrsOf(nobody.example) = %v", got)
	}
}

func TestLimits(t *testing.T) {
	s := New(config(t, src), hour)
	s.SetLimits(3, 2) // всего три претензии, на один адрес — не больше двух
	ip3 := netip.MustParseAddr("3.3.3.3")

	// На адрес — не больше двух: третья претензия по тому же правилу отбрасывается.
	s.Observe(t0, []string{"a.cdn.example"}, []netip.Addr{ip1}, hour)
	s.Observe(t0, []string{"b.cdn.example"}, []netip.Addr{ip1}, hour)
	s.Observe(t0, []string{"c.cdn.example"}, []netip.Addr{ip1}, hour)
	if len(s.Claims(ip1)) != 2 || s.Dropped() != 1 || s.Total() != 2 {
		t.Fatalf("предел на адрес: претензий %d, отброшено %d, всего %d", len(s.Claims(ip1)), s.Dropped(), s.Total())
	}
	// Претензия по более раннему правилу вытесняет худшую, а не отбрасывается.
	wantChanges(t, s.Observe(t0, []string{"video.example"}, []netip.Addr{ip1}, hour), "1.1.1.1 alt => vpn strict")
	if len(s.Claims(ip1)) != 2 || s.Total() != 2 {
		t.Fatalf("вытеснение: претензий %d, всего %d", len(s.Claims(ip1)), s.Total())
	}

	// Общий предел: третья претензия проходит, четвёртая — нет.
	s.Observe(t0, []string{"x.cdn.example"}, []netip.Addr{ip2}, hour)
	wantChanges(t, s.Observe(t0, []string{"y.cdn.example"}, []netip.Addr{ip3}, hour))
	if s.Total() != 3 || s.Len() != 2 || s.Dropped() != 2 {
		t.Fatalf("общий предел: всего %d, адресов %d, отброшено %d", s.Total(), s.Len(), s.Dropped())
	}
	// Продление уже существующей претензии проходит и при заполненном хранилище.
	s.Observe(t0.Add(30*time.Minute), []string{"x.cdn.example"}, []netip.Addr{ip2}, hour)
	if cs := s.Claims(ip2); len(cs) != 1 || !cs[0].Expires.Equal(t0.Add(90*time.Minute)) {
		t.Errorf("продление при заполненном хранилище: %+v", cs)
	}
	// Истечение освобождает место.
	s.Expire(t0.Add(61 * time.Minute))
	if s.Total() != 1 {
		t.Errorf("после истечения всего %d, ожидалась 1", s.Total())
	}
	if got := s.Observe(t0.Add(62*time.Minute), []string{"y.cdn.example"}, []netip.Addr{ip3}, hour); len(got) != 1 {
		t.Errorf("после освобождения места претензия не принята: %v", got)
	}
	// Смена правил тоже пересчитывает общее число.
	s.SetConfig(config(t, "exit vpn = W\nexit alt = W\ndefault direct\n"))
	if s.Total() != 0 || s.Len() != 0 {
		t.Errorf("после смены правил всего %d, адресов %d", s.Total(), s.Len())
	}
}

func TestEntries(t *testing.T) {
	s := New(config(t, src), hour)
	s.Observe(t0, []string{"video.example"}, []netip.Addr{ip2, netip.MustParseAddr("10.9.1.1")}, hour)
	s.Observe(t0, []string{"yandex.ru"}, []netip.Addr{ip1}, hour)
	got := s.Entries()
	// 10.9.1.1 входит в подсеть более раннего правила — в динамических списках его нет.
	want := []Entry{{ip1, rules.Action{Exit: "direct"}}, {ip2, rules.Action{Exit: "vpn", Strict: true}}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Entries = %+v, ожидалось %+v", got, want)
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

	// Перезапуск через полтора часа: претензия cdn.example (срок час) истекла, видео — нет.
	fresh := New(config(t, src), hour)
	if n := fresh.Load(bytes.NewReader(buf.Bytes()), t0.Add(90*time.Minute)); n != 1 {
		t.Errorf("принято претензий %d, ожидалась 1", n)
	}
	cs := fresh.Claims(ip1)
	if len(cs) != 1 || cs[0].Names[1] != "edge.video.example" || cs[0].Action.Exit != "vpn" || !cs[0].Expires.Equal(t0.Add(3*hour)) {
		t.Errorf("восстановленная претензия: %+v", cs)
	}
	if fresh.Total() != 1 || len(fresh.Entries()) != 1 {
		t.Errorf("всего %d, в списках %d", fresh.Total(), len(fresh.Entries()))
	}

	// Правила с тех пор изменились: претензия решается заново по новым.
	changed := New(config(t, "exit vpn = W\nexit alt = W\ndefault direct\nother.example -> alt\n"), hour)
	changed.Load(bytes.NewReader(buf.Bytes()), t0)
	if cs := changed.Claims(ip1); len(cs) != 1 || cs[0].Action.Exit != "alt" || cs[0].Index != 0 {
		t.Errorf("после смены правил: %+v", cs)
	}
}

func TestLoadIgnoresGarbage(t *testing.T) {
	far := t0.Add(1000 * hour).Unix()
	lines := []string{
		"не JSON вовсе",
		`{"a":"не-адрес","n":["video.example"],"e":` + fmt.Sprint(far) + `}`,
		`{"a":"2001:db8::1","n":["video.example"],"e":` + fmt.Sprint(far) + `}`,
		`{"a":"1.1.1.1","n":[],"e":` + fmt.Sprint(far) + `}`,
		`{"a":"1.1.1.1","n":["video.example"],"e":1}`,
		`{"a":"2.2.2.2","n":["video.example"],"e":` + fmt.Sprint(far) + `}`,
		"",
	}
	s := New(config(t, src), hour)
	if n := s.Load(strings.NewReader(strings.Join(lines, "\n")), t0); n != 1 {
		t.Errorf("принято %d, ожидалась 1", n)
	}
	// Срок из файла ограничен сутками от текущего времени.
	if cs := s.Claims(ip2); len(cs) != 1 || !cs[0].Expires.Equal(t0.Add(24*hour)) {
		t.Errorf("срок не ограничен: %+v", cs)
	}
}
