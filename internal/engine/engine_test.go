package engine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"trassa/internal/claims"
	"trassa/internal/rules"
)

const src = `exit vpn = W
default direct
video.example -> vpn strict
ru -> direct
10.9.0.0/16 -> vpn
`

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func config(t *testing.T, s string) *rules.Config {
	t.Helper()
	cfg, ps := rules.Load(s, nil)
	if rules.HasErrors(ps) {
		t.Fatalf("правила: %v", ps)
	}
	return cfg
}

type fakeSink struct {
	got  []string
	fail bool
}

func (f *fakeSink) Apply(changes []claims.Change) error {
	if f.fail {
		return errors.New("списки недоступны")
	}
	for _, c := range changes {
		f.got = append(f.got, c.Addr.String()+" "+show(c.Old)+" => "+show(c.New))
	}
	return nil
}

type logs struct{ lines []string }

func (l *logs) printf(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func wireName(s string) []byte {
	var b []byte
	for _, l := range strings.Split(s, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

type rr struct {
	name string
	typ  uint16
	ttl  uint32
	data []byte
}

func dns(q string, flags uint16, rrs ...rr) []byte {
	b := []byte{0x12, 0x34, byte(flags >> 8), byte(flags), 0, 1, 0, byte(len(rrs)), 0, 0, 0, 0}
	b = append(b, wireName(q)...)
	b = append(b, 0, 1, 0, 1)
	for _, r := range rrs {
		b = append(b, wireName(r.name)...)
		b = binary.BigEndian.AppendUint16(b, r.typ)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, r.ttl)
		b = binary.BigEndian.AppendUint16(b, uint16(len(r.data)))
		b = append(b, r.data...)
	}
	return b
}

func a(name string, ttl uint32, ip string) rr {
	x := netip.MustParseAddr(ip).As4()
	return rr{name, 1, ttl, x[:]}
}

// ipv4 собирает пакет UDP от роутера клиенту 192.168.1.94.
func ipv4(sport uint16, payload []byte) []byte {
	b := make([]byte, 28+len(payload))
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[12:], []byte{192, 168, 1, 1})
	copy(b[16:], []byte{192, 168, 1, 94})
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], 40000)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

func ipv6(sport uint16, payload []byte) []byte {
	b := make([]byte, 48+len(payload))
	b[0], b[6], b[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
	b[23], b[39] = 1, 0x94
	binary.BigEndian.PutUint16(b[40:], sport)
	binary.BigEndian.PutUint16(b[42:], 40000)
	binary.BigEndian.PutUint16(b[44:], uint16(8+len(payload)))
	copy(b[48:], payload)
	return b
}

func answer(q string, addrs ...string) []byte {
	var rrs []rr
	for _, ip := range addrs {
		rrs = append(rrs, a(q, 300, ip))
	}
	return ipv4(53, dns(q, 0x8180, rrs...))
}

func newEngine(t *testing.T, sink Sink) (*Engine, *logs) {
	l := &logs{}
	return New(config(t, src), sink, l.printf, t0), l
}

func TestAnswerUnderRuleReachesSink(t *testing.T) {
	sink := &fakeSink{}
	e, _ := newEngine(t, sink)
	e.HandlePacket(t0, answer("video.example", "1.1.1.1", "2.2.2.2"))
	want := "1.1.1.1 - => vpn strict\n2.2.2.2 - => vpn strict"
	if got := strings.Join(sink.got, "\n"); got != want {
		t.Errorf("изменения:\n%s\nожидалось:\n%s", got, want)
	}
	if s := e.Stats(); s.Packets != 1 || s.Answers != 1 || s.Claimed != 1 || s.Changes != 2 {
		t.Errorf("счётчики: %+v", s)
	}
	// Тот же ответ ещё раз: списки не меняются.
	e.HandlePacket(t0.Add(time.Minute), answer("video.example", "1.1.1.1", "2.2.2.2"))
	if len(sink.got) != 2 || e.Stats().Changes != 2 {
		t.Errorf("повторный ответ изменил списки: %v", sink.got)
	}
}

func TestDefaultNameChangesNothing(t *testing.T) {
	sink := &fakeSink{}
	e, _ := newEngine(t, sink)
	e.HandlePacket(t0, answer("unknown.example", "1.1.1.1"))
	if len(sink.got) != 0 {
		t.Errorf("имя по default изменило списки: %v", sink.got)
	}
	if s := e.Stats(); s.Answers != 1 || s.Claimed != 0 {
		t.Errorf("счётчики: %+v", s)
	}
}

func TestMixedCaseCNAMEAndIPv6Transport(t *testing.T) {
	sink := &fakeSink{}
	e, _ := newEngine(t, sink)
	pkt := dns("WWW.Other.Example", 0x8180,
		rr{"www.other.example", 5, 60, wireName("Edge.Video.Example")},
		a("edge.video.example", 60, "3.3.3.3"))
	e.HandlePacket(t0, ipv6(53, pkt))
	if got := strings.Join(sink.got, "\n"); got != "3.3.3.3 - => vpn strict" {
		t.Errorf("изменения: %q", got)
	}
}

func TestIgnoresWhatIsNotAnAnswer(t *testing.T) {
	ok := dns("video.example", 0x8180, a("video.example", 60, "1.1.1.1"))
	aaaa := dns("video.example", 0x8180, rr{"video.example", 28, 60, make([]byte, 16)})
	frag := ipv4(53, ok)
	binary.BigEndian.PutUint16(frag[6:], 0x2000)
	tcp := ipv4(53, ok)
	tcp[9] = 6
	cases := []struct {
		name  string
		pkt   []byte
		count func(Stats) uint64
	}{
		{"пусто", nil, func(s Stats) uint64 { return s.NotDNS }},
		{"не IP", []byte("это не пакет, а просто строка"), func(s Stats) uint64 { return s.NotDNS }},
		{"TCP", tcp, func(s Stats) uint64 { return s.NotDNS }},
		{"фрагмент", frag, func(s Stats) uint64 { return s.NotDNS }},
		{"порт источника не 53", ipv4(5353, ok), func(s Stats) uint64 { return s.NotDNS }},
		{"мусор на порту 53", ipv4(53, []byte{1, 2, 3}), func(s Stats) uint64 { return s.Malformed }},
		{"обрезанный DNS", ipv4(53, ok[:len(ok)-3]), func(s Stats) uint64 { return s.Malformed }},
		{"запрос, а не ответ", ipv4(53, dns("video.example", 0x0100)), func(s Stats) uint64 { return s.Skipped }},
		{"NXDOMAIN", ipv4(53, dns("video.example", 0x8183)), func(s Stats) uint64 { return s.Skipped }},
		{"усечённый ответ", ipv4(53, dns("video.example", 0x8380, a("video.example", 60, "1.1.1.1"))), func(s Stats) uint64 { return s.Skipped }},
		{"только AAAA", ipv4(53, aaaa), func(s Stats) uint64 { return s.Skipped }},
		{"имя с недопустимым символом", ipv4(53, dns("vi deo.example", 0x8180, a("vi deo.example", 60, "1.1.1.1"))), func(s Stats) uint64 { return s.BadName }},
	}
	for _, c := range cases {
		sink := &fakeSink{}
		e, _ := newEngine(t, sink)
		e.HandlePacket(t0, c.pkt)
		if len(sink.got) != 0 {
			t.Errorf("%s: списки изменились: %v", c.name, sink.got)
		}
		if s := e.Stats(); c.count(s) != 1 || s.Packets != 1 {
			t.Errorf("%s: счётчики %+v", c.name, s)
		}
	}
}

func TestTickExpires(t *testing.T) {
	sink := &fakeSink{}
	e, _ := newEngine(t, sink)
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	e.Tick(t0.Add(30 * time.Minute))
	e.Tick(t0.Add(61 * time.Minute))
	want := "1.1.1.1 - => vpn strict\n1.1.1.1 vpn strict => -"
	if got := strings.Join(sink.got, "\n"); got != want {
		t.Errorf("изменения:\n%s\nожидалось:\n%s", got, want)
	}
}

func TestHugeTTLIsCapped(t *testing.T) {
	sink := &fakeSink{}
	e, _ := newEngine(t, sink)
	e.HandlePacket(t0, ipv4(53, dns("video.example", 0x8180, a("video.example", 0xffffffff, "1.1.1.1"))))
	e.Tick(t0.Add(25 * time.Hour))
	if len(sink.got) != 2 {
		t.Errorf("претензия с огромным TTL не истекла за сутки: %v", sink.got)
	}
}

func TestReload(t *testing.T) {
	sink := &fakeSink{}
	e, _ := newEngine(t, sink)
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	e.Reload(config(t, "exit vpn = W\ndefault direct\nvideo.example -> vpn\n"))
	want := "1.1.1.1 - => vpn strict\n1.1.1.1 vpn strict => vpn"
	if got := strings.Join(sink.got, "\n"); got != want {
		t.Errorf("изменения:\n%s\nожидалось:\n%s", got, want)
	}
	// Новые ответы решаются уже по новым правилам.
	e.HandlePacket(t0, answer("yandex.ru", "5.5.5.5"))
	if len(sink.got) != 2 {
		t.Errorf("правило, которого больше нет, сработало: %v", sink.got)
	}
}

func TestObserveModeOnlyLogs(t *testing.T) {
	e, l := newEngine(t, nil)
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	if len(l.lines) != 1 || !strings.Contains(l.lines[0], "192.168.1.94") ||
		!strings.Contains(l.lines[0], "video.example") || !strings.Contains(l.lines[0], "1.1.1.1 - → vpn strict") {
		t.Errorf("журнал: %q", l.lines)
	}
	if e.Stats().ApplyErrors != 0 {
		t.Error("в режиме наблюдения применять нечего, ошибок быть не должно")
	}
}

func TestSinkFailureIsCountedNotFatal(t *testing.T) {
	e, l := newEngine(t, &fakeSink{fail: true})
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	if e.Stats().ApplyErrors != 1 || !strings.Contains(strings.Join(l.lines, "\n"), "списки недоступны") {
		t.Errorf("счётчики %+v, журнал %q", e.Stats(), l.lines)
	}
}

func TestWhy(t *testing.T) {
	e, _ := newEngine(t, nil)
	e.HandlePacket(t0, answer("video.example", "1.1.1.1", "2.2.2.2"))
	e.HandlePacket(t0, answer("video.example", "10.9.0.5"))

	text, err := e.Why("Video.Example.", t0.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"video.example → vpn strict", "строка 3", "адресов по этому имени в памяти: 3", "1.1.1.1", "10 мин назад", "192.168.1.94"} {
		if !strings.Contains(text, want) {
			t.Errorf("why по имени: нет %q в\n%s", want, text)
		}
	}

	text, err = e.Why("1.1.1.1", t0.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1.1.1.1 → direct", "ни одно правило не подошло", "претензия: video.example", "строка 3", "в динамическом списке: vpn strict"} {
		if !strings.Contains(text, want) {
			t.Errorf("why по адресу: нет %q в\n%s", want, text)
		}
	}

	text, _ = e.Why("10.9.0.5", t0)
	if !strings.Contains(text, "10.9.0.5 → vpn") || !strings.Contains(text, "претензия: video.example") {
		t.Errorf("why по адресу из подсети:\n%s", text)
	}

	text, _ = e.Why("8.8.8.8", t0)
	if !strings.Contains(text, "в DNS-ответах этот адрес не встречался") {
		t.Errorf("why по незнакомому адресу:\n%s", text)
	}
	if text, _ = e.Why("never.seen.example", t0); !strings.Contains(text, "DNS-ответов для этого имени ещё не было") {
		t.Errorf("why по незнакомому имени:\n%s", text)
	}
	if _, err := e.Why("149.154.167", t0); err == nil {
		t.Error("недописанный адрес должен быть ошибкой")
	}
}

func TestStatus(t *testing.T) {
	e, _ := newEngine(t, nil)
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	e.HandlePacket(t0, answer("unknown.example", "9.9.9.9"))
	e.HandlePacket(t0, []byte("мусор"))
	text := e.Status(t0.Add(90 * time.Minute))
	for _, want := range []string{
		"режим наблюдения", "работает 1ч30м", "правил: 3", "адресов в памяти: 1",
		"пакетов: 3", "ответов с адресами: 2", "под правила: 1", "изменений: 1", "не DNS: 1",
		"192.168.1.94 video.example → vpn strict (строка 3)", "192.168.1.94 unknown.example → direct (default)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("в состоянии нет %q:\n%s", want, text)
		}
	}
	routed, _ := newEngine(t, &fakeSink{})
	if !strings.Contains(routed.Status(t0), "режим маршрутизации") {
		t.Error("с приёмником изменений режим должен называться маршрутизацией")
	}
}
