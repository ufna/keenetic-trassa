package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"trassa/internal/claims"
	"trassa/internal/ctl"
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
		t.Fatalf("rules: %v", ps)
	}
	return cfg
}

type fakeSink struct {
	got     []string
	rebuilt []string // snapshot passed to the last Rebuild
	builds  int
	sources map[rules.View][]netip.Addr // passed to the last Rebuild or SetSources
	sourced int                         // SetSources calls
	fail    bool
}

// viewPrefix marks a device view's change; the view of devices in no list has no prefix.
func viewPrefix(v rules.View) string {
	if v == 0 {
		return ""
	}
	return fmt.Sprintf("[%d] ", v)
}

func (f *fakeSink) Apply(changes []claims.Change) error {
	if f.fail {
		return errors.New("sets unavailable")
	}
	for _, c := range changes {
		f.got = append(f.got, viewPrefix(c.View)+c.Addr.String()+" "+show(c.Old)+" => "+show(c.New))
	}
	return nil
}

func (f *fakeSink) Rebuild(cfg *rules.Config, sources map[rules.View][]netip.Addr, entries []claims.Entry) error {
	f.builds++
	f.sources = sources
	f.rebuilt = nil
	for _, e := range entries {
		f.rebuilt = append(f.rebuilt, viewPrefix(e.View)+e.Addr.String()+" "+e.Action.String())
	}
	if f.fail {
		return errors.New("sets unavailable")
	}
	return nil
}

func (f *fakeSink) SetSources(sources map[rules.View][]netip.Addr) error {
	f.sourced++
	f.sources = sources
	if f.fail {
		return errors.New("sets unavailable")
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

// ipv4 builds a UDP packet from the router to client 192.168.1.94.
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
		t.Errorf("changes:\n%s\nwant:\n%s", got, want)
	}
	if s := e.Stats(); s.Packets != 1 || s.Answers != 1 || s.Claimed != 1 || s.Changes != 2 {
		t.Errorf("counters: %+v", s)
	}
	// The same answer again: the sets do not change.
	e.HandlePacket(t0.Add(time.Minute), answer("video.example", "1.1.1.1", "2.2.2.2"))
	if len(sink.got) != 2 || e.Stats().Changes != 2 {
		t.Errorf("a repeated answer changed the sets: %v", sink.got)
	}
}

func TestDefaultNameChangesNothing(t *testing.T) {
	sink := &fakeSink{}
	e, _ := newEngine(t, sink)
	e.HandlePacket(t0, answer("unknown.example", "1.1.1.1"))
	if len(sink.got) != 0 {
		t.Errorf("a name under the default changed the sets: %v", sink.got)
	}
	if s := e.Stats(); s.Answers != 1 || s.Claimed != 0 {
		t.Errorf("counters: %+v", s)
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
		t.Errorf("changes: %q", got)
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
		{"empty", nil, func(s Stats) uint64 { return s.NotDNS }},
		{"not IP", []byte("this is not a packet, just a string"), func(s Stats) uint64 { return s.NotDNS }},
		{"TCP", tcp, func(s Stats) uint64 { return s.NotDNS }},
		{"fragment", frag, func(s Stats) uint64 { return s.NotDNS }},
		{"source port is not 53", ipv4(5353, ok), func(s Stats) uint64 { return s.NotDNS }},
		{"garbage on port 53", ipv4(53, []byte{1, 2, 3}), func(s Stats) uint64 { return s.Malformed }},
		{"truncated DNS", ipv4(53, ok[:len(ok)-3]), func(s Stats) uint64 { return s.Malformed }},
		{"query, not an answer", ipv4(53, dns("video.example", 0x0100)), func(s Stats) uint64 { return s.Skipped }},
		{"NXDOMAIN", ipv4(53, dns("video.example", 0x8183)), func(s Stats) uint64 { return s.Skipped }},
		{"answer with TC set", ipv4(53, dns("video.example", 0x8380, a("video.example", 60, "1.1.1.1"))), func(s Stats) uint64 { return s.Skipped }},
		{"AAAA only", ipv4(53, aaaa), func(s Stats) uint64 { return s.Skipped }},
		{"name with an invalid character", ipv4(53, dns("vi deo.example", 0x8180, a("vi deo.example", 60, "1.1.1.1"))), func(s Stats) uint64 { return s.BadName }},
	}
	for _, c := range cases {
		sink := &fakeSink{}
		e, _ := newEngine(t, sink)
		e.HandlePacket(t0, c.pkt)
		if len(sink.got) != 0 {
			t.Errorf("%s: the sets changed: %v", c.name, sink.got)
		}
		if s := e.Stats(); c.count(s) != 1 || s.Packets != 1 {
			t.Errorf("%s: counters %+v", c.name, s)
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
		t.Errorf("changes:\n%s\nwant:\n%s", got, want)
	}
}

func TestHugeTTLIsCapped(t *testing.T) {
	sink := &fakeSink{}
	e, _ := newEngine(t, sink)
	e.HandlePacket(t0, ipv4(53, dns("video.example", 0x8180, a("video.example", 0xffffffff, "1.1.1.1"))))
	e.Tick(t0.Add(25 * time.Hour))
	if len(sink.got) != 2 {
		t.Errorf("a claim with a huge TTL did not expire within a day: %v", sink.got)
	}
}

func TestReload(t *testing.T) {
	sink := &fakeSink{}
	e, l := newEngine(t, sink)
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	e.HandlePacket(t0, answer("yandex.ru", "5.5.5.5"))
	e.Reload(config(t, "exit vpn = W\ndefault direct\nvideo.example -> vpn\n"))
	// The sets are rebuilt in full: addresses of a rule that no longer exists are left out of the snapshot.
	if sink.builds != 1 || strings.Join(sink.rebuilt, "\n") != "1.1.1.1 vpn" {
		t.Errorf("builds %d, snapshot %q", sink.builds, sink.rebuilt)
	}
	if len(sink.got) != 2 {
		t.Errorf("the rule change went through Apply: %v", sink.got)
	}
	if !strings.Contains(strings.Join(l.lines, "\n"), "rules changed") {
		t.Errorf("the rule change is not in the log: %q", l.lines)
	}
	// New answers are decided by the new rules.
	e.HandlePacket(t0, answer("yandex.ru", "6.6.6.6"))
	if len(sink.got) != 2 {
		t.Errorf("a rule that no longer exists matched: %v", sink.got)
	}
	if e.Config().Rules[0].Action.Strict {
		t.Error("Config returns the old rules")
	}
}

func TestResync(t *testing.T) {
	sink := &fakeSink{}
	e, _ := newEngine(t, sink)
	e.HandlePacket(t0, answer("video.example", "1.1.1.1", "2.2.2.2"))
	if err := e.Resync(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(sink.rebuilt, "\n") != "1.1.1.1 vpn strict\n2.2.2.2 vpn strict" {
		t.Errorf("snapshot: %q", sink.rebuilt)
	}
	sink.fail = true
	if err := e.Resync(); err == nil || e.Stats().ApplyErrors != 1 {
		t.Errorf("build failure: error %v, counter %d", err, e.Stats().ApplyErrors)
	}
	observe, _ := newEngine(t, nil)
	if err := observe.Resync(); err != nil {
		t.Errorf("observe mode has nothing to build: %v", err)
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	e, _ := newEngine(t, &fakeSink{})
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	var buf bytes.Buffer
	if err := e.SaveState(&buf); err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	fresh, _ := newEngine(t, sink)
	if n := fresh.LoadState(&buf, t0.Add(10*time.Minute)); n != 1 {
		t.Fatalf("restored %d claims", n)
	}
	fresh.Resync()
	if strings.Join(sink.rebuilt, "\n") != "1.1.1.1 vpn strict" {
		t.Errorf("snapshot after restart: %q", sink.rebuilt)
	}
	if text, _ := fresh.Why("1.1.1.1", t0.Add(10*time.Minute)); !strings.Contains(text, "claim: video.example") {
		t.Errorf("the restored claim is not visible:\n%s", text)
	}
}

func TestExitsInWhyAndStatus(t *testing.T) {
	e, _ := newEngine(t, &fakeSink{})
	text, _ := e.Why("video.example", t0)
	if strings.Contains(text, "now via") {
		t.Errorf("nothing is known about exits yet:\n%s", text)
	}
	e.SetExits(map[string]string{"vpn": "Wireguard2"})
	if text, _ = e.Why("video.example", t0); !strings.Contains(text, "exit vpn: now via Wireguard2") {
		t.Errorf("live tunnel:\n%s", text)
	}
	if !strings.Contains(e.Status(t0), "exits: vpn → Wireguard2") {
		t.Errorf("status:\n%s", e.Status(t0))
	}
	e.SetExits(map[string]string{"vpn": ""})
	if text, _ = e.Why("video.example", t0); !strings.Contains(text, "all tunnels are down — traffic is blocked") {
		t.Errorf("strict without tunnels:\n%s", text)
	}
	if text, _ = e.Why("10.9.0.5", t0); !strings.Contains(text, "all tunnels are down — traffic goes direct") {
		t.Errorf("plain rule without tunnels:\n%s", text)
	}
	if !strings.Contains(e.Status(t0), "exits: vpn → no live tunnels") {
		t.Errorf("status:\n%s", e.Status(t0))
	}
}

func TestObserveModeOnlyLogs(t *testing.T) {
	e, l := newEngine(t, nil)
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	if len(l.lines) != 1 || !strings.Contains(l.lines[0], "192.168.1.94") ||
		!strings.Contains(l.lines[0], "video.example") || !strings.Contains(l.lines[0], "1.1.1.1 - → vpn strict") {
		t.Errorf("log: %q", l.lines)
	}
	if e.Stats().ApplyErrors != 0 {
		t.Error("observe mode has nothing to apply, there must be no errors")
	}
}

func TestSinkFailureIsCountedNotFatal(t *testing.T) {
	e, l := newEngine(t, &fakeSink{fail: true})
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	if e.Stats().ApplyErrors != 1 || !strings.Contains(strings.Join(l.lines, "\n"), "sets unavailable") {
		t.Errorf("counters %+v, log %q", e.Stats(), l.lines)
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
	for _, want := range []string{"video.example → vpn strict", "rule, line 3", "addresses for this name in memory: 3", "1.1.1.1", "10m ago", "192.168.1.94"} {
		if !strings.Contains(text, want) {
			t.Errorf("why by name: no %q in\n%s", want, text)
		}
	}

	text, err = e.Why("1.1.1.1", t0.Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1.1.1.1 → direct", "no rule matched", "claim: video.example", "line 3", "in the dynamic set: vpn strict"} {
		if !strings.Contains(text, want) {
			t.Errorf("why by address: no %q in\n%s", want, text)
		}
	}

	text, _ = e.Why("10.9.0.5", t0)
	if !strings.Contains(text, "10.9.0.5 → vpn") || !strings.Contains(text, "claim: video.example") {
		t.Errorf("why by an address from a subnet:\n%s", text)
	}

	text, _ = e.Why("8.8.8.8", t0)
	if !strings.Contains(text, "this address has not been seen in DNS answers") {
		t.Errorf("why by an unknown address:\n%s", text)
	}
	if text, _ = e.Why("never.seen.example", t0); !strings.Contains(text, "no DNS answers for this name yet") {
		t.Errorf("why by an unknown name:\n%s", text)
	}
	if _, err := e.Why("149.154.167", t0); err == nil {
		t.Error("an incomplete address must be an error")
	}
}

func TestStatus(t *testing.T) {
	e, _ := newEngine(t, nil)
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	e.HandlePacket(t0, answer("unknown.example", "9.9.9.9"))
	e.HandlePacket(t0, []byte("garbage"))
	text := e.Status(t0.Add(90 * time.Minute))
	for _, want := range []string{
		"observe mode", "uptime 1h30m", "rules: 3", "addresses in memory: 1",
		"packets: 3", "answers with addresses: 2", "matched rules: 1", "changes: 1", "not DNS: 1",
		"192.168.1.94 video.example → vpn strict (line 3)", "192.168.1.94 unknown.example → direct (default)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("status has no %q:\n%s", want, text)
		}
	}
	routed, _ := newEngine(t, &fakeSink{})
	if !strings.Contains(routed.Status(t0), "routing mode") {
		t.Error("with a sink the mode must be called routing")
	}
}

func TestManyAddressesAreCapped(t *testing.T) {
	sink := &fakeSink{}
	e, l := newEngine(t, sink)
	var rrs []rr
	for i := 0; i < 40; i++ {
		rrs = append(rrs, a("video.example", 300, fmt.Sprintf("7.7.7.%d", i+1)))
	}
	e.HandlePacket(t0, ipv4(53, dns("video.example", 0x8180, rrs...)))
	if len(sink.got) != maxAnswerAddrs {
		t.Errorf("%d of 40 addresses taken, limit %d", len(sink.got), maxAnswerAddrs)
	}
	// The log line does not grow with the answer.
	if len(l.lines) != 1 || len(l.lines[0]) > 600 || !strings.Contains(l.lines[0], "… 24 more") {
		t.Errorf("log: %d lines, first is %d long: %q", len(l.lines), len(l.lines[0]), l.lines)
	}
}

func chain(q string, hops int, last string, ip string) []byte {
	rrs := []rr{}
	cur := q
	for i := 0; i < hops; i++ {
		next := fmt.Sprintf("hop%d.example.net", i)
		if i == hops-1 {
			next = last
		}
		rrs = append(rrs, rr{cur, 5, 60, wireName(next)})
		cur = next
	}
	return ipv4(53, dns(q, 0x8180, append(rrs, a(cur, 60, ip))...))
}

func TestLongCNAMEChainIsCut(t *testing.T) {
	sink := &fakeSink{}
	e, _ := newEngine(t, sink)
	// The rule is on the third name of the chain: it counts.
	e.HandlePacket(t0, chain("www.other.example", 2, "edge.video.example", "1.1.1.1"))
	if len(sink.got) != 1 {
		t.Fatalf("short chain: %v", sink.got)
	}
	// The rule is on the twelfth name: the chain is cut to maxChain names, so no match.
	e.HandlePacket(t0, chain("www.far.example", 11, "edge.video.example", "2.2.2.2"))
	if len(sink.got) != 1 {
		t.Errorf("a chain that is too long was still counted: %v", sink.got)
	}
	if text, _ := e.Why("2.2.2.2", t0); !strings.Contains(text, "has not been seen") {
		t.Errorf("an address from a cut chain got into memory:\n%s", text)
	}
}

func TestStoreLimitIsReported(t *testing.T) {
	e, _ := newEngine(t, nil)
	for i := 0; i < maxPerAddr+5; i++ {
		e.HandlePacket(t0, answer(fmt.Sprintf("n%d.video.example", i), "1.1.1.1"))
	}
	if s := e.Stats(); s.Dropped != 5 {
		t.Errorf("dropped %d, want 5", s.Dropped)
	}
	if !strings.Contains(e.Status(t0), "over limit: 5") || !strings.Contains(e.Status(t0), "claims: 16") {
		t.Errorf("status:\n%s", e.Status(t0))
	}
}

func TestFailuresAskForResync(t *testing.T) {
	sink := &fakeSink{}
	e, _ := newEngine(t, sink)
	if e.NeedsResync() {
		t.Error("a healthy daemon needs no rebuild")
	}
	sink.fail = true
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	if !e.NeedsResync() {
		t.Error("after an Apply failure the sets differ from memory: a rebuild is needed")
	}
	if err := e.Resync(); err == nil || !e.NeedsResync() {
		t.Errorf("failed rebuild: error %v, flag %v", err, e.NeedsResync())
	}
	sink.fail = false
	if err := e.Resync(); err != nil || e.NeedsResync() {
		t.Errorf("successful rebuild: error %v, flag %v", err, e.NeedsResync())
	}
	if strings.Join(sink.rebuilt, "\n") != "1.1.1.1 vpn strict" {
		t.Errorf("after the rebuild, the address lost in the failure did not come back: %q", sink.rebuilt)
	}

	sink.fail = true
	if err := e.Reload(config(t, "exit vpn = W\ndefault direct\nvideo.example -> vpn\n")); err == nil || !e.NeedsResync() {
		t.Errorf("Reload must report the build failure: error %v, flag %v", err, e.NeedsResync())
	}
}

func TestState(t *testing.T) {
	e, _ := newEngine(t, nil)
	if st := e.State(); st.Mode != "observe" || st.Rules != 3 || len(st.Exits) != 1 || st.Exits[0].Known || st.Recent == nil {
		t.Errorf("empty state: %+v", st)
	}
	e.HandlePacket(t0, answer("video.example", "1.1.1.1"))
	e.HandlePacket(t0.Add(time.Second), answer("unknown.example", "9.9.9.9"))
	e.SetExits(map[string]string{"vpn": "Wireguard2"})
	st := e.State()
	if !st.Started.Equal(t0) || st.Addrs != 1 || st.Claims != 1 || st.Stats.Answers != 2 || st.Stats.Claimed != 1 {
		t.Errorf("counters: %+v", st)
	}
	if st.Exits[0] != (ctl.ExitState{Name: "vpn", Via: "Wireguard2", Known: true}) {
		t.Errorf("exits: %+v", st.Exits)
	}
	want := []ctl.Observation{
		{At: t0.Add(time.Second), Client: "192.168.1.94", Name: "unknown.example", Action: "direct"},
		{At: t0, Client: "192.168.1.94", Name: "video.example", Action: "vpn strict", Line: 3},
	}
	if len(st.Recent) != 2 || st.Recent[0] != want[0] || st.Recent[1] != want[1] {
		t.Errorf("observations (newest first): %+v", st.Recent)
	}
	if routed, _ := newEngine(t, &fakeSink{}); routed.State().Mode != "route" {
		t.Error("with a sink the mode is route")
	}
}

// A client may connect to an address from ipv4hint without asking for A records at all.
func TestHTTPSHintsAreClaimed(t *testing.T) {
	e, _ := newEngine(t, &fakeSink{})
	hint := []byte{0, 1, 0, 0, 4, 0, 4, 3, 3, 3, 3} // priority 1, target ".", ipv4hint 3.3.3.3
	e.HandlePacket(t0, ipv4(53, dns("video.example", 0x8180, rr{"video.example", 65, 300, hint})))
	if cs := e.store.Claims(netip.MustParseAddr("3.3.3.3")); len(cs) != 1 || cs[0].Action.Exit != "vpn" {
		t.Errorf("claims for the hint address: %+v", cs)
	}
}
