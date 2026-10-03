package dataplane

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"trassa/internal/claims"
	"trassa/internal/rules"
)

// model runs a connection's first packet through the chains of an iptables-restore script, with
// the sets of ipset restore scripts, and reports the mark it gets. It knows only the rule forms
// trassa writes: anything else fails the test.
type model struct {
	t      *testing.T
	sets   map[string][]netip.Prefix
	chains map[string][][]string
}

func newModel(t *testing.T, calls []string) *model {
	t.Helper()
	m := &model{t: t, sets: map[string][]netip.Prefix{}, chains: map[string][][]string{}}
	for _, c := range calls {
		head, body, _ := strings.Cut(c, " <<\n")
		switch head {
		case "ipset restore":
			m.ipset(body)
		case "iptables-restore -n":
			m.iptables(body)
		}
	}
	return m
}

func (m *model) ipset(script string) {
	for _, line := range strings.Split(strings.TrimSpace(script), "\n") {
		f := strings.Fields(line)
		switch f[0] {
		case "create":
			if _, ok := m.sets[f[1]]; !ok {
				m.sets[f[1]] = nil
			}
		case "flush":
			m.sets[f[1]] = nil
		case "add":
			p, err := netip.ParsePrefix(f[2])
			if err != nil {
				p = netip.PrefixFrom(netip.MustParseAddr(f[2]), 32)
			}
			m.sets[f[1]] = append(m.sets[f[1]], p)
		case "del":
			kept := m.sets[f[1]][:0]
			for _, p := range m.sets[f[1]] {
				if p.String() != f[2]+"/32" {
					kept = append(kept, p)
				}
			}
			m.sets[f[1]] = kept
		case "swap":
			m.sets[f[1]], m.sets[f[2]] = m.sets[f[2]], m.sets[f[1]]
		case "destroy":
			delete(m.sets, f[1])
		default:
			m.t.Fatalf("model: unknown ipset command %q", line)
		}
	}
}

func (m *model) iptables(script string) {
	for _, line := range strings.Split(script, "\n") {
		switch {
		case strings.HasPrefix(line, ":"):
			m.chains[strings.Fields(line[1:])[0]] = nil
		case strings.HasPrefix(line, "-A "):
			f := strings.Fields(line)
			m.chains[f[1]] = append(m.chains[f[1]], f[2:])
		}
	}
}

func (m *model) in(set string, a netip.Addr) bool {
	ps, ok := m.sets[set]
	if !ok {
		m.t.Fatalf("model: set %s does not exist", set)
	}
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func num(t *testing.T, s string) uint32 {
	t.Helper()
	n, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		t.Fatalf("model: number %q: %v", s, err)
	}
	return uint32(n)
}

// packet is one packet of a connection as the model sees it.
type packet struct {
	src, dst       netip.Addr
	fresh          bool   // the connection's first packet
	mark, connmark uint32 // the packet's mark and the connection's
}

// mark runs the first packet of a new connection from src to dst through the chain TRASSA.
func (m *model) mark(src, dst string) uint32 {
	first, _ := m.connection(src, dst)
	return first
}

// connection runs a connection's first packet, then a later one that carries the mark the first
// one saved into the connection, and returns both packets' marks.
func (m *model) connection(src, dst string) (first, later uint32) {
	p := packet{src: netip.MustParseAddr(src), dst: netip.MustParseAddr(dst), fresh: true}
	m.run(routeChain, &p, 0)
	q := packet{src: p.src, dst: p.dst, connmark: p.connmark}
	m.run(routeChain, &q, 0)
	return p.mark, q.mark
}

// run runs a chain. It stops on RETURN, at the end of the chain, or after a goto.
func (m *model) run(chain string, p *packet, depth int) {
	if depth > 4 {
		m.t.Fatal("model: chains loop")
	}
	rs, ok := m.chains[chain]
	if !ok {
		m.t.Fatalf("model: chain %s does not exist", chain)
	}
	for _, r := range rs {
		match, module, neg := true, "", false
		var target []string
		for i := 0; i < len(r) && target == nil; i++ {
			switch r[i] {
			case "-m":
				module = r[i+1]
				i++
			case "!":
				neg = true
			case "--mark":
				val, mask, _ := strings.Cut(r[i+1], "/")
				mk := uint32(0xffffffff)
				if mask != "" {
					mk = num(m.t, mask)
				}
				have := p.mark
				if module == "connmark" {
					have = p.connmark
				}
				hit := have&mk == num(m.t, val)
				match = match && hit != neg
				neg = false
				i++
			case "--ctstate":
				if r[i+1] != "NEW" {
					m.t.Fatalf("model: unknown state %q", r[i+1])
				}
				match = match && p.fresh
				i++
			case "--match-set":
				a := p.dst
				if r[i+2] == "src" {
					a = p.src
				}
				match = match && m.in(r[i+1], a)
				i += 2
			case "-s", "-d":
				a := p.dst
				if r[i] == "-s" {
					a = p.src
				}
				match = match && netip.MustParsePrefix(r[i+1]).Contains(a)
				i++
			case "-j", "-g":
				target = r[i:]
			default:
				m.t.Fatalf("model: unknown option %q in %v", r[i], r)
			}
		}
		if !match {
			continue
		}
		switch {
		case target[0] == "-j" && target[1] == "RETURN":
			return
		case target[0] == "-j" && target[1] == "MARK":
			p.mark = num(m.t, target[3])
		case target[0] == "-j" && target[1] == "CONNMARK" && target[2] == "--restore-mark":
			p.mark = p.connmark
		case target[0] == "-j" && target[1] == "CONNMARK" && target[2] == "--save-mark":
			p.connmark = p.mark
		case target[0] == "-g":
			m.run(target[1], p, depth+1)
			return
		default:
			m.t.Fatalf("model: unknown target %v", target)
		}
	}
}

const devicesSrc = `exit vpn = W
device tv = 192.168.1.40
device office = 192.168.1.50
default direct
youtube.example -> vpn for tv
instagram.example -> vpn for !office
91.108.4.0/22 -> vpn for tv
1.1.1.0/24 -> vpn
`

// devicesModel builds devicesSrc for three devices: one in list tv, one in office, one in both.
func devicesModel(t *testing.T) *model {
	const tv, office, both rules.View = 1, 2, 3
	ip := netip.MustParseAddr
	run := &scripted{fail: []string{" -C "}}
	r := NewRouter(run, "br0", netip.Addr{})
	r.SetExits(map[string]string{"vpn": "nwg2"})
	v := rules.Action{Exit: "vpn"}
	entries := []claims.Entry{
		{View: 0, Addr: ip("6.6.6.6"), Action: v},  // instagram: everyone but office
		{View: tv, Addr: ip("5.5.5.5"), Action: v}, // youtube: the TV only
		{View: tv, Addr: ip("6.6.6.6"), Action: v},
		{View: both, Addr: ip("5.5.5.5"), Action: v}, // a device in both lists: youtube yes, instagram no
	}
	sources := map[rules.View][]netip.Addr{tv: {ip("192.168.1.40")}, office: {ip("192.168.1.50")}, both: {ip("192.168.1.60")}}
	if err := r.Rebuild(cfgOf(t, devicesSrc), sources, entries); err != nil {
		t.Fatal(err)
	}
	return newModel(t, run.calls)
}

func TestDeviceViewsMeaning(t *testing.T) {
	m := devicesModel(t)
	vm := markOf(t, marksOf(t, devicesSrc)[1])
	cases := []struct {
		from, to string
		want     uint32
	}{
		{"192.168.1.40", "5.5.5.5", vm}, {"192.168.1.30", "5.5.5.5", 0}, {"192.168.1.50", "5.5.5.5", 0}, {"192.168.1.60", "5.5.5.5", vm},
		{"192.168.1.30", "6.6.6.6", vm}, {"192.168.1.40", "6.6.6.6", vm}, {"192.168.1.50", "6.6.6.6", 0}, {"192.168.1.60", "6.6.6.6", 0},
		{"192.168.1.40", "91.108.4.9", vm}, {"192.168.1.30", "91.108.4.9", 0}, {"192.168.1.60", "91.108.4.9", vm},
		{"192.168.1.50", "1.1.1.1", vm}, {"192.168.1.40", "1.1.1.1", vm}, {"192.168.1.30", "1.1.1.1", vm},
	}
	for _, c := range cases {
		if got := m.mark(c.from, c.to); got != c.want {
			t.Errorf("%s → %s: mark %#x, want %#x", c.from, c.to, got, c.want)
		}
	}
}

func TestDeviceViewsWithTunnelDefault(t *testing.T) {
	const src = "exit vpn = W\ndevice tv = 192.168.1.40\ndefault vpn\nbank.example -> direct for tv\n"
	ip := netip.MustParseAddr
	run := &scripted{fail: []string{" -C "}}
	r := NewRouter(run, "br0", netip.Addr{})
	r.SetExits(map[string]string{"vpn": "nwg2"})
	entries := []claims.Entry{{View: 1, Addr: ip("7.7.7.7"), Action: rules.Action{Exit: "direct"}}}
	if err := r.Rebuild(cfgOf(t, src), map[rules.View][]netip.Addr{1: {ip("192.168.1.40")}}, entries); err != nil {
		t.Fatal(err)
	}
	m := newModel(t, run.calls)
	vm := markOf(t, marksOf(t, src)[1])
	cases := []struct {
		from, to string
		want     uint32
	}{
		{"192.168.1.40", "7.7.7.7", markBase}, {"192.168.1.30", "7.7.7.7", vm},
		{"192.168.1.40", "8.8.8.8", vm}, {"192.168.1.40", "192.168.1.1", 0},
	}
	for _, c := range cases {
		if got := m.mark(c.from, c.to); got != c.want {
			t.Errorf("%s → %s: mark %#x, want %#x", c.from, c.to, got, c.want)
		}
	}
}
func TestNoneBlocks(t *testing.T) {
	const src = "exit vpn = W\ndevice kids = 192.168.1.70\ndefault direct\nads.example -> none\n9.9.9.0/24 -> none\ngame.example -> none for kids\n"
	ip := netip.MustParseAddr
	run := &scripted{fail: []string{" -C "}}
	r := NewRouter(run, "br0", netip.Addr{})
	r.SetExits(map[string]string{"vpn": "nwg2"})
	none := rules.Action{Exit: rules.None}
	entries := []claims.Entry{{Addr: ip("6.6.6.6"), Action: none}, {View: 1, Addr: ip("6.6.6.6"), Action: none}, {View: 1, Addr: ip("7.7.7.7"), Action: none}}
	if err := r.Rebuild(cfgOf(t, src), map[rules.View][]netip.Addr{1: {ip("192.168.1.70")}}, entries); err != nil {
		t.Fatal(err)
	}
	marks := marksOf(t, src) // direct, vpn, vpn strict, none
	if len(marks) != 4 {
		t.Fatalf("slots: %v", marks)
	}
	nm := markOf(t, marks[3])
	m := newModel(t, run.calls)
	cases := []struct {
		from, to string
		want     uint32
	}{
		{"192.168.1.30", "6.6.6.6", nm}, {"192.168.1.30", "9.9.9.9", nm}, {"192.168.1.30", "7.7.7.7", 0},
		{"192.168.1.70", "7.7.7.7", nm}, {"192.168.1.70", "9.9.9.9", nm}, {"192.168.1.70", "8.8.8.8", 0},
	}
	for _, c := range cases {
		if got := m.mark(c.from, c.to); got != c.want {
			t.Errorf("%s → %s: mark %#x, want %#x", c.from, c.to, got, c.want)
		}
	}
	if got := fibAfter(run.calls).route(nm); got != "table 543: prohibit" {
		t.Errorf("a blocked mark goes to %q", got)
	}
	// Tunnels going down do not unblock anything.
	r.SetExits(map[string]string{"vpn": ""})
	if got := fibAfter(run.calls).route(nm); got != "table 543: prohibit" {
		t.Errorf("with the tunnel down a blocked mark goes to %q", got)
	}
}

func TestDefaultNoneKeepsLocalNetworks(t *testing.T) {
	const src = "exit vpn = W\ndefault none\nallowed.example -> direct\n"
	ip := netip.MustParseAddr
	run := &scripted{fail: []string{" -C "}}
	r := NewRouter(run, "br0", netip.Addr{})
	if err := r.Rebuild(cfgOf(t, src), nil, []claims.Entry{{Addr: ip("5.5.5.5"), Action: rules.Action{Exit: "direct"}}}); err != nil {
		t.Fatal(err)
	}
	nm := markOf(t, marksOf(t, src)[3])
	m := newModel(t, run.calls)
	cases := []struct {
		to   string
		want uint32
	}{{"8.8.8.8", nm}, {"5.5.5.5", markBase}, {"192.168.1.1", 0}, {"10.0.0.5", 0}}
	for _, c := range cases {
		if got := m.mark("192.168.1.30", c.to); got != c.want {
			t.Errorf("→ %s: mark %#x, want %#x", c.to, got, c.want)
		}
	}
}

func TestNoNoneSlotWithoutNone(t *testing.T) {
	if got := len(marksOf(t, oneExit)); got != 3 {
		t.Errorf("rules without none: %d slots, want 3", got)
	}
}

// Every later packet of a connection keeps the first packet's mark: the saved mark is restored
// before any view's chain is entered, and every view's chain saves its mark.
func TestDeviceViewsKeepTheMarkOnLaterPackets(t *testing.T) {
	m := devicesModel(t)
	vm := markOf(t, marksOf(t, devicesSrc)[1])
	cases := []struct {
		from, to string
		want     uint32
	}{
		{"192.168.1.40", "5.5.5.5", vm}, {"192.168.1.60", "5.5.5.5", vm}, {"192.168.1.30", "6.6.6.6", vm},
		{"192.168.1.40", "91.108.4.9", vm}, {"192.168.1.50", "6.6.6.6", 0},
	}
	for _, c := range cases {
		if first, later := m.connection(c.from, c.to); first != c.want || later != c.want {
			t.Errorf("%s → %s: first packet %#x, later %#x, want %#x", c.from, c.to, first, later, c.want)
		}
	}
}

func TestNoneLeavesTheOtherMarksAlone(t *testing.T) {
	const without = "exit vpn = W\nexit alt = W\ndefault direct\nx.example -> vpn\n"
	with := without + "ads.example -> none\n"
	if a, b := marksOf(t, without), marksOf(t, with); fmt.Sprint(a) != fmt.Sprint(b[:len(a)]) || len(b) != len(a)+1 {
		t.Errorf("marks without none %v, with %v", a, b)
	}
}

func TestNoneComesAndGoes(t *testing.T) {
	const without = "exit vpn = W\ndefault direct\nx.example -> vpn\n"
	with := without + "ads.example -> none\n"
	none := rules.Action{Exit: rules.None}
	nm := marksOf(t, with)[3]
	run := &scripted{fail: []string{" -C "}}
	r := NewRouter(run, "br0", netip.Addr{})
	if err := r.Rebuild(cfgOf(t, with), nil, nil); err != nil {
		t.Fatal(err)
	}
	run.calls = nil
	if err := r.Apply([]claims.Change{{Addr: netip.MustParseAddr("6.6.6.6"), New: &none}}); err != nil {
		t.Fatal(err)
	}
	equal(t, run.calls, []string{"ipset restore <<\nadd trassa_d3 6.6.6.6 -exist\n"})
	run.calls = nil
	run.out = map[string]string{"ip rule list": "203:\tfrom all fwmark " + nm + " lookup 543 \n"}
	run.fail = nil
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(run.calls, "ip route replace prohibit default table 543") {
		t.Errorf("reconcile must restore the blocking route: %v", run.calls)
	}
	// The rules stop blocking: the slot's rule goes and its table is emptied.
	run.calls = nil
	if err := r.Rebuild(cfgOf(t, without), nil, nil); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(run.changed(), "\n")
	for _, want := range []string{"ip rule del pref 203 fwmark " + nm + " lookup 543", "ip route flush table 543"} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q in\n%s", want, all)
		}
	}
}

// default none is for every device, devices of a list included: their chain blocks too, and leaves
// the local networks open.
func TestDefaultNoneForADeviceView(t *testing.T) {
	const src = "exit vpn = W\ndevice tv = 192.168.1.40\ndefault none\nallowed.example -> direct for tv\n"
	ip := netip.MustParseAddr
	run := &scripted{fail: []string{" -C "}}
	r := NewRouter(run, "br0", netip.Addr{})
	entries := []claims.Entry{{View: 1, Addr: ip("5.5.5.5"), Action: rules.Action{Exit: "direct"}}}
	if err := r.Rebuild(cfgOf(t, src), map[rules.View][]netip.Addr{1: {ip("192.168.1.40")}}, entries); err != nil {
		t.Fatal(err)
	}
	nm := markOf(t, marksOf(t, src)[3])
	m := newModel(t, run.calls)
	cases := []struct {
		from, to string
		want     uint32
	}{
		{"192.168.1.40", "5.5.5.5", markBase}, {"192.168.1.40", "8.8.8.8", nm}, {"192.168.1.40", "192.168.1.1", 0},
		{"192.168.1.30", "5.5.5.5", nm},
	}
	for _, c := range cases {
		if got := m.mark(c.from, c.to); got != c.want {
			t.Errorf("%s → %s: mark %#x, want %#x", c.from, c.to, got, c.want)
		}
	}
}
