package dataplane

import (
	"net/netip"
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

// mark runs the first packet of a new connection from src to dst through the chain TRASSA.
func (m *model) mark(src, dst string) uint32 {
	var mark uint32
	m.run(routeChain, netip.MustParseAddr(src), netip.MustParseAddr(dst), &mark, 0)
	return mark
}

// run runs a chain. It stops on RETURN, at the end of the chain, or after a goto.
func (m *model) run(chain string, src, dst netip.Addr, mark *uint32, depth int) {
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
				have := *mark
				if module == "connmark" {
					have = 0 // the first packet: the connection has no mark yet
				}
				hit := have&mk == num(m.t, val)
				match = match && hit != neg
				neg = false
				i++
			case "--ctstate":
				i++ // every packet here starts a new connection
			case "--match-set":
				a := dst
				if r[i+2] == "src" {
					a = src
				}
				match = match && m.in(r[i+1], a)
				i += 2
			case "-s", "-d":
				a := dst
				if r[i] == "-s" {
					a = src
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
			*mark = num(m.t, target[3])
		case target[0] == "-j" && target[1] == "CONNMARK":
		case target[0] == "-g":
			m.run(target[1], src, dst, mark, depth+1)
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

func TestDeviceViewsMeaning(t *testing.T) {
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
	m := newModel(t, run.calls)
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
