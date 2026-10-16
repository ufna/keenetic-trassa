package dataplane

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ufna/keenetic-trassa/internal/claims"
	"github.com/ufna/keenetic-trassa/internal/rules"
)

const (
	markBase   = 0x54520000 // every trassa mark has 0x5452 in the upper 16 bits
	markMask   = "0xffff0000"
	genShift   = 6  // slot numbers take the lower 6 bits: at most 1 + 2*28 + 1 = 58 slots
	genBits    = 10 // layout generation
	tableBase  = 540
	prefBase   = 200
	directPref = "199" // the direct slot goes back to the main table
	fallPref   = "298" // a slot of this layout whose table has no route goes direct
	stalePref  = "299" // a mark of any other layout goes nowhere
	staleTable = "599"
	routeChain = "TRASSA"
	setPrefix  = "trassa_"

	viewChainPrefix = routeChain + "_V"
)

// localNets are destinations that do not go into the tunnel via default: private and special networks.
var localNets = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3",
}

// Slot is an "exit + mode" pair. Number 0 is direct.
type Slot struct {
	Index  int
	Exit   string
	Strict bool
	gen    uint32
}

// generation is a 10-bit fingerprint of the exit names in order. Slot numbers mean exits in this
// order; when the list changes, the generation changes, and connections marked under the old
// layout do not follow the new meaning of their slot number. The same list gives the same
// generation after a daemon restart, so connections in progress keep their path.
func generation(cfg *rules.Config) uint32 {
	h := fnv.New32a()
	for _, e := range cfg.Exits {
		h.Write([]byte(e.Name))
		h.Write([]byte{0})
	}
	return h.Sum32() & (1<<genBits - 1)
}

// Mark is the slot's packet mark: direct is always markBase, tunnel slots carry the generation.
func (s Slot) Mark() string {
	if s.Index == 0 {
		return fmt.Sprintf("0x%x", markBase)
	}
	return fmt.Sprintf("0x%x", markBase|s.gen<<genShift|uint32(s.Index))
}

func (s Slot) Table() string { return strconv.Itoa(tableBase + s.Index) }
func (s Slot) Pref() string  { return strconv.Itoa(prefBase + s.Index) }
func (s Slot) Set() string   { return setPrefix + "d" + strconv.Itoa(s.Index) }

type staticSet struct {
	Name  string
	Nets  []netip.Prefix
	Slot  Slot
	rule  rules.Rule // the rule the set serves: which devices it applies to
	index int        // the rule's position: a "*" rule above it ends the rules for its devices
}

// Layout is what must exist in the kernel for the given rules and device views.
type Layout struct {
	Slots   []Slot      // Slots[0] is direct; then two per exit: normal and strict
	Static  []staticSet // one per rule with addresses, in rule order
	Default Slot
	// Views are the device views with their own source set, dynamic sets and chain, ascending.
	// The view of devices in no list (0) uses the main chain and is not listed.
	Views []rules.View
	gen   uint32
	exits map[string]int
	none  int // position of the blocking slot in Slots; 0 means the rules block nothing
	// ends holds, for every view, where its rules end (its "*" rule, or the number of rules) and
	// what it gets when nothing above matches.
	ends map[rules.View]viewEnd
}

// viewEnd is where a view's rules end and what its traffic gets when nothing above matches: the
// view's "*" rule, or default.
type viewEnd struct {
	limit int
	slot  Slot
}

func NewLayout(cfg *rules.Config, views []rules.View) (*Layout, error) {
	if len(cfg.Exits) > rules.MaxExits {
		return nil, fmt.Errorf("%d exits, at most %d are supported", len(cfg.Exits), rules.MaxExits)
	}
	gen := generation(cfg)
	l := &Layout{Slots: []Slot{{Exit: rules.Direct}}, Views: deviceViews(views), gen: gen, exits: map[string]int{}}
	for i, e := range cfg.Exits {
		l.exits[e.Name] = i
		l.Slots = append(l.Slots, Slot{Index: 1 + 2*i, Exit: e.Name, gen: gen}, Slot{Index: 2 + 2*i, Exit: e.Name, Strict: true, gen: gen})
	}
	if cfg.UsesNone() {
		// Blocking gets its own slot after the exits, and only when the rules use it: rules
		// without none get exactly the kernel state they got before.
		l.Slots = append(l.Slots, Slot{Index: len(l.Slots), Exit: rules.None, gen: gen})
		l.none = len(l.Slots) - 1
	}
	for i, r := range cfg.Rules {
		if len(r.Nets) > 0 {
			slot, ok := l.Slot(r.Action)
			if !ok {
				return nil, fmt.Errorf("line %d: exit %q is not declared", r.Line, r.Action.Exit)
			}
			l.Static = append(l.Static, staticSet{Name: setPrefix + "s" + strconv.Itoa(i), Nets: r.Nets, Slot: slot, rule: r, index: i})
		}
	}
	l.ends = map[rules.View]viewEnd{}
	for _, v := range append([]rules.View{0}, l.Views...) {
		d := cfg.DefaultFor(v)
		slot, ok := l.Slot(d.Action)
		if !ok {
			return nil, fmt.Errorf("default: exit %q is not declared", d.Action.Exit)
		}
		l.ends[v] = viewEnd{limit: cfg.CatchAll(v), slot: slot}
	}
	l.Default = l.ends[0].slot
	return l, nil
}

// Slot returns the slot for an action; false means the layout has no such exit.
func (l *Layout) Slot(a rules.Action) (Slot, bool) {
	if a.Exit == rules.None {
		if l.none == 0 {
			return Slot{}, false
		}
		return l.Slots[l.none], true
	}
	if a.Exit == rules.Direct {
		return l.Slots[0], true
	}
	x, ok := l.exits[a.Exit]
	if !ok {
		return Slot{}, false
	}
	i := 1 + 2*x
	if a.Strict {
		i++
	}
	return l.Slots[i], true
}

// deviceViews returns the distinct device views ascending, without 0.
func deviceViews(views []rules.View) []rules.View {
	var out []rules.View
	for _, v := range views {
		if v != 0 && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

// viewSet is the set of the source addresses of view v's devices.
func viewSet(v rules.View) string { return setPrefix + "v" + strconv.Itoa(int(v)) }

// viewChain is the chain that marks view v's connections.
func viewChain(v rules.View) string { return viewChainPrefix + strconv.Itoa(int(v)) }

// dynSet is the set of addresses from DNS that view v sends to slot s.
func dynSet(v rules.View, s Slot) string {
	if v == 0 {
		return s.Set()
	}
	return viewSet(v) + "d" + strconv.Itoa(s.Index)
}

func (l *Layout) hasView(v rules.View) bool { return v == 0 || slices.Contains(l.Views, v) }

func (l *Layout) hasChain(name string) bool {
	for _, v := range l.Views {
		if viewChain(v) == name {
			return true
		}
	}
	return false
}

func (l *Layout) hasSet(name string) bool {
	for _, v := range append([]rules.View{0}, l.Views...) {
		if v != 0 && viewSet(v) == name {
			return true
		}
		for _, s := range l.Slots {
			if dynSet(v, s) == name {
				return true
			}
		}
	}
	for _, s := range l.Static {
		if s.Name == name {
			return true
		}
	}
	return false
}

const tmpSuffix = "_n" // a set is filled under this temporary name and then swapped in

// writeSwap fills a set under a temporary name and swaps it in whole: a live set is never empty,
// even for a moment.
func writeSwap(b *strings.Builder, name, kind string, adds []string) {
	tmp := name + tmpSuffix
	fmt.Fprintf(b, "create %s %s -exist\ncreate %s %s -exist\nflush %s\n", name, kind, tmp, kind, tmp)
	for _, a := range adds {
		fmt.Fprintf(b, "add %s %s -exist\n", tmp, a)
	}
	fmt.Fprintf(b, "swap %s %s\ndestroy %s\n", tmp, name, tmp)
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

// setsScript is the input for "ipset restore": every set of the layout, each swapped in whole.
func (l *Layout) setsScript(sources map[rules.View][]netip.Addr, entries []claims.Entry) string {
	type set struct {
		name, kind string
		adds       []string
	}
	var sets []*set
	byName := map[string]*set{}
	add := func(name, kind string, adds []string) {
		s := &set{name: name, kind: kind, adds: adds}
		sets = append(sets, s)
		byName[name] = s
	}
	for _, s := range l.Slots {
		add(s.Set(), "hash:ip", nil)
	}
	for _, st := range l.Static {
		var nets []string
		for _, n := range st.Nets {
			nets = append(nets, n.String())
		}
		add(st.Name, "hash:net", nets)
	}
	for _, v := range l.Views {
		add(viewSet(v), "hash:ip", addrStrings(sources[v]))
		for _, s := range l.Slots {
			add(dynSet(v, s), "hash:ip", nil)
		}
	}
	for _, e := range entries {
		// The snapshot was taken under the same rules as the layout; an entry with an unknown exit
		// or view is skipped.
		if slot, ok := l.Slot(e.Action); ok && l.hasView(e.View) {
			s := byName[dynSet(e.View, slot)]
			s.adds = append(s.adds, e.Addr.String())
		}
	}
	var b strings.Builder
	for _, s := range sets {
		writeSwap(&b, s.name, s.kind, s.adds)
	}
	return b.String()
}

// sourcesScript refills the views' source sets, each swapped in whole.
func (l *Layout) sourcesScript(sources map[rules.View][]netip.Addr) string {
	var b strings.Builder
	for _, v := range l.Views {
		writeSwap(&b, viewSet(v), "hash:ip", addrStrings(sources[v]))
	}
	return b.String()
}

// chainScript is the input for "iptables-restore -n": declaring a chain flushes it, then the rules
// follow. A device of a device list goes from the main chain to its view's chain by a goto, so the
// main chain's rules for devices in no list are never reached for it.
func (l *Layout) chainScript() string {
	var b strings.Builder
	b.WriteString("*mangle\n:" + routeChain + " - [0:0]\n")
	for _, v := range l.Views {
		b.WriteString(":" + viewChain(v) + " - [0:0]\n")
	}
	rule := func(chain, format string, args ...any) {
		fmt.Fprintf(&b, "-A "+chain+" "+format+"\n", args...)
	}
	// The packet is already marked by the firmware, so it is not ours.
	rule(routeChain, "-m mark ! --mark 0x0 -j RETURN")
	// An established connection keeps its path.
	rule(routeChain, "-m connmark --mark 0x%x/%s -j CONNMARK --restore-mark", markBase, markMask)
	rule(routeChain, "-m mark ! --mark 0x0 -j RETURN")
	for _, v := range l.Views {
		// Only a new connection goes there: a later packet either got its mark restored above or
		// belongs to a connection trassa left alone.
		rule(routeChain, "-m conntrack --ctstate NEW -m set --match-set %s src -g %s", viewSet(v), viewChain(v))
	}
	l.marks(rule, routeChain, 0)
	for _, v := range l.Views {
		l.marks(rule, viewChain(v), v)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// marks adds to chain the rules that mark view v's new connections, and saving the mark into the
// connection.
func (l *Layout) marks(rule func(chain, format string, args ...any), chain string, v rules.View) {
	// Only the first packet of a connection gets a mark. An unmarked connection already in
	// progress is not moved to another path mid-transfer, and replies to inbound connections
	// are not mistaken for outbound ones.
	const fresh = "-m mark --mark 0x0 -m conntrack --ctstate NEW"
	for _, s := range l.Slots {
		rule(chain, fresh+" -m set --match-set %s dst -j MARK --set-mark %s", dynSet(v, s), s.Mark())
	}
	end := l.ends[v]
	for _, s := range l.Static {
		if s.rule.AppliesTo(v) && s.index < end.limit {
			rule(chain, fresh+" -m set --match-set %s dst -j MARK --set-mark %s", s.Name, s.Slot.Mark())
		}
	}
	// What the view's traffic gets when nothing above matched: its "*" rule or default. Direct
	// needs no mark: the router routes the connection as without trassa.
	if end.slot.Index != 0 {
		for _, n := range localNets {
			rule(chain, "-m mark --mark 0x0 -d %s -j RETURN", n)
		}
		rule(chain, fresh+" -j MARK --set-mark %s", end.slot.Mark())
	}
	rule(chain, "-m mark --mark 0x%x/%s -j CONNMARK --save-mark", markBase, markMask)
}
