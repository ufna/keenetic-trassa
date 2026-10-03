package dataplane

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"strconv"
	"strings"

	"trassa/internal/claims"
	"trassa/internal/rules"
)

const (
	markBase   = 0x54520000 // every trassa mark has 0x5452 in the upper 16 bits
	markMask   = "0xffff0000"
	genShift   = 6  // slot numbers take the lower 6 bits: at most 1 + 2*29 = 59 slots
	genBits    = 10 // layout generation
	tableBase  = 540
	prefBase   = 200
	directPref = "199" // the direct slot goes back to the main table
	stalePref  = "299" // a mark of any other layout goes nowhere
	staleTable = "599"
	routeChain = "TRASSA"
	setPrefix  = "trassa_"
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
	Name string
	Nets []netip.Prefix
	Slot Slot
}

// Layout is what must exist in the kernel for the given rules.
type Layout struct {
	Slots   []Slot      // Slots[0] is direct; then two per exit: normal and strict
	Static  []staticSet // one per rule with addresses, in rule order
	Default Slot
	exits   map[string]int
}

func NewLayout(cfg *rules.Config) (*Layout, error) {
	if len(cfg.Exits) > rules.MaxExits {
		return nil, fmt.Errorf("%d exits, at most %d are supported", len(cfg.Exits), rules.MaxExits)
	}
	gen := generation(cfg)
	l := &Layout{Slots: []Slot{{Exit: rules.Direct}}, exits: map[string]int{}}
	for i, e := range cfg.Exits {
		l.exits[e.Name] = i
		l.Slots = append(l.Slots, Slot{Index: 1 + 2*i, Exit: e.Name, gen: gen}, Slot{Index: 2 + 2*i, Exit: e.Name, Strict: true, gen: gen})
	}
	for i, r := range cfg.Rules {
		if len(r.Nets) > 0 {
			slot, ok := l.Slot(r.Action)
			if !ok {
				return nil, fmt.Errorf("line %d: exit %q is not declared", r.Line, r.Action.Exit)
			}
			l.Static = append(l.Static, staticSet{Name: setPrefix + "s" + strconv.Itoa(i), Nets: r.Nets, Slot: slot})
		}
	}
	def, ok := l.Slot(cfg.Default)
	if !ok {
		return nil, fmt.Errorf("default: exit %q is not declared", cfg.Default.Exit)
	}
	l.Default = def
	return l, nil
}

// Slot returns the slot for an action; false means the layout has no such exit.
func (l *Layout) Slot(a rules.Action) (Slot, bool) {
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

func (l *Layout) hasSet(name string) bool {
	for _, s := range l.Slots {
		if s.Set() == name {
			return true
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

// setsScript is the input for "ipset restore". Each set is filled under a temporary name and
// swapped in whole: a live set is never empty, even for a moment.
func (l *Layout) setsScript(entries []claims.Entry) string {
	type set struct {
		name, kind string
		adds       []string
	}
	var sets []*set
	byName := map[string]*set{}
	add := func(name, kind string) *set {
		s := &set{name: name, kind: kind}
		sets = append(sets, s)
		byName[name] = s
		return s
	}
	for _, s := range l.Slots {
		add(s.Set(), "hash:ip")
	}
	for _, st := range l.Static {
		s := add(st.Name, "hash:net")
		for _, n := range st.Nets {
			s.adds = append(s.adds, n.String())
		}
	}
	for _, e := range entries {
		// The snapshot was taken under the same rules as the layout; an entry with an unknown exit is skipped.
		if slot, ok := l.Slot(e.Action); ok {
			byName[slot.Set()].adds = append(byName[slot.Set()].adds, e.Addr.String())
		}
	}
	var b strings.Builder
	for _, s := range sets {
		tmp := s.name + tmpSuffix
		fmt.Fprintf(&b, "create %s %s -exist\ncreate %s %s -exist\nflush %s\n", s.name, s.kind, tmp, s.kind, tmp)
		for _, a := range s.adds {
			fmt.Fprintf(&b, "add %s %s -exist\n", tmp, a)
		}
		fmt.Fprintf(&b, "swap %s %s\ndestroy %s\n", tmp, s.name, tmp)
	}
	return b.String()
}

// chainScript is the input for "iptables-restore -n": declaring the chain flushes it, then the rules follow.
func (l *Layout) chainScript() string {
	var b strings.Builder
	b.WriteString("*mangle\n:" + routeChain + " - [0:0]\n")
	rule := func(format string, args ...any) {
		fmt.Fprintf(&b, "-A "+routeChain+" "+format+"\n", args...)
	}
	// The packet is already marked by the firmware, so it is not ours.
	rule("-m mark ! --mark 0x0 -j RETURN")
	// An established connection keeps its path.
	rule("-m connmark --mark 0x%x/%s -j CONNMARK --restore-mark", markBase, markMask)
	rule("-m mark ! --mark 0x0 -j RETURN")
	// Only the first packet of a connection gets a mark. An unmarked connection already in
	// progress is not moved to another path mid-transfer, and replies to inbound connections
	// are not mistaken for outbound ones.
	const fresh = "-m mark --mark 0x0 -m conntrack --ctstate NEW"
	for _, s := range l.Slots {
		rule(fresh+" -m set --match-set %s dst -j MARK --set-mark %s", s.Set(), s.Mark())
	}
	for _, s := range l.Static {
		rule(fresh+" -m set --match-set %s dst -j MARK --set-mark %s", s.Name, s.Slot.Mark())
	}
	if l.Default.Index != 0 {
		for _, n := range localNets {
			rule("-m mark --mark 0x0 -d %s -j RETURN", n)
		}
		rule(fresh+" -j MARK --set-mark %s", l.Default.Mark())
	}
	rule("-m mark --mark 0x%x/%s -j CONNMARK --save-mark", markBase, markMask)
	b.WriteString("COMMIT\n")
	return b.String()
}
