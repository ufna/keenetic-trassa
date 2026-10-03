// Package claims remembers which rules claim which address and computes which
// dynamic kernel address set an address belongs in.
package claims

import (
	"bufio"
	"encoding/json"
	"io"
	"net/netip"
	"slices"
	"sort"
	"time"

	"trassa/internal/rules"
)

// Claim is a claim on an address, created from a DNS answer. The decision depends on the device:
// Index and Action are given for the view a caller asked about.
type Claim struct {
	Names   []string     // the queried name and its CNAME targets
	Index   int          // rule number for the view asked about; lower means older
	Action  rules.Action // the decision for the view asked about
	Expires time.Time

	dec  []rules.Decision // per tracked view (Store.views); Rule == nil: no rule for that view
	rank int              // the earliest rule for any device: eviction keeps claims of older rules
}

// Change is a change to the dynamic sets of one view. nil means "the address is in no set".
type Change struct {
	View     rules.View
	Addr     netip.Addr
	Old, New *rules.Action
}

// Store is not safe for concurrent use: the caller serializes access.
type Store struct {
	cfg    *rules.Config
	views  []rules.View // tracked views: views[0] is 0, a device in no list; then device views ascending
	minTTL time.Duration
	byAddr map[netip.Addr][]Claim

	total   int    // claims in total, across all addresses
	limit   int    // cap on total; 0 means no cap
	perAddr int    // cap on claims per address; 0 means no cap
	dropped uint64 // claims rejected because of the caps
}

// SetLimits bounds the store's memory: total claims and claims per address.
// A device on the home network can send any number of "answers", and without caps
// the store would grow along with them.
func (s *Store) SetLimits(total, perAddr int) { s.limit, s.perAddr = total, perAddr }

// Total returns the number of claims across all addresses.
func (s *Store) Total() int { return s.total }

// Dropped returns the number of claims rejected because of the caps.
func (s *Store) Dropped() uint64 { return s.dropped }

func New(cfg *rules.Config, minTTL time.Duration) *Store {
	return &Store{cfg: cfg, views: []rules.View{0}, minTTL: minTTL, byAddr: map[netip.Addr][]Claim{}}
}

// Views returns the tracked device views, ascending, without the view of devices in no list.
func (s *Store) Views() []rules.View { return append([]rules.View(nil), s.views[1:]...) }

// position returns the position of view v among the tracked views.
func (s *Store) position(v rules.View) (int, bool) {
	for i, w := range s.views {
		if w == v {
			return i, true
		}
	}
	return 0, false
}

// decide decides a name chain for every tracked view. ok is false if no rule matches the chain for
// any device at all; a chain matched only by a rule of an untracked view is still kept, since a
// device of that view may join later.
func (s *Store) decide(names []string) (dec []rules.Decision, rank int, ok bool) {
	any := s.cfg.MatchChainAny(names)
	if any.Rule == nil {
		return nil, 0, false
	}
	dec = make([]rules.Decision, len(s.views))
	for i, v := range s.views {
		dec[i] = s.decideFor(v, names, any)
	}
	return dec, any.Index, true
}

// decideFor decides a name chain for view v, given any, its decision with "for" ignored. The rule
// any found is the first rule matching the first name that matches at all: when it applies to v,
// it is v's decision too, and the rules need no second scan.
func (s *Store) decideFor(v rules.View, names []string, any rules.Decision) rules.Decision {
	if any.Rule != nil && any.Rule.AppliesTo(v) {
		return any
	}
	return s.cfg.MatchChainFor(v, names)
}

func (s *Store) Len() int { return len(s.byAddr) }

// ClaimsFor returns the claims on an address that have a rule for view v, with Index and Action for v.
func (s *Store) ClaimsFor(v rules.View, addr netip.Addr) []Claim {
	i, ok := s.position(v)
	if !ok {
		return nil
	}
	var out []Claim
	for _, c := range s.byAddr[addr] {
		if d := c.dec[i]; d.Rule != nil {
			c.Index, c.Action = d.Index, d.Action
			out = append(out, c)
		}
	}
	return out
}

// Claims returns the claims on an address for a device in no list.
func (s *Store) Claims(addr netip.Addr) []Claim { return s.ClaimsFor(0, addr) }

// AddrsOf returns the addresses claimed by the queried name, in ascending order.
func (s *Store) AddrsOf(name string) []netip.Addr {
	var out []netip.Addr
	for a, cs := range s.byAddr {
		for _, c := range cs {
			if c.Names[0] == name {
				out = append(out, a)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// Known reports whether any DNS answer claimed the address, for any device.
func (s *Store) Known(addr netip.Addr) bool { return len(s.byAddr[addr]) > 0 }

// EffectiveFor returns the action with which the address belongs in view v's dynamic set, or nil.
func (s *Store) EffectiveFor(v rules.View, addr netip.Addr) *rules.Action {
	i, ok := s.position(v)
	if !ok {
		return nil
	}
	return s.effective(i, addr)
}

// Effective is EffectiveFor for a device in no list.
func (s *Store) Effective(addr netip.Addr) *rules.Action { return s.EffectiveFor(0, addr) }

func (s *Store) effective(i int, addr netip.Addr) *rules.Action {
	cs := s.byAddr[addr]
	var best *rules.Decision
	for k := range cs {
		if d := &cs[k].dec[i]; d.Rule != nil && (best == nil || d.Index < best.Index) {
			best = d
		}
	}
	if best == nil {
		return nil
	}
	// A subnet of an earlier rule is older: its static set serves the address.
	if st := s.cfg.MatchAddrFor(s.views[i], addr); st.Rule != nil && st.Index < best.Index {
		return nil
	}
	a := best.Action
	return &a
}

// effectiveAll returns the address's action for every tracked view.
func (s *Store) effectiveAll(addr netip.Addr) []*rules.Action {
	out := make([]*rules.Action, len(s.views))
	for i := range s.views {
		out[i] = s.effective(i, addr)
	}
	return out
}

// changes compares an address's actions with old, taken under the same views, view by view.
func (s *Store) changes(out []Change, addr netip.Addr, old []*rules.Action) []Change {
	for i, v := range s.views {
		out = appendChange(out, v, addr, old[i], s.effective(i, addr))
	}
	return out
}

// Observe records a DNS answer: names are the queried name and its CNAME targets, addrs the answer's addresses.
func (s *Store) Observe(now time.Time, names []string, addrs []netip.Addr, ttl time.Duration) []Change {
	dec, rank, ok := s.decide(names)
	if !ok {
		return nil
	}
	if ttl < s.minTTL {
		ttl = s.minTTL
	}
	// Copy: we keep the caller's slice for a long time, and it must not change under us.
	names = append([]string(nil), names...)
	c := Claim{Names: names, Expires: now.Add(ttl), dec: dec, rank: rank}
	var out []Change
	for _, a := range addrs {
		if !usable(a) {
			continue
		}
		old := s.effectiveAll(a)
		s.add(a, c)
		out = s.changes(out, a, old)
	}
	return out
}

// Expire removes the claims that have expired by now.
func (s *Store) Expire(now time.Time) []Change {
	var out []Change
	for a, cs := range s.byAddr {
		// Nothing expired, nothing changes: the tick holds the engine's lock, so it skips the
		// addresses it would only recompute.
		if !anyExpired(cs, now) {
			continue
		}
		old := s.effectiveAll(a)
		live := cs[:0]
		for _, c := range cs {
			if c.Expires.After(now) {
				live = append(live, c)
			}
		}
		s.total -= len(cs) - len(live)
		s.put(a, live)
		out = s.changes(out, a, old)
	}
	sortChanges(out)
	return out
}

func anyExpired(cs []Claim, now time.Time) bool {
	for _, c := range cs {
		if !c.Expires.After(now) {
			return true
		}
	}
	return false
}

// SetConfig switches the store to new rules and device views (the view of devices in no list is
// tracked always): every claim is decided again from its name chain. Changes are reported for the
// views tracked after the switch; a view tracked before but not after has no sets any more.
func (s *Store) SetConfig(cfg *rules.Config, views []rules.View) []Change {
	old := make(map[rules.View]map[netip.Addr]*rules.Action, len(s.views))
	for i, v := range s.views {
		m := make(map[netip.Addr]*rules.Action, len(s.byAddr))
		for a := range s.byAddr {
			m[a] = s.effective(i, a)
		}
		old[v] = m
	}
	s.cfg, s.views = cfg, trackedViews(views)
	var out []Change
	for a, cs := range s.byAddr {
		kept := cs[:0]
		for _, c := range cs {
			dec, rank, ok := s.decide(c.Names)
			if !ok {
				continue
			}
			c.dec, c.rank = dec, rank
			kept = append(kept, c)
		}
		s.total -= len(cs) - len(kept)
		s.put(a, kept)
		for i, v := range s.views {
			out = appendChange(out, v, a, old[v][a], s.effective(i, a))
		}
	}
	sortChanges(out)
	return out
}

// SetViews switches the tracked device views under the same rules. It runs whenever a listed
// device joins or leaves, under the engine's lock, so only the added views are decided: the views
// tracked before keep their decisions. Changes are reported for the added views; a removed view
// has no sets any more, as in SetConfig.
func (s *Store) SetViews(views []rules.View) []Change {
	next := trackedViews(views)
	if slices.Equal(next, s.views) {
		return nil
	}
	from := make([]int, len(next)) // position of each next view among the current ones; -1 if added
	for i, v := range next {
		from[i] = -1
		if k, ok := s.position(v); ok {
			from[i] = k
		}
	}
	for _, cs := range s.byAddr {
		for ci := range cs {
			c := &cs[ci]
			r := &s.cfg.Rules[c.rank]
			any := rules.Decision{Index: c.rank, Rule: r, Action: r.Action}
			dec := make([]rules.Decision, len(next))
			for i, v := range next {
				if from[i] >= 0 {
					dec[i] = c.dec[from[i]]
				} else {
					dec[i] = s.decideFor(v, c.Names, any)
				}
			}
			c.dec = dec
		}
	}
	s.views = next
	var out []Change
	for i, v := range next {
		if from[i] < 0 {
			for a := range s.byAddr {
				out = appendChange(out, v, a, nil, s.effective(i, a))
			}
		}
	}
	sortChanges(out)
	return out
}

// trackedViews puts the view of devices in no list first, then the distinct device views ascending.
func trackedViews(views []rules.View) []rules.View {
	out := []rules.View{0}
	for _, v := range views {
		if v != 0 && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out[1:])
	return out
}

func (s *Store) put(a netip.Addr, cs []Claim) {
	if len(cs) == 0 {
		delete(s.byAddr, a)
		return
	}
	s.byAddr[a] = cs
}

// add replaces the claim for the same queried name or adds a new one, respecting the caps.
// A replacement never shortens the expiry: a new answer can only extend a claim.
func (s *Store) add(a netip.Addr, c Claim) {
	cs := s.byAddr[a]
	for i := range cs {
		if cs[i].Names[0] == c.Names[0] {
			if cs[i].Expires.After(c.Expires) {
				c.Expires = cs[i].Expires
			}
			cs[i] = c
			return
		}
	}
	if s.perAddr > 0 && len(cs) >= s.perAddr {
		// The address is full: a new claim evicts the worst one only if it is older than it.
		worst := 0
		for i := range cs {
			if cs[i].rank > cs[worst].rank {
				worst = i
			}
		}
		if cs[worst].rank <= c.rank {
			s.dropped++
			return
		}
		cs[worst] = c
		return
	}
	if s.limit > 0 && s.total >= s.limit {
		s.dropped++
		return
	}
	s.byAddr[a] = append(cs, c)
	s.total++
}

func appendChange(out []Change, v rules.View, a netip.Addr, old, cur *rules.Action) []Change {
	if old == nil && cur == nil || old != nil && cur != nil && *old == *cur {
		return out
	}
	return append(out, Change{View: v, Addr: a, Old: old, New: cur})
}

func sortChanges(cs []Change) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].View != cs[j].View {
			return cs[i].View < cs[j].View
		}
		return cs[i].Addr.Less(cs[j].Addr)
	})
}

// usable reports whether the address can be a destination of ordinary traffic. The kernel
// address set rejects the zero address (blocking DNS servers answer with it) outright, and a
// single such entry would break the whole set rebuild; other special addresses need no routing.
func usable(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	return b[0] != 0 && b[0] != 127 && b[0] < 224 && !(b[0] == 169 && b[1] == 254)
}

// Entry is an address and the action with which it belongs in a view's dynamic set.
type Entry struct {
	View   rules.View
	Addr   netip.Addr
	Action rules.Action
}

// Entries returns everything that belongs in the dynamic sets of the tracked views, by view, then
// by ascending address.
func (s *Store) Entries() []Entry {
	out := make([]Entry, 0, len(s.byAddr))
	for a := range s.byAddr {
		for i, v := range s.views {
			if eff := s.effective(i, a); eff != nil {
				out = append(out, Entry{View: v, Addr: a, Action: *eff})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].View != out[j].View {
			return out[i].View < out[j].View
		}
		return out[i].Addr.Less(out[j].Addr)
	})
	return out
}

// maxKeep is how far ahead the expiry of a claim read from a file may reach.
const maxKeep = 24 * time.Hour

type saved struct {
	Addr    string   `json:"a"`
	Names   []string `json:"n"`
	Expires int64    `json:"e"`
}

// Save writes the claims, one per line. Decisions are not saved: on load every
// claim is decided again by the rules in effect at that time.
func (s *Store) Save(w io.Writer) error {
	enc := json.NewEncoder(w)
	for a, cs := range s.byAddr {
		for _, c := range cs {
			if err := enc.Encode(saved{Addr: a.String(), Names: c.Names, Expires: c.Expires.Unix()}); err != nil {
				return err
			}
		}
	}
	return nil
}

// Load reads claims written by Save and returns the number accepted.
func (s *Store) Load(r io.Reader, now time.Time) int {
	n := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<10)
	for sc.Scan() {
		var v saved
		if json.Unmarshal(sc.Bytes(), &v) != nil || len(v.Names) == 0 {
			continue
		}
		// Names from the file are checked like names from DNS: the file outlives the daemon.
		if !normalize(v.Names) {
			continue
		}
		a, err := netip.ParseAddr(v.Addr)
		if err != nil || !usable(a) {
			continue
		}
		expires := time.Unix(v.Expires, 0)
		if !expires.After(now) {
			continue
		}
		if limit := now.Add(maxKeep); expires.After(limit) {
			expires = limit
		}
		dec, rank, ok := s.decide(v.Names)
		if !ok {
			continue
		}
		before := s.total
		s.add(a, Claim{Names: v.Names, Expires: expires, dec: dec, rank: rank})
		if s.total > before {
			n++
		}
	}
	return n
}

// normalize brings names to the form they are matched in; false if any of them is not a domain name.
func normalize(names []string) bool {
	for i, n := range names {
		norm, err := rules.NormalizeName(n)
		if err != nil {
			return false
		}
		names[i] = norm
	}
	return true
}
