// Package claims remembers which rules claim which address and computes which
// dynamic kernel address set an address belongs in.
package claims

import (
	"bufio"
	"encoding/json"
	"io"
	"net/netip"
	"sort"
	"time"

	"trassa/internal/rules"
)

// Claim is a rule's claim on an address, created from a DNS answer.
type Claim struct {
	Names   []string // the queried name and its CNAME targets
	Index   int      // rule number; lower means older
	Action  rules.Action
	Expires time.Time
}

// Change is a change to the dynamic sets. nil means "the address is in no set".
type Change struct {
	Addr     netip.Addr
	Old, New *rules.Action
}

// Store is not safe for concurrent use: the caller serializes access.
type Store struct {
	cfg    *rules.Config
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
	return &Store{cfg: cfg, minTTL: minTTL, byAddr: map[netip.Addr][]Claim{}}
}

func (s *Store) Len() int { return len(s.byAddr) }

// Claims returns a copy of the claims on an address: the store rewrites its slices in place.
func (s *Store) Claims(addr netip.Addr) []Claim { return append([]Claim(nil), s.byAddr[addr]...) }

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

// Effective returns the action with which the address belongs in a dynamic set, or nil.
func (s *Store) Effective(addr netip.Addr) *rules.Action {
	cs := s.byAddr[addr]
	if len(cs) == 0 {
		return nil
	}
	best := cs[0]
	for _, c := range cs[1:] {
		if c.Index < best.Index {
			best = c
		}
	}
	// A subnet of an earlier rule is older: its static set serves the address.
	if st := s.cfg.MatchAddr(addr); st.Rule != nil && st.Index < best.Index {
		return nil
	}
	a := best.Action
	return &a
}

// Observe records a DNS answer: names are the queried name and its CNAME targets, addrs the answer's addresses.
func (s *Store) Observe(now time.Time, names []string, addrs []netip.Addr, ttl time.Duration) []Change {
	d := s.cfg.MatchChain(names)
	if d.Rule == nil {
		return nil
	}
	if ttl < s.minTTL {
		ttl = s.minTTL
	}
	// Copy: we keep the caller's slice for a long time, and it must not change under us.
	names = append([]string(nil), names...)
	c := Claim{Names: names, Index: d.Index, Action: d.Action, Expires: now.Add(ttl)}
	var out []Change
	for _, a := range addrs {
		if !usable(a) {
			continue
		}
		old := s.Effective(a)
		s.add(a, c)
		out = appendChange(out, a, old, s.Effective(a))
	}
	return out
}

// Expire removes the claims that have expired by now.
func (s *Store) Expire(now time.Time) []Change {
	var out []Change
	for a, cs := range s.byAddr {
		old := s.Effective(a)
		live := cs[:0]
		for _, c := range cs {
			if c.Expires.After(now) {
				live = append(live, c)
			}
		}
		s.total -= len(cs) - len(live)
		s.put(a, live)
		out = appendChange(out, a, old, s.Effective(a))
	}
	sortChanges(out)
	return out
}

// SetConfig switches the store to new rules: every claim is decided again from its name chain.
func (s *Store) SetConfig(cfg *rules.Config) []Change {
	old := make(map[netip.Addr]*rules.Action, len(s.byAddr))
	for a := range s.byAddr {
		old[a] = s.Effective(a)
	}
	s.cfg = cfg
	var out []Change
	for a, cs := range s.byAddr {
		kept := cs[:0]
		for _, c := range cs {
			d := cfg.MatchChain(c.Names)
			if d.Rule == nil {
				continue
			}
			c.Index, c.Action = d.Index, d.Action
			kept = append(kept, c)
		}
		s.total -= len(cs) - len(kept)
		s.put(a, kept)
		out = appendChange(out, a, old[a], s.Effective(a))
	}
	sortChanges(out)
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
			if cs[i].Index > cs[worst].Index {
				worst = i
			}
		}
		if cs[worst].Index <= c.Index {
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

func appendChange(out []Change, a netip.Addr, old, cur *rules.Action) []Change {
	if old == nil && cur == nil || old != nil && cur != nil && *old == *cur {
		return out
	}
	return append(out, Change{Addr: a, Old: old, New: cur})
}

func sortChanges(cs []Change) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].Addr.Less(cs[j].Addr) })
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

// Entry is an address and the action with which it belongs in a dynamic set.
type Entry struct {
	Addr   netip.Addr
	Action rules.Action
}

// Entries returns everything that belongs in the dynamic sets, by ascending address.
func (s *Store) Entries() []Entry {
	out := make([]Entry, 0, len(s.byAddr))
	for a := range s.byAddr {
		if eff := s.Effective(a); eff != nil {
			out = append(out, Entry{Addr: a, Action: *eff})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
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
		d := s.cfg.MatchChain(v.Names)
		if d.Rule == nil {
			continue
		}
		before := s.total
		s.add(a, Claim{Names: v.Names, Index: d.Index, Action: d.Action, Expires: expires})
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
