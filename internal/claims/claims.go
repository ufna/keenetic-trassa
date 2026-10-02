// Package claims помнит, какие правила претендуют на какой адрес, и вычисляет,
// в каком динамическом списке адресов ядра адрес должен находиться.
package claims

import (
	"net/netip"
	"sort"
	"time"

	"trassa/internal/rules"
)

// Claim — претензия правила на адрес, возникшая из DNS-ответа.
type Claim struct {
	Names   []string // запрошенное имя и его CNAME-цели
	Index   int      // номер правила; меньше — старше
	Action  rules.Action
	Expires time.Time
}

// Change — изменение динамических списков. nil означает «адреса нет ни в одном списке».
type Change struct {
	Addr     netip.Addr
	Old, New *rules.Action
}

// Store не потокобезопасен: вызывающий обеспечивает последовательный доступ.
type Store struct {
	cfg    *rules.Config
	minTTL time.Duration
	byAddr map[netip.Addr][]Claim
}

func New(cfg *rules.Config, minTTL time.Duration) *Store {
	return &Store{cfg: cfg, minTTL: minTTL, byAddr: map[netip.Addr][]Claim{}}
}

func (s *Store) Len() int { return len(s.byAddr) }

// Claims возвращает копию претензий на адрес: хранилище переписывает свои срезы на месте.
func (s *Store) Claims(addr netip.Addr) []Claim { return append([]Claim(nil), s.byAddr[addr]...) }

// AddrsOf возвращает адреса, на которые претендует запрошенное имя name, по возрастанию.
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

// Effective возвращает действие, с которым адрес должен быть в динамическом списке, или nil.
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
	// Подсеть более раннего правила старше: адрес обслуживает её статический список.
	if st := s.cfg.MatchAddr(addr); st.Rule != nil && st.Index < best.Index {
		return nil
	}
	a := best.Action
	return &a
}

// Observe учитывает DNS-ответ: names — запрошенное имя и его CNAME-цели, addrs — адреса из ответа.
func (s *Store) Observe(now time.Time, names []string, addrs []netip.Addr, ttl time.Duration) []Change {
	d := s.cfg.MatchChain(names)
	if d.Rule == nil {
		return nil
	}
	if ttl < s.minTTL {
		ttl = s.minTTL
	}
	// Копия: срез вызывающего хранится долго и не должен меняться у нас под руками.
	names = append([]string(nil), names...)
	c := Claim{Names: names, Index: d.Index, Action: d.Action, Expires: now.Add(ttl)}
	var out []Change
	for _, a := range addrs {
		old := s.Effective(a)
		s.byAddr[a] = upsert(s.byAddr[a], c)
		out = appendChange(out, a, old, s.Effective(a))
	}
	return out
}

// Expire удаляет претензии, срок которых вышел к моменту now.
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
		s.put(a, live)
		out = appendChange(out, a, old, s.Effective(a))
	}
	sortChanges(out)
	return out
}

// SetConfig переводит хранилище на новые правила: каждая претензия заново решается по своей цепочке имён.
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

// upsert заменяет претензию того же запрошенного имени или добавляет новую.
// Срок при замене не укорачивается: новый ответ может только продлить претензию.
func upsert(cs []Claim, c Claim) []Claim {
	for i := range cs {
		if cs[i].Names[0] == c.Names[0] {
			if cs[i].Expires.After(c.Expires) {
				c.Expires = cs[i].Expires
			}
			cs[i] = c
			return cs
		}
	}
	return append(cs, c)
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
