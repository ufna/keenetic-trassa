// Package claims помнит, какие правила претендуют на какой адрес, и вычисляет,
// в каком динамическом списке адресов ядра адрес должен находиться.
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

	total   int    // претензий всего, по всем адресам
	limit   int    // предел total; 0 — без предела
	perAddr int    // предел претензий на один адрес; 0 — без предела
	dropped uint64 // претензий, не принятых из-за пределов
}

// SetLimits ограничивает память хранилища: всего претензий и претензий на один адрес.
// Устройство в домашней сети может прислать сколько угодно «ответов», и без пределов
// хранилище росло бы вместе с ними.
func (s *Store) SetLimits(total, perAddr int) { s.limit, s.perAddr = total, perAddr }

// Total возвращает число претензий по всем адресам.
func (s *Store) Total() int { return s.total }

// Dropped возвращает число претензий, не принятых из-за пределов.
func (s *Store) Dropped() uint64 { return s.dropped }

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
		if !usable(a) {
			continue
		}
		old := s.Effective(a)
		s.add(a, c)
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
		s.total -= len(cs) - len(live)
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

// add заменяет претензию того же запрошенного имени или добавляет новую, соблюдая пределы.
// Срок при замене не укорачивается: новый ответ может только продлить претензию.
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
		// Адрес заполнен: новая претензия вытесняет худшую, только если сама старше её.
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

// usable сообщает, что адрес может быть назначением обычного трафика. Нулевой адрес (им
// отвечают блокирующие DNS-серверы) список адресов ядра не принимает вовсе, и одна такая
// запись срывала бы всё перестроение списков; остальные служебные адреса маршрутизировать незачем.
func usable(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	return b[0] != 0 && b[0] != 127 && b[0] < 224 && !(b[0] == 169 && b[1] == 254)
}

// Entry — адрес и действие, с которым он должен быть в динамическом списке.
type Entry struct {
	Addr   netip.Addr
	Action rules.Action
}

// Entries возвращает всё, что должно быть в динамических списках, по возрастанию адреса.
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

// maxKeep — на сколько вперёд может смотреть срок претензии, прочитанной из файла.
const maxKeep = 24 * time.Hour

type saved struct {
	Addr    string   `json:"a"`
	Names   []string `json:"n"`
	Expires int64    `json:"e"`
}

// Save записывает претензии, по одной в строке. Решения не сохраняются: при чтении
// каждая претензия решается заново по тем правилам, которые действуют тогда.
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

// Load читает претензии, записанные Save, и возвращает число принятых.
func (s *Store) Load(r io.Reader, now time.Time) int {
	n := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<10)
	for sc.Scan() {
		var v saved
		if json.Unmarshal(sc.Bytes(), &v) != nil || len(v.Names) == 0 {
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
