// Package engine ведёт пакет из очереди до решения: IP → DNS → правила → претензии.
package engine

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	"trassa/internal/claims"
	"trassa/internal/dnsmsg"
	"trassa/internal/ippkt"
	"trassa/internal/rules"
)

// Пределы защищают роутер от устройства домашней сети, которое засыпает его «ответами»:
// всё, что хранится и пишется в журнал, ограничено независимо от содержимого пакетов.
const (
	minTTL         = time.Hour
	maxTTL         = 24 * time.Hour
	maxClaims      = 20000 // претензий в памяти всего
	maxPerAddr     = 16    // претензий на один адрес
	maxChain       = 8     // имён в цепочке CNAME; настоящие цепочки короче
	maxAnswerAddrs = 32    // адресов из одного ответа
	logChanges     = 8     // изменений в одной строке журнала
	recentSize     = 200
	statusRows     = 10
)

// Sink исполняет решения в ядре. nil — режим наблюдения: изменения только журналируются.
type Sink interface {
	// Apply правит динамические списки адресов.
	Apply(changes []claims.Change) error
	// Rebuild строит всё заново по правилам и снимку адресов.
	Rebuild(cfg *rules.Config, entries []claims.Entry) error
}

type Stats struct {
	Packets     uint64 // пакетов из очереди
	Answers     uint64 // DNS-ответов с адресами
	Claimed     uint64 // из них подошло под правило
	Changes     uint64 // изменений списков
	NotDNS      uint64 // не UDP с порта 53
	Malformed   uint64 // DNS не разобрался
	Skipped     uint64 // запрос, ошибка, усечённый ответ, ответ без адресов
	BadName     uint64 // запрошенное имя не похоже на доменное
	Dropped     uint64 // не учтено: память заполнена
	ApplyErrors uint64
}

type observation struct {
	at     time.Time
	client netip.Addr
	name   string
	line   int // 0 — сработал default
	action rules.Action
}

type Engine struct {
	mu      sync.Mutex
	cfg     *rules.Config
	store   *claims.Store
	sink    Sink
	logf    func(format string, args ...any)
	started time.Time
	stats   Stats
	recent  []observation
	exits   map[string]string // выход → имя живого интерфейса; nil — сведений нет
}

func New(cfg *rules.Config, sink Sink, logf func(format string, args ...any), now time.Time) *Engine {
	store := claims.New(cfg, minTTL)
	store.SetLimits(maxClaims, maxPerAddr)
	return &Engine{cfg: cfg, store: store, sink: sink, logf: logf, started: now}
}

func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.snapshot()
}

func (e *Engine) snapshot() Stats {
	s := e.stats
	s.Dropped = e.store.Dropped()
	return s
}

// HandlePacket учитывает один пакет из очереди. raw начинается с заголовка IP.
func (e *Engine) HandlePacket(now time.Time, raw []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.Packets++
	u, err := ippkt.ParseUDP(raw)
	if err != nil || u.SrcPort != 53 {
		e.stats.NotDNS++
		return
	}
	m, err := dnsmsg.Parse(u.Payload)
	if err != nil {
		e.stats.Malformed++
		return
	}
	if !m.Response || m.RCode != 0 || m.Truncated {
		e.stats.Skipped++
		return
	}
	wire, addrs, ttl := m.Resolve()
	if len(addrs) == 0 {
		e.stats.Skipped++
		return
	}
	if len(wire) > maxChain {
		wire = wire[:maxChain]
	}
	if len(addrs) > maxAnswerAddrs {
		addrs = addrs[:maxAnswerAddrs]
	}
	// Имена из пакета приводятся так же, как имена в правилах; что не приводится — не доменное имя.
	names := make([]string, 0, len(wire))
	for i, w := range wire {
		n, err := rules.NormalizeName(w)
		if err != nil {
			if i == 0 {
				e.stats.BadName++
				return
			}
			continue
		}
		names = append(names, n)
	}
	e.stats.Answers++
	d := e.cfg.MatchChain(names)
	o := observation{at: now, client: u.Dst, name: names[0], action: d.Action}
	if d.Rule != nil {
		o.line = d.Rule.Line
	}
	e.remember(o)
	if d.Rule == nil {
		return
	}
	e.stats.Claimed++
	life := time.Duration(ttl) * time.Second
	if life > maxTTL {
		life = maxTTL
	}
	e.apply(e.store.Observe(now, names, addrs, life), fmt.Sprintf("%s спросил %s", u.Dst, names[0]))
}

// Tick снимает претензии с истёкшим сроком.
func (e *Engine) Tick(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.apply(e.store.Expire(now), "срок истёк")
}

// Reload переводит демон на новые правила, не теряя накопленных наблюдений.
// Списки строятся заново целиком: при смене правил номера пар «выход + режим» сдвигаются.
func (e *Engine) Reload(cfg *rules.Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
	e.note(e.store.SetConfig(cfg), "правила изменены")
	e.rebuild()
}

// Resync строит всё заново по текущим правилам и памяти: при старте и после того,
// как прошивка стёрла правила.
func (e *Engine) Resync() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rebuild()
}

func (e *Engine) rebuild() error {
	if e.sink == nil {
		return nil
	}
	err := e.sink.Rebuild(e.cfg, e.store.Entries())
	if err != nil {
		e.stats.ApplyErrors++
		e.logf("не удалось построить списки и маршруты: %v", err)
	}
	return err
}

// Config возвращает действующие правила.
func (e *Engine) Config() *rules.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// SaveState записывает накопленные претензии, чтобы пережить перезапуск.
func (e *Engine) SaveState(w io.Writer) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.store.Save(w)
}

// LoadState читает претензии, записанные SaveState. Списки после этого строит Resync.
func (e *Engine) LoadState(r io.Reader, now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.store.Load(r, now)
}

// SetExits сообщает, через какой интерфейс сейчас идёт каждый выход (пусто — живых нет).
func (e *Engine) SetExits(active map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.exits = active
}

// note записывает изменения в журнал и счётчики.
func (e *Engine) note(changes []claims.Change, why string) {
	if len(changes) == 0 {
		return
	}
	e.stats.Changes += uint64(len(changes))
	shown := changes
	if len(shown) > logChanges {
		shown = shown[:logChanges]
	}
	parts := make([]string, len(shown), len(shown)+1)
	for i, c := range shown {
		parts[i] = fmt.Sprintf("%s %s → %s", c.Addr, show(c.Old), show(c.New))
	}
	if more := len(changes) - len(shown); more > 0 {
		parts = append(parts, fmt.Sprintf("… ещё %d", more))
	}
	e.logf("%s: %s", why, strings.Join(parts, "; "))
}

func (e *Engine) apply(changes []claims.Change, why string) {
	e.note(changes, why)
	if len(changes) == 0 || e.sink == nil {
		return
	}
	if err := e.sink.Apply(changes); err != nil {
		e.stats.ApplyErrors++
		e.logf("не удалось применить изменения: %v", err)
	}
}

// exitLine описывает нынешнее состояние выхода действия; пусто, если сказать нечего.
func (e *Engine) exitLine(a rules.Action) string {
	if a.Exit == rules.Direct || e.exits == nil {
		return ""
	}
	if dev := e.exits[a.Exit]; dev != "" {
		return fmt.Sprintf("выход %s: сейчас через %s\n", a.Exit, dev)
	}
	if a.Strict {
		return fmt.Sprintf("выход %s: все туннели недоступны — трафик блокируется (strict)\n", a.Exit)
	}
	return fmt.Sprintf("выход %s: все туннели недоступны — трафик идёт напрямую\n", a.Exit)
}

func show(a *rules.Action) string {
	if a == nil {
		return "-"
	}
	return a.String()
}

func (e *Engine) remember(o observation) {
	if len(e.recent) == recentSize {
		e.recent = append(e.recent[:0], e.recent[1:]...)
	}
	e.recent = append(e.recent, o)
}

func (e *Engine) lineOf(index int) int {
	if index < len(e.cfg.Rules) {
		return e.cfg.Rules[index].Line
	}
	return e.cfg.DefaultLine
}

// Why объясняет, куда пойдёт имя или адрес, и показывает, что о нём известно из DNS.
func (e *Engine) Why(subject string, now time.Time) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	subj, d, err := e.cfg.MatchSubject(subject)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s → %s\n", subj, d.Action)
	if d.Rule != nil {
		fmt.Fprintf(&b, "правило, строка %d: %s\n", d.Rule.Line, d.Rule.Text)
	} else {
		fmt.Fprintf(&b, "ни одно правило не подошло, действует default (строка %d)\n", e.cfg.DefaultLine)
	}
	b.WriteString(e.exitLine(d.Action))
	if addr, err := netip.ParseAddr(subj); err == nil {
		cs := e.store.Claims(addr)
		if len(cs) == 0 {
			b.WriteString("в DNS-ответах этот адрес не встречался\n")
			return b.String(), nil
		}
		for _, c := range cs {
			fmt.Fprintf(&b, "претензия: %s → %s (строка %d, ещё %s)\n",
				strings.Join(c.Names, " → "), c.Action, e.lineOf(c.Index), ago(c.Expires.Sub(now)))
		}
		if eff := e.store.Effective(addr); eff != nil {
			fmt.Fprintf(&b, "в динамическом списке: %s\n", *eff)
		} else {
			b.WriteString("в динамическом списке нет: адрес входит в подсеть более раннего правила\n")
		}
		return b.String(), nil
	}
	addrs := e.store.AddrsOf(subj)
	fmt.Fprintf(&b, "адресов по этому имени в памяти: %d", len(addrs))
	for i, a := range addrs {
		if i == 8 {
			b.WriteString(", …")
			break
		}
		if i == 0 {
			b.WriteString(": ")
		} else {
			b.WriteString(", ")
		}
		b.WriteString(a.String())
	}
	b.WriteString("\n")
	for i := len(e.recent) - 1; i >= 0; i-- {
		if o := e.recent[i]; o.name == subj {
			fmt.Fprintf(&b, "последний DNS-ответ: %s назад, устройство %s\n", ago(now.Sub(o.at)), o.client)
			return b.String(), nil
		}
	}
	b.WriteString("DNS-ответов для этого имени ещё не было\n")
	return b.String(), nil
}

// Status — краткое состояние демона для человека.
func (e *Engine) Status(now time.Time) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var b strings.Builder
	if e.sink == nil {
		b.WriteString("trassa: режим наблюдения — списки адресов и маршруты не меняются\n")
	} else {
		b.WriteString("trassa: режим маршрутизации\n")
	}
	s := e.snapshot()
	fmt.Fprintf(&b, "работает %s, правил: %d, адресов в памяти: %d, претензий: %d\n",
		uptime(now.Sub(e.started)), len(e.cfg.Rules), e.store.Len(), e.store.Total())
	fmt.Fprintf(&b, "пакетов: %d, ответов с адресами: %d, под правила: %d, изменений: %d\n", s.Packets, s.Answers, s.Claimed, s.Changes)
	fmt.Fprintf(&b, "пропущено — не DNS: %d, повреждённых: %d, прочих: %d, неверных имён: %d, сверх предела: %d; ошибок применения: %d\n",
		s.NotDNS, s.Malformed, s.Skipped, s.BadName, s.Dropped, s.ApplyErrors)
	if e.exits != nil {
		parts := make([]string, 0, len(e.cfg.Exits))
		for _, x := range e.cfg.Exits {
			dev := e.exits[x.Name]
			if dev == "" {
				dev = "нет живых туннелей"
			}
			parts = append(parts, x.Name+" → "+dev)
		}
		fmt.Fprintf(&b, "выходы: %s\n", strings.Join(parts, "; "))
	}
	if len(e.recent) == 0 {
		b.WriteString("наблюдений пока нет\n")
		return b.String()
	}
	b.WriteString("последние наблюдения:\n")
	from := max(0, len(e.recent)-statusRows)
	for _, o := range e.recent[from:] {
		where := "default"
		if o.line != 0 {
			where = fmt.Sprintf("строка %d", o.line)
		}
		fmt.Fprintf(&b, "  %s %s %s → %s (%s)\n", o.at.Format("15:04:05"), o.client, o.name, o.action, where)
	}
	return b.String()
}

// ago пишет промежуток коротко: «45 с», «10 мин», «3 ч».
func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d с", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	}
	return fmt.Sprintf("%d ч", int(d.Hours()))
}

func uptime(d time.Duration) string {
	h, m := int(d.Hours()), int(d.Minutes())%60
	if h == 0 {
		return fmt.Sprintf("%dм", m)
	}
	return fmt.Sprintf("%dч%02dм", h, m)
}
