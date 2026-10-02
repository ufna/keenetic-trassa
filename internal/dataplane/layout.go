package dataplane

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"trassa/internal/claims"
	"trassa/internal/rules"
)

const (
	markBase   = 0x54520000 // метки trassa: markBase + номер пары
	markMask   = "0xffff0000"
	markPrefix = "fwmark 0x5452" // так метки trassa выглядят в выводе ip rule
	tableBase  = 540
	prefBase   = 200
	routeChain = "TRASSA"
	setPrefix  = "trassa_"
)

// localNets — назначения, которые не уходят в туннель по default: частные и служебные сети.
var localNets = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3",
}

// Slot — пара «выход + режим». Номер 0 — direct.
type Slot struct {
	Index  int
	Exit   string
	Strict bool
}

func (s Slot) Mark() string  { return fmt.Sprintf("0x%x", markBase+s.Index) }
func (s Slot) Table() string { return strconv.Itoa(tableBase + s.Index) }
func (s Slot) Pref() string  { return strconv.Itoa(prefBase + s.Index) }
func (s Slot) Set() string   { return setPrefix + "d" + strconv.Itoa(s.Index) }

type staticSet struct {
	Name string
	Nets []netip.Prefix
	Slot Slot
}

// Layout — что должно существовать в ядре для данных правил.
type Layout struct {
	Slots   []Slot      // Slots[0] — direct; дальше по два на выход: обычный и strict
	Static  []staticSet // по одному на правило с адресами, в порядке правил
	Default Slot
	exits   map[string]int
}

func NewLayout(cfg *rules.Config) (*Layout, error) {
	if len(cfg.Exits) > rules.MaxExits {
		return nil, fmt.Errorf("выходов %d, поддерживается не больше %d", len(cfg.Exits), rules.MaxExits)
	}
	l := &Layout{Slots: []Slot{{Exit: rules.Direct}}, exits: map[string]int{}}
	for i, e := range cfg.Exits {
		l.exits[e.Name] = i
		l.Slots = append(l.Slots, Slot{Index: 1 + 2*i, Exit: e.Name}, Slot{Index: 2 + 2*i, Exit: e.Name, Strict: true})
	}
	for i, r := range cfg.Rules {
		if len(r.Nets) > 0 {
			slot, ok := l.Slot(r.Action)
			if !ok {
				return nil, fmt.Errorf("строка %d: выход %q не объявлен", r.Line, r.Action.Exit)
			}
			l.Static = append(l.Static, staticSet{Name: setPrefix + "s" + strconv.Itoa(i), Nets: r.Nets, Slot: slot})
		}
	}
	def, ok := l.Slot(cfg.Default)
	if !ok {
		return nil, fmt.Errorf("default: выход %q не объявлен", cfg.Default.Exit)
	}
	l.Default = def
	return l, nil
}

// Slot возвращает пару для действия; false — такого выхода в раскладке нет.
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

// setsScript — ввод для «ipset restore»: все списки создаются, очищаются и наполняются заново.
func (l *Layout) setsScript(entries []claims.Entry) string {
	var b strings.Builder
	for _, s := range l.Slots {
		fmt.Fprintf(&b, "create %s hash:ip -exist\nflush %s\n", s.Set(), s.Set())
	}
	for _, s := range l.Static {
		fmt.Fprintf(&b, "create %s hash:net -exist\nflush %s\n", s.Name, s.Name)
		for _, n := range s.Nets {
			fmt.Fprintf(&b, "add %s %s -exist\n", s.Name, n)
		}
	}
	for _, e := range entries {
		// Снимок сделан по тем же правилам, что и раскладка; запись с неизвестным выходом пропускается.
		if slot, ok := l.Slot(e.Action); ok {
			fmt.Fprintf(&b, "add %s %s -exist\n", slot.Set(), e.Addr)
		}
	}
	return b.String()
}

// chainScript — ввод для «iptables-restore -n»: объявление цепочки очищает её, затем идут правила.
func (l *Layout) chainScript() string {
	var b strings.Builder
	b.WriteString("*mangle\n:" + routeChain + " - [0:0]\n")
	rule := func(format string, args ...any) {
		fmt.Fprintf(&b, "-A "+routeChain+" "+format+"\n", args...)
	}
	// Пакет уже помечен прошивкой — не наш.
	rule("-m mark ! --mark 0x0 -j RETURN")
	// Установленное соединение идёт прежним путём.
	rule("-m connmark --mark 0x%x/%s -j CONNMARK --restore-mark", markBase, markMask)
	rule("-m mark ! --mark 0x0 -j RETURN")
	// Метку получает только первый пакет соединения. Уже идущее соединение без метки не
	// перекидывается на другой путь посреди передачи, а ответы на входящие соединения
	// не принимаются за исходящие.
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
