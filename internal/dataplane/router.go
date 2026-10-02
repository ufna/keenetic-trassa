package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"trassa/internal/claims"
	"trassa/internal/rules"
)

const (
	// Rebuild и Apply вызываются под замком пути пакета: они должны уложиться в предел
	// простоя цикла приёма (5 с), иначе демон сочтёт себя зависшим.
	buildTimeout = 4 * time.Second
	applyTimeout = 2 * time.Second
)

// ErrMissing — правил маршрутизации нет на месте: прошивка переписала таблицу.
var ErrMissing = errors.New("правила маршрутизации trassa отсутствуют")

// Router держит в ядре списки адресов, цепочку меток, правила и таблицы маршрутов.
type Router struct {
	run    InputRunner
	lan    string
	source netip.Addr // если задан — маршрутизируются только пакеты от этого адреса

	mu     sync.Mutex
	layout *Layout
	active map[string]string // выход → системное имя живого интерфейса; пусто — живых нет
}

func NewRouter(run InputRunner, lan string, source netip.Addr) *Router {
	return &Router{run: run, lan: lan, source: source, active: map[string]string{}}
}

// jump — условие прыжка в цепочку: аргументы для -C/-A и строка, которой его печатает «-S».
func (r *Router) jump() (args []string, printed string) {
	if r.source.IsValid() {
		args = append(args, "-s", r.source.String())
		printed = "-s " + r.source.String() + "/32 "
	}
	args = append(args, "-i", r.lan, "-j", routeChain)
	return args, "-A PREROUTING " + printed + "-i " + r.lan + " -j " + routeChain
}

// Rebuild строит всё заново по правилам cfg и снимку entries и убирает оставшееся от прежней раскладки.
func (r *Router) Rebuild(cfg *rules.Config, entries []claims.Entry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	// Пока построение не завершилось успехом, раскладки нет: Apply по прежней раскладке
	// положил бы адрес в список чужого выхода.
	r.layout = nil
	l, err := NewLayout(cfg)
	if err != nil {
		return err
	}
	if _, err := r.run.RunInput(ctx, l.setsScript(entries), "ipset", "restore"); err != nil {
		return err
	}
	if _, err := r.run.RunInput(ctx, l.chainScript(), "iptables-restore", "-n"); err != nil {
		return err
	}
	// Сначала правила и маршруты, потом прыжок: метки начинают ставиться, когда для них уже есть путь.
	if err := r.syncRules(ctx, l); err != nil {
		return err
	}
	if err := r.syncRoutes(ctx, l); err != nil {
		return err
	}
	if err := r.syncJump(ctx); err != nil {
		return err
	}
	r.layout = l
	// Лишние списки удаляются последними: до замены цепочки на них ещё ссылались правила.
	names, _ := r.run.Run(ctx, "ipset", "list", "-n")
	for _, name := range strings.Fields(names) {
		if strings.HasPrefix(name, setPrefix) && !l.hasSet(name) {
			r.run.Run(ctx, "ipset", "destroy", name)
		}
	}
	return nil
}

// syncJump оставляет в PREROUTING ровно один прыжок — с нынешним условием, в конце цепочки.
func (r *Router) syncJump(ctx context.Context) error {
	args, printed := r.jump()
	have := false
	out, _ := r.run.Run(ctx, "iptables", mangle("-S", "PREROUTING")...)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasSuffix(line, " -j "+routeChain) {
			continue
		}
		if line == printed {
			have = true
			continue
		}
		// Прыжок с прежним условием (сменился наблюдаемый источник).
		r.run.Run(ctx, "iptables", mangle(append([]string{"-D"}, strings.Fields(line)[1:]...)...)...)
	}
	if have {
		return nil
	}
	if _, err := r.run.Run(ctx, "iptables", mangle(append([]string{"-C", "PREROUTING"}, args...)...)...); err == nil {
		return nil
	}
	// В конец цепочки: прошивка должна успеть поставить свои метки раньше.
	_, err := r.run.Run(ctx, "iptables", mangle(append([]string{"-A", "PREROUTING"}, args...)...)...)
	return err
}

// syncRules добавляет недостающие правила маршрутизации и удаляет свои лишние.
func (r *Router) syncRules(ctx context.Context, l *Layout) error {
	out, err := r.run.Run(ctx, "ip", "rule", "list")
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, s := range l.Slots[1:] {
		want[s.Pref()] = true
		if strings.Contains(out, "fwmark "+s.Mark()+" lookup "+s.Table()) {
			continue
		}
		if _, err := r.run.Run(ctx, "ip", "rule", "add", "fwmark", s.Mark()+"/0xffffffff", "lookup", s.Table(), "pref", s.Pref()); err != nil {
			return err
		}
	}
	for _, own := range ownRules(out) {
		if !want[own.pref] {
			dropRule(ctx, r.run, own)
		}
	}
	return nil
}

// dropRule удаляет своё правило маршрутизации и очищает его таблицу — но только если это
// таблица из диапазона trassa: чужую таблицу не трогаем, что бы ни стояло в правиле.
func dropRule(ctx context.Context, run Runner, own ownRule) {
	run.Run(ctx, "ip", "rule", "del", "pref", own.pref)
	if t, err := strconv.Atoi(own.table); err == nil && t > tableBase && t < tableBase+2*rules.MaxExits+2 {
		run.Run(ctx, "ip", "route", "flush", "table", own.table)
	}
}

type ownRule struct{ pref, table string }

// ownRules находит в выводе «ip rule list» правила с метками trassa.
func ownRules(list string) []ownRule {
	var out []ownRule
	for _, line := range strings.Split(list, "\n") {
		if !strings.Contains(line, markPrefix) {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		out = append(out, ownRule{pref: strings.TrimSuffix(f[0], ":"), table: f[len(f)-1]})
	}
	return out
}

// syncRoutes приводит маршрут в таблице каждой пары к состоянию её выхода.
func (r *Router) syncRoutes(ctx context.Context, l *Layout) error {
	var first error
	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	for _, s := range l.Slots[1:] {
		if s.Strict {
			// Постоянная «чёрная дыра» с низким приоритетом: когда интерфейс туннеля выключают,
			// ядро само удаляет маршрут через него, и без неё таблица на несколько секунд
			// оставалась бы пустой — трафик уходил бы через провайдера.
			_, err := r.run.Run(ctx, "ip", "route", "replace", "blackhole", "default", "table", s.Table(), "metric", "1000")
			note(err)
		}
		var err error
		switch dev := r.active[s.Exit]; {
		case dev != "":
			_, err = r.run.Run(ctx, "ip", "route", "replace", "default", "dev", dev, "table", s.Table())
		case s.Strict:
			// Защита от утечки: без туннеля трафик этой пары никуда не идёт.
			_, err = r.run.Run(ctx, "ip", "route", "replace", "blackhole", "default", "table", s.Table())
		default:
			// Таблица пуста — пакет идёт по основной, то есть через провайдера.
			_, err = r.run.Run(ctx, "ip", "route", "flush", "table", s.Table())
		}
		note(err)
	}
	return first
}

// Apply правит динамические списки. Все изменения — одной командой.
func (r *Router) Apply(changes []claims.Change) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.layout == nil {
		return errors.New("списки адресов ещё не построены")
	}
	var b strings.Builder
	line := func(op string, a rules.Action, addr netip.Addr) error {
		slot, ok := r.layout.Slot(a)
		if !ok {
			return fmt.Errorf("выхода %q нет в построенной раскладке", a.Exit)
		}
		fmt.Fprintf(&b, "%s %s %s -exist\n", op, slot.Set(), addr)
		return nil
	}
	for _, c := range changes {
		if c.Old != nil {
			if err := line("del", *c.Old, c.Addr); err != nil {
				return err
			}
		}
		if c.New != nil {
			if err := line("add", *c.New, c.Addr); err != nil {
				return err
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()
	_, err := r.run.RunInput(ctx, b.String(), "ipset", "restore")
	return err
}

// SetExits запоминает, через какой интерфейс идёт каждый выход, и меняет маршруты.
func (r *Router) SetExits(active map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active = active
	if r.layout == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	return r.syncRoutes(ctx, r.layout)
}

// Reconcile сверяет построенное с ядром. Прошивка переписывает таблицу mangle целиком, поэтому
// отсутствие прыжка означает, что нет и цепочки: возвращается ErrMissing, и вызывающий строит
// всё заново. Правила и маршруты ставятся повторно при каждой сверке: ядро удаляет маршрут,
// когда интерфейс выключают, и узнать об этом иначе неоткуда.
func (r *Router) Reconcile(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.layout == nil {
		return ErrMissing
	}
	args, _ := r.jump()
	if _, err := r.run.Run(ctx, "iptables", mangle(append([]string{"-C", "PREROUTING"}, args...)...)...); err != nil {
		return ErrMissing
	}
	if err := r.syncRules(ctx, r.layout); err != nil {
		return err
	}
	return r.syncRoutes(ctx, r.layout)
}

// Teardown удаляет всё, что trassa построил для маршрутизации, не зная раскладки:
// по именам и меткам. Отсутствие объектов ошибкой не считается.
func Teardown(ctx context.Context, run Runner) {
	out, _ := run.Run(ctx, "iptables", mangle("-S", "PREROUTING")...)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, " -j "+routeChain) {
			run.Run(ctx, "iptables", mangle(append([]string{"-D"}, strings.Fields(line)[1:]...)...)...)
		}
	}
	run.Run(ctx, "iptables", mangle("-F", routeChain)...)
	run.Run(ctx, "iptables", mangle("-X", routeChain)...)
	list, _ := run.Run(ctx, "ip", "rule", "list")
	for _, own := range ownRules(list) {
		dropRule(ctx, run, own)
	}
	names, _ := run.Run(ctx, "ipset", "list", "-n")
	for _, name := range strings.Fields(names) {
		if strings.HasPrefix(name, setPrefix) {
			run.Run(ctx, "ipset", "destroy", name)
		}
	}
}
