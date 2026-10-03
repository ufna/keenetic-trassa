package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"trassa/internal/claims"
	"trassa/internal/rules"
)

const (
	// Rebuild and Apply are called under the packet path lock: they must fit within the
	// receive loop's idle limit (5 s), or the daemon will consider itself hung.
	buildTimeout = 4 * time.Second
	applyTimeout = 2 * time.Second
)

// ErrMissing means the routing rules are gone: the firmware rewrote the table.
var ErrMissing = errors.New("trassa routing rules are missing")

// ErrViews means the device views changed: the source sets cannot just be refilled, a rebuild is needed.
var ErrViews = errors.New("device views changed: the address sets must be rebuilt")

// Router maintains the address sets, mark chain, rules and routing tables in the kernel.
type Router struct {
	run    InputRunner
	lan    string
	source netip.Addr // if set, only packets from this address are routed

	mu     sync.Mutex
	layout *Layout
	active map[string]string // exit → system name of the live interface; empty means none is live
}

func NewRouter(run InputRunner, lan string, source netip.Addr) *Router {
	return &Router{run: run, lan: lan, source: source, active: map[string]string{}}
}

// jump is the condition of the jump into the chain: arguments for -C/-A and the line "-S" prints for it.
func (r *Router) jump() (args []string, printed string) {
	if r.source.IsValid() {
		args = append(args, "-s", r.source.String())
		printed = "-s " + r.source.String() + "/32 "
	}
	args = append(args, "-i", r.lan, "-j", routeChain)
	return args, "-A PREROUTING " + printed + "-i " + r.lan + " -j " + routeChain
}

// Rebuild builds everything from scratch from the cfg rules and the entries snapshot, and removes leftovers of the previous layout.
func (r *Router) Rebuild(cfg *rules.Config, sources map[rules.View][]netip.Addr, entries []claims.Entry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	// Until the build succeeds there is no layout: Apply with the previous layout
	// would put an address into another exit's set.
	r.layout = nil
	l, err := NewLayout(cfg, viewsOf(sources))
	if err != nil {
		return err
	}
	if _, err := r.run.RunInput(ctx, l.setsScript(sources, entries), "ipset", "restore"); err != nil {
		return err
	}
	// A path exists before anything points at it: routes, then the rules leading to them, then
	// the chain setting the new marks. Rules of the previous layout go only after the chain
	// stopped setting its marks, and the jump comes last.
	if err := r.syncRoutes(ctx, l); err != nil {
		return err
	}
	seen, err := r.addRules(ctx, l)
	if err != nil {
		return err
	}
	if _, err := r.run.RunInput(ctx, l.chainScript(), "iptables-restore", "-n"); err != nil {
		return err
	}
	r.pruneRules(ctx, l, seen)
	// Chains of views that are gone: the new main chain no longer leads to them.
	r.dropViewChains(ctx, l)
	if err := r.syncJump(ctx); err != nil {
		return err
	}
	r.layout = l
	// Stale sets are removed last: until the chain was replaced, rules still referenced them.
	names, _ := r.run.Run(ctx, "ipset", "list", "-n")
	for _, name := range strings.Fields(names) {
		if strings.HasPrefix(name, setPrefix) && !l.hasSet(name) {
			r.run.Run(ctx, "ipset", "destroy", name)
		}
	}
	return nil
}

// syncJump leaves exactly one jump in PREROUTING, with the current condition, at the end of the chain.
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
		// A jump with an old condition (the observed source changed).
		r.run.Run(ctx, "iptables", mangle(append([]string{"-D"}, strings.Fields(line)[1:]...)...)...)
	}
	if have {
		return nil
	}
	if _, err := r.run.Run(ctx, "iptables", mangle(append([]string{"-C", "PREROUTING"}, args...)...)...); err == nil {
		return nil
	}
	// At the end of the chain: the firmware must get to set its marks first.
	_, err := r.run.Run(ctx, "iptables", mangle(append([]string{"-A", "PREROUTING"}, args...)...)...)
	return err
}

// addRules adds the routing rules the layout needs and returns the rules list it saw.
func (r *Router) addRules(ctx context.Context, l *Layout) (string, error) {
	out, err := r.run.Run(ctx, "ip", "rule", "list")
	if err != nil {
		return "", err
	}
	have := map[string]bool{}
	for _, o := range ownRules(out) {
		have[o.key()] = true
	}
	for _, w := range l.wantedRules() {
		if have[w.key()] {
			continue
		}
		mark := w.mark
		if !strings.Contains(mark, "/") {
			mark += "/0xffffffff"
		}
		if _, err := r.run.Run(ctx, "ip", "rule", "add", "fwmark", mark, "lookup", w.table, "pref", w.pref); err != nil {
			return "", err
		}
	}
	return out, nil
}

// pruneRules removes our own rules (from the list seen by addRules) that the layout does not need.
func (r *Router) pruneRules(ctx context.Context, l *Layout, seen string) {
	want, keep := map[string]bool{}, map[string]bool{}
	for _, w := range l.wantedRules() {
		want[w.key()], keep[w.table] = true, true
	}
	for _, o := range ownRules(seen) {
		if !want[o.key()] {
			dropRule(ctx, r.run, o, keep)
		}
	}
}

// syncRules adds the rules the layout needs, then removes our own rules it does not need.
func (r *Router) syncRules(ctx context.Context, l *Layout) error {
	seen, err := r.addRules(ctx, l)
	if err != nil {
		return err
	}
	r.pruneRules(ctx, l, seen)
	return nil
}

// dropRule removes one of our routing rules by its full condition, and clears its table unless
// a wanted rule still uses it.
func dropRule(ctx context.Context, run Runner, o ownRule, keep map[string]bool) {
	run.Run(ctx, "ip", "rule", "del", "pref", o.pref, "fwmark", o.mark, "lookup", o.table)
	if t, err := strconv.Atoi(o.table); err == nil && t > tableBase && t < tableBase+60 && !keep[o.table] {
		run.Run(ctx, "ip", "route", "flush", "table", o.table)
	}
}

// ownRule is a routing rule with a trassa mark, as "ip rule list" prints it.
type ownRule struct{ pref, mark, table string }

func (o ownRule) key() string { return o.pref + " " + o.mark + " " + o.table }

// wantedRules are the routing rules a layout needs: direct back to the main table; one rule per
// tunnel slot; a slot of this layout whose table has no route (a normal exit with no live
// tunnel) falls through to the main table, i.e. goes direct; a mark of any other layout goes
// nowhere. A strict slot never falls through: its table keeps a permanent blackhole.
func (l *Layout) wantedRules() []ownRule {
	out := []ownRule{{directPref, fmt.Sprintf("0x%x", markBase), "main"}}
	for _, s := range l.Slots[1:] {
		out = append(out, ownRule{s.Pref(), s.Mark(), s.Table()})
	}
	genMask := uint32(0xffffffff) &^ (1<<genShift - 1)
	return append(out,
		ownRule{fallPref, fmt.Sprintf("0x%x/0x%x", markBase|l.gen<<genShift, genMask), "main"},
		ownRule{stalePref, fmt.Sprintf("0x%x/%s", markBase, markMask), staleTable})
}

// ownRules finds rules with trassa marks in "ip rule list" output.
func ownRules(list string) []ownRule {
	var out []ownRule
	for _, line := range strings.Split(list, "\n") {
		f := strings.Fields(line)
		var o ownRule
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "fwmark":
				o.mark = f[i+1]
			case "lookup":
				o.table = f[i+1]
			}
		}
		if len(f) == 0 || !strings.HasPrefix(o.mark, "0x5452") {
			continue
		}
		o.pref = strings.TrimSuffix(f[0], ":")
		out = append(out, o)
	}
	return out
}

// syncRoutes brings the route in each slot's table in line with the state of its exit.
func (r *Router) syncRoutes(ctx context.Context, l *Layout) error {
	var first error
	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	// Marks of another layout go nowhere.
	_, err := r.run.Run(ctx, "ip", "route", "replace", "blackhole", "default", "table", staleTable)
	note(err)
	for _, s := range l.Slots[1:] {
		if s.Strict {
			// A permanent low-priority blackhole: when the tunnel interface goes down, the kernel
			// removes the route through it, and without the blackhole the table would be empty
			// for a few seconds, so traffic would leak through the ISP.
			_, err := r.run.Run(ctx, "ip", "route", "replace", "blackhole", "default", "table", s.Table(), "metric", "1000")
			note(err)
		}
		var err error
		switch dev := r.active[s.Exit]; {
		case dev != "":
			_, err = r.run.Run(ctx, "ip", "route", "replace", "default", "dev", dev, "table", s.Table())
		case s.Strict:
			// Leak protection: without the tunnel, this slot's traffic goes nowhere.
			_, err = r.run.Run(ctx, "ip", "route", "replace", "blackhole", "default", "table", s.Table())
		default:
			// The table is empty, so the packet follows the main table, i.e. through the ISP.
			_, err = r.run.Run(ctx, "ip", "route", "flush", "table", s.Table())
		}
		note(err)
	}
	return first
}

// Apply updates the dynamic sets. All changes go in a single command.
func (r *Router) Apply(changes []claims.Change) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.layout == nil {
		return errors.New("address sets are not built yet")
	}
	var b strings.Builder
	line := func(op string, v rules.View, a rules.Action, addr netip.Addr) error {
		if !r.layout.hasView(v) {
			return fmt.Errorf("device view %d is not in the built layout", v)
		}
		slot, ok := r.layout.Slot(a)
		if !ok {
			return fmt.Errorf("exit %q is not in the built layout", a.Exit)
		}
		fmt.Fprintf(&b, "%s %s %s -exist\n", op, dynSet(v, slot), addr)
		return nil
	}
	for _, c := range changes {
		if c.Old != nil {
			if err := line("del", c.View, *c.Old, c.Addr); err != nil {
				return err
			}
		}
		if c.New != nil {
			if err := line("add", c.View, *c.New, c.Addr); err != nil {
				return err
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()
	_, err := r.run.RunInput(ctx, b.String(), "ipset", "restore")
	return err
}

// SetExits records which interface each exit goes through and updates the routes.
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

// Reconcile checks what was built against the kernel. The firmware rewrites the mangle table
// as a whole, so a missing jump means the chain is gone too: ErrMissing is returned and the
// caller rebuilds everything. Rules and routes are reapplied on every reconcile: the kernel
// removes a route when its interface goes down, and there is no other way to learn about it.
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
	if err := r.syncRoutes(ctx, r.layout); err != nil {
		return err
	}
	return r.syncRules(ctx, r.layout)
}

// Teardown removes everything trassa built for routing without knowing the layout:
// by names and marks. Missing objects are not an error.
func Teardown(ctx context.Context, run Runner) {
	out, _ := run.Run(ctx, "iptables", mangle("-S", "PREROUTING")...)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, " -j "+routeChain) {
			run.Run(ctx, "iptables", mangle(append([]string{"-D"}, strings.Fields(line)[1:]...)...)...)
		}
	}
	run.Run(ctx, "iptables", mangle("-F", routeChain)...)
	// View chains go after the main chain stopped leading to them and before it is deleted.
	for _, name := range viewChains(ctx, run) {
		run.Run(ctx, "iptables", mangle("-F", name)...)
		run.Run(ctx, "iptables", mangle("-X", name)...)
	}
	run.Run(ctx, "iptables", mangle("-X", routeChain)...)
	list, _ := run.Run(ctx, "ip", "rule", "list")
	for _, own := range ownRules(list) {
		dropRule(ctx, run, own, nil)
	}
	names, _ := run.Run(ctx, "ipset", "list", "-n")
	for _, name := range strings.Fields(names) {
		if strings.HasPrefix(name, setPrefix) {
			run.Run(ctx, "ipset", "destroy", name)
		}
	}
}

// viewsOf returns the views that have source addresses.
func viewsOf(sources map[rules.View][]netip.Addr) []rules.View {
	var out []rules.View
	for v, addrs := range sources {
		if len(addrs) > 0 {
			out = append(out, v)
		}
	}
	return out
}

// viewChains lists trassa's view chains in the mangle table.
func viewChains(ctx context.Context, run Runner) []string {
	out, _ := run.Run(ctx, "iptables-save", "-t", "mangle")
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, ":"+viewChainPrefix) {
			continue
		}
		if f := strings.Fields(line[1:]); len(f) > 0 {
			names = append(names, f[0])
		}
	}
	return names
}

// dropViewChains removes the view chains the layout does not have.
func (r *Router) dropViewChains(ctx context.Context, l *Layout) {
	for _, name := range viewChains(ctx, r.run) {
		if !l.hasChain(name) {
			r.run.Run(ctx, "iptables", mangle("-F", name)...)
			r.run.Run(ctx, "iptables", mangle("-X", name)...)
		}
	}
}

// SetSources refills the views' source sets after a device changed its address. If the views
// themselves changed, it changes nothing and returns ErrViews: the caller rebuilds.
func (r *Router) SetSources(sources map[rules.View][]netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.layout == nil {
		return errors.New("address sets are not built yet")
	}
	if !slices.Equal(deviceViews(viewsOf(sources)), r.layout.Views) {
		return ErrViews
	}
	if len(r.layout.Views) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()
	_, err := r.run.RunInput(ctx, r.layout.sourcesScript(sources), "ipset", "restore")
	return err
}
