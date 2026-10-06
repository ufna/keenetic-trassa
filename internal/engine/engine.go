// Package engine carries a packet from the queue to a decision: IP → DNS → rules → claims.
package engine

import (
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"trassa/internal/claims"
	"trassa/internal/ctl"
	"trassa/internal/devices"
	"trassa/internal/dnsmsg"
	"trassa/internal/ippkt"
	"trassa/internal/rules"
)

// Limits protect the router from a home-network device that floods it with "answers":
// everything stored or logged is bounded regardless of what the packets contain.
const (
	minTTL         = time.Hour
	maxTTL         = 24 * time.Hour
	maxClaims      = 20000 // claims held in memory in total
	maxPerAddr     = 16    // claims per address
	maxChain       = 8     // names in a CNAME chain; real chains are shorter
	maxAnswerAddrs = 32    // addresses taken from one answer
	logChanges     = 8     // changes shown in one log line
	recentSize     = 500   // DNS answers kept for the web page
	statusRows     = 10
	stateRows      = 30
)

// Sink carries out decisions in the kernel. nil means observe mode: changes are only logged.
type Sink interface {
	// Apply edits the dynamic address sets.
	Apply(changes []claims.Change) error
	// Rebuild builds everything from scratch from the rules, the device views' source addresses
	// and an address snapshot.
	Rebuild(cfg *rules.Config, sources map[rules.View][]netip.Addr, entries []claims.Entry) error
	// SetSources refills the source sets after a device changed its address.
	SetSources(sources map[rules.View][]netip.Addr) error
}

// Stats are the daemon counters; the fields are described in ctl.Stats.
type Stats = ctl.Stats

type observation struct {
	seq    uint64 // arrival number, from 1
	at     time.Time
	client netip.Addr
	device string // the device's name from the firmware, if known
	name   string
	line   int // 0 means the default applied
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
	seq     uint64            // number of the last DNS answer remembered
	exits   map[string]string // exit → name of the live interface; nil means unknown
	dirty   bool              // kernel sets may have drifted from memory: a rebuild is needed
	hosts   []devices.Host    // the firmware's device list, as last read
	devs    devices.Map       // where the device lists' devices are
	built   bool              // the kernel was built at least once: until then devices only update memory
}

func New(cfg *rules.Config, sink Sink, logf func(format string, args ...any), now time.Time) *Engine {
	store := claims.New(cfg, minTTL)
	store.SetLimits(maxClaims, maxPerAddr)
	// Addresses written in the device lists count before the firmware is asked.
	devs := devices.Resolve(cfg, nil)
	store.SetViews(devs.ViewList())
	return &Engine{cfg: cfg, store: store, sink: sink, logf: logf, started: now, devs: devs}
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

// HandlePacket processes one packet from the queue. raw starts with the IP header.
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
	// Names from the packet are normalized like names in the rules; whatever fails is not a domain name.
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
	// The decision shown is the asking device's; the memory keeps the answer for every device.
	d := e.cfg.MatchChainFor(e.devs.Views[u.Dst], names)
	o := observation{at: now, client: u.Dst, device: e.devs.Labels[u.Dst], name: names[0], action: d.Action}
	if d.Rule != nil {
		o.line = d.Rule.Line
		if !d.Rule.All { // "*" is what everything else gets, not a match
			e.stats.Claimed++
		}
	}
	e.remember(o)
	life := time.Duration(ttl) * time.Second
	if life > maxTTL {
		life = maxTTL
	}
	// Without device lists the asking device's decision is everyone's: no rule, nothing to keep.
	if (d.Rule == nil || d.Rule.All) && len(e.cfg.Devices) == 0 {
		return
	}
	e.apply(e.store.Observe(now, names, addrs, life), fmt.Sprintf("%s asked for %s", who(u.Dst, o.device), names[0]))
}

// Tick drops claims that have expired.
func (e *Engine) Tick(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.apply(e.store.Expire(now), "expired")
}

// Reload switches the daemon to new rules without losing the observations gathered so far.
// The sets are rebuilt in full: when the rules change, the numbers of "exit + mode" pairs shift.
// The new rules take effect even if the sets could not be built: an error is returned,
// and the build is retried until it succeeds (see NeedsResync).
func (e *Engine) Reload(cfg *rules.Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
	old := e.devs
	e.devs = devices.Resolve(cfg, e.hosts)
	e.logDevices(old, false)
	e.note(e.store.SetConfig(cfg, e.devs.ViewList()), "rules changed")
	return e.rebuild()
}

// NeedsResync reports that the last update of the sets failed and they must be rebuilt.
func (e *Engine) NeedsResync() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dirty
}

// Resync rebuilds everything from the current rules and memory: at startup and after
// the firmware has wiped the rules.
func (e *Engine) Resync() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rebuild()
}

func (e *Engine) rebuild() error {
	if e.sink == nil {
		return nil
	}
	err := e.sink.Rebuild(e.cfg, e.devs.Sources(), e.store.Entries())
	e.dirty = err != nil
	e.built = e.built || err == nil
	if err != nil {
		e.stats.ApplyErrors++
		e.logf("could not build address sets and routes: %v", err)
	}
	return err
}

// Config returns the rules in effect.
func (e *Engine) Config() *rules.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

// SaveState writes the accumulated claims so they survive a restart.
func (e *Engine) SaveState(w io.Writer) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.store.Save(w)
}

// LoadState reads claims written by SaveState. Resync builds the sets afterwards.
func (e *Engine) LoadState(r io.Reader, now time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.store.Load(r, now)
}

// SetExits records which interface each exit currently goes through (empty means none is live).
func (e *Engine) SetExits(active map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.exits = active
}

// SetDevices records the firmware's device list. When the device views change, decisions for the
// new views are computed and everything is rebuilt; when only addresses change, only the source
// sets are refilled.
func (e *Engine) SetDevices(hosts []devices.Host) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	first := e.hosts == nil
	e.hosts = slices.Clone(hosts) // the caller may reuse its slice
	old := e.devs
	e.devs = devices.Resolve(e.cfg, e.hosts)
	e.logDevices(old, first)
	if views := e.devs.ViewList(); !slices.Equal(views, e.store.Views()) {
		e.note(e.store.SetViews(views), "device lists changed")
		if !e.built {
			// At start the devices come before the exits and the saved state: the first build
			// (Resync) takes them along.
			return nil
		}
		return e.rebuild()
	}
	sources := e.devs.Sources()
	// A pending rebuild (dirty) takes the new addresses along.
	if e.sink == nil || !e.built || e.dirty || maps.EqualFunc(old.Sources(), sources, slices.Equal[[]netip.Addr]) {
		return nil
	}
	if err := e.sink.SetSources(sources); err != nil {
		// The kernel lags behind memory: a rebuild fixes it (see NeedsResync).
		e.dirty = true
		e.stats.ApplyErrors++
		e.logf("could not update the device addresses: %v", err)
		return err
	}
	return nil
}

// logDevices writes to the log the listed devices whose address or state changed. The first time
// the firmware's list arrives, and for lists new in the rules, it also writes the devices that are
// not on the network: a name the router does not know is better read in the log than guessed.
func (e *Engine) logDevices(old devices.Map, first bool) {
	type seen struct {
		ip    netip.Addr
		state string
	}
	was := map[string]seen{}
	for _, l := range old.Lists {
		for _, m := range l.Members {
			was[l.Name+" "+m.Ref.String()] = seen{m.IP, m.State}
		}
	}
	for _, l := range e.devs.Lists {
		for _, m := range l.Members {
			prev, known := was[l.Name+" "+m.Ref.String()]
			switch {
			case (first || !known) && !m.IP.IsValid():
				e.logf("device %s of list %s: %s", m.Ref, l.Name, m.State)
			case known && prev.ip == m.IP && prev.state == m.State:
			case m.IP.IsValid():
				if !known || prev.ip != m.IP {
					e.logf("device %s of list %s: now at %s", m.Ref, l.Name, m.IP)
				}
			default:
				e.logf("device %s of list %s: %s", m.Ref, l.Name, m.State)
			}
		}
	}
}

// who names a device for the log: its address and, if known, its name.
func who(a netip.Addr, device string) string {
	if device == "" {
		return a.String()
	}
	return a.String() + " (" + device + ")"
}

// note records changes in the log and the counters.
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
		if c.View == 0 {
			parts[i] = fmt.Sprintf("%s %s → %s", c.Addr, show(c.Old), show(c.New))
		} else {
			parts[i] = fmt.Sprintf("%s for %s: %s → %s", c.Addr, e.cfg.ViewName(c.View), show(c.Old), show(c.New))
		}
	}
	if more := len(changes) - len(shown); more > 0 {
		parts = append(parts, fmt.Sprintf("… %d more", more))
	}
	e.logf("%s: %s", why, strings.Join(parts, "; "))
}

func (e *Engine) apply(changes []claims.Change, why string) {
	e.note(changes, why)
	if len(changes) == 0 || e.sink == nil {
		return
	}
	if err := e.sink.Apply(changes); err != nil {
		// Memory already reflects the change but the kernel set does not: there will be no repeat
		// change for this address, so only a rebuild fixes the mismatch.
		e.dirty = true
		e.stats.ApplyErrors++
		e.logf("could not apply changes: %v", err)
	}
}

// exitLine describes the current state of the action's exit; empty if there is nothing to say.
func (e *Engine) exitLine(a rules.Action) string {
	if a.Exit == rules.None {
		if e.sink == nil {
			return "would be blocked: observe mode changes nothing\n"
		}
		return "blocked: new connections are refused\n"
	}
	if a.Exit == rules.Direct || e.exits == nil {
		return ""
	}
	if dev := e.exits[a.Exit]; dev != "" {
		return fmt.Sprintf("exit %s: now via %s\n", a.Exit, dev)
	}
	if a.Strict {
		return fmt.Sprintf("exit %s: all tunnels are down — traffic is blocked (strict)\n", a.Exit)
	}
	return fmt.Sprintf("exit %s: all tunnels are down — traffic goes direct\n", a.Exit)
}

func show(a *rules.Action) string {
	if a == nil {
		return "-"
	}
	return a.String()
}

func (e *Engine) remember(o observation) {
	e.seq++
	o.seq = e.seq
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

// Why explains where a name or address will go and shows what is known about it from DNS.
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
		fmt.Fprintf(&b, "rule, line %d: %s\n", d.Rule.Line, d.Rule.Text)
	} else {
		fmt.Fprintf(&b, "no rule matched; default applies (line %d)\n", e.cfg.DefaultLine)
	}
	b.WriteString(e.exitLine(d.Action))
	// The lists of devices on the network, and every single list: a list whose devices are away
	// still has rules worth knowing about.
	views := e.devs.ViewList()
	for _, v := range e.cfg.ListViews() {
		if !slices.Contains(views, v) {
			views = append(views, v)
		}
	}
	b.WriteString(e.cfg.DeviceLines(subject, views))
	if addr, err := netip.ParseAddr(subj); err == nil {
		if !e.store.Known(addr) {
			b.WriteString("this address has not been seen in DNS answers\n")
			return b.String(), nil
		}
		cs := e.store.Claims(addr)
		for _, c := range cs {
			fmt.Fprintf(&b, "claim: %s → %s (line %d, %s left)\n",
				strings.Join(c.Names, " → "), c.Action, e.lineOf(c.Index), ago(c.Expires.Sub(now)))
		}
		switch eff := e.store.Effective(addr); {
		case eff != nil:
			fmt.Fprintf(&b, "in the dynamic set: %s\n", *eff)
		case len(cs) > 0 && claims.PrivateAddr(addr) && !slices.ContainsFunc(cs, func(c claims.Claim) bool { return c.Action.Exit != rules.None }):
			b.WriteString("not in the dynamic set: a name does not block a private address\n")
		case len(cs) > 0:
			b.WriteString("not in the dynamic set: the address is in a subnet of an earlier rule\n")
		}
		for _, v := range e.store.Views() {
			if eff := e.store.EffectiveFor(v, addr); eff != nil {
				fmt.Fprintf(&b, "in the dynamic set for %s: %s\n", e.cfg.ViewName(v), *eff)
			}
		}
		for _, c := range e.store.Untracked(addr) {
			fmt.Fprintf(&b, "claim for devices not on the network now: %s → %s (line %d, %s left)\n",
				strings.Join(c.Names, " → "), c.Action, e.lineOf(c.Index), ago(c.Expires.Sub(now)))
		}
		return b.String(), nil
	}
	addrs := e.store.AddrsOf(subj)
	fmt.Fprintf(&b, "addresses for this name in memory: %d", len(addrs))
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
			fmt.Fprintf(&b, "last DNS answer: %s ago, device %s\n", ago(now.Sub(o.at)), o.client)
			return b.String(), nil
		}
	}
	b.WriteString("no DNS answers for this name yet\n")
	return b.String(), nil
}

// Status is a brief human-readable daemon status.
func (e *Engine) Status(now time.Time) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var b strings.Builder
	if e.sink == nil {
		b.WriteString("trassa: observe mode — address sets and routes are not changed\n")
	} else {
		b.WriteString("trassa: routing mode\n")
	}
	s := e.snapshot()
	fmt.Fprintf(&b, "uptime %s, rules: %d, addresses in memory: %d, claims: %d\n",
		uptime(now.Sub(e.started)), len(e.cfg.Rules), e.store.Len(), e.store.Total())
	fmt.Fprintf(&b, "packets: %d, answers with addresses: %d, matched rules: %d, changes: %d\n", s.Packets, s.Answers, s.Claimed, s.Changes)
	fmt.Fprintf(&b, "skipped — not DNS: %d, malformed: %d, other: %d, bad names: %d, over limit: %d; apply errors: %d\n",
		s.NotDNS, s.Malformed, s.Skipped, s.BadName, s.Dropped, s.ApplyErrors)
	if e.exits != nil {
		parts := make([]string, 0, len(e.cfg.Exits))
		for _, x := range e.cfg.Exits {
			dev := e.exits[x.Name]
			if dev == "" {
				dev = "no live tunnels"
			}
			parts = append(parts, x.Name+" → "+dev)
		}
		fmt.Fprintf(&b, "exits: %s\n", strings.Join(parts, "; "))
	}
	for _, l := range e.devs.Lists {
		parts := make([]string, 0, len(l.Members))
		for _, m := range l.Members {
			switch {
			case m.IP.IsValid() && m.Label != "":
				parts = append(parts, m.Label+" ("+m.IP.String()+")")
			case m.IP.IsValid():
				parts = append(parts, m.IP.String())
			case m.Label != "":
				parts = append(parts, m.Label+" — "+m.State)
			default:
				parts = append(parts, m.Ref.String()+" — "+m.State)
			}
		}
		fmt.Fprintf(&b, "devices %s: %s\n", l.Name, strings.Join(parts, ", "))
	}
	if len(e.recent) == 0 {
		b.WriteString("no observations yet\n")
		return b.String()
	}
	b.WriteString("recent observations:\n")
	from := max(0, len(e.recent)-statusRows)
	for _, o := range e.recent[from:] {
		where := "default"
		if o.line != 0 {
			where = fmt.Sprintf("line %d", o.line)
		}
		fmt.Fprintf(&b, "  %s %s %s → %s (%s)\n", o.at.Format("15:04:05"), who(o.client, o.device), o.name, o.action, where)
	}
	return b.String()
}

// State is the state for the web page, newest observations first.
func (e *Engine) State() ctl.State {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := ctl.State{Mode: "observe", Started: e.started, Rules: len(e.cfg.Rules), Addrs: e.store.Len(),
		Claims: e.store.Total(), Stats: e.snapshot(), Exits: []ctl.ExitState{}, Recent: []ctl.Observation{}}
	if e.sink != nil {
		st.Mode = "route"
	}
	for _, x := range e.cfg.Exits {
		st.Exits = append(st.Exits, ctl.ExitState{Name: x.Name, Via: e.exits[x.Name], Known: e.exits != nil})
	}
	for i := len(e.recent) - 1; i >= 0 && len(st.Recent) < stateRows; i-- {
		st.Recent = append(st.Recent, e.recent[i].json())
	}
	return st
}

// ago writes a duration briefly: "45s", "10m", "3h".
func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

func uptime(d time.Duration) string {
	h, m := int(d.Hours()), int(d.Minutes())%60
	if h == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dh%02dm", h, m)
}

func (o observation) json() ctl.Observation {
	return ctl.Observation{At: o.at, Client: o.client.String(), Device: o.device, Name: o.name,
		Action: o.action.String(), Line: o.line}
}

// Answers returns the DNS answers newer than after, newest first. If the list cannot be continued
// from after (the page's first request, a daemon restart, or the answers it missed are no longer
// kept), it returns the whole list.
func (e *Engine) Answers(after uint64) ctl.Answers {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := ctl.Answers{Last: e.seq, Answers: []ctl.Answer{}}
	oldest := e.seq + 1
	if len(e.recent) > 0 {
		oldest = e.recent[0].seq
	}
	if after == 0 || after > e.seq || after+1 < oldest {
		out.Full, after = true, 0
	}
	for i := len(e.recent) - 1; i >= 0 && e.recent[i].seq > after; i-- {
		out.Answers = append(out.Answers, ctl.Answer{Seq: e.recent[i].seq, Observation: e.recent[i].json()})
	}
	return out
}
