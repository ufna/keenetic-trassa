// Package engine carries a packet from the queue to a decision: IP → DNS → rules → claims.
package engine

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	"trassa/internal/claims"
	"trassa/internal/ctl"
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
	recentSize     = 200
	statusRows     = 10
	stateRows      = 30
)

// Sink carries out decisions in the kernel. nil means observe mode: changes are only logged.
type Sink interface {
	// Apply edits the dynamic address sets.
	Apply(changes []claims.Change) error
	// Rebuild builds everything from scratch from the rules and an address snapshot.
	Rebuild(cfg *rules.Config, entries []claims.Entry) error
}

// Stats are the daemon counters; the fields are described in ctl.Stats.
type Stats = ctl.Stats

type observation struct {
	at     time.Time
	client netip.Addr
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
	exits   map[string]string // exit → name of the live interface; nil means unknown
	dirty   bool              // kernel sets may have drifted from memory: a rebuild is needed
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
	e.apply(e.store.Observe(now, names, addrs, life), fmt.Sprintf("%s asked for %s", u.Dst, names[0]))
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
	e.note(e.store.SetConfig(cfg), "rules changed")
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
	err := e.sink.Rebuild(e.cfg, e.store.Entries())
	e.dirty = err != nil
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
		parts[i] = fmt.Sprintf("%s %s → %s", c.Addr, show(c.Old), show(c.New))
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
	if addr, err := netip.ParseAddr(subj); err == nil {
		cs := e.store.Claims(addr)
		if len(cs) == 0 {
			b.WriteString("this address has not been seen in DNS answers\n")
			return b.String(), nil
		}
		for _, c := range cs {
			fmt.Fprintf(&b, "claim: %s → %s (line %d, %s left)\n",
				strings.Join(c.Names, " → "), c.Action, e.lineOf(c.Index), ago(c.Expires.Sub(now)))
		}
		if eff := e.store.Effective(addr); eff != nil {
			fmt.Fprintf(&b, "in the dynamic set: %s\n", *eff)
		} else {
			b.WriteString("not in the dynamic set: the address is in a subnet of an earlier rule\n")
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
		fmt.Fprintf(&b, "  %s %s %s → %s (%s)\n", o.at.Format("15:04:05"), o.client, o.name, o.action, where)
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
		o := e.recent[i]
		st.Recent = append(st.Recent, ctl.Observation{At: o.at, Client: o.client.String(), Name: o.name,
			Action: o.action.String(), Line: o.line})
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
