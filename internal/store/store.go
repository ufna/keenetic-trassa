// Package store keeps the rules on the router: checking, saving, version history and rollback.
// The same code always does the checking: on save from the web page, on trassa reload and at daemon start.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"trassa/internal/rules"
)

const (
	// RulesFile is the rules file in the rules directory.
	RulesFile = "rules.conf"
	// DisabledFile marks trassa as turned off: while it exists, the init script does not start the daemon.
	DisabledFile = "disabled"
	// Keep is how many versions the history keeps.
	Keep = 20
	// MaxSize is the maximum size of the rules text.
	MaxSize = 256 << 10

	historyDir = "history"
	lockFile   = ".lock"
	idTime     = "20060102-150405.000" // version time in UTC: sorting versions by name sorts them by time
)

const (
	kindPage     = "page"     // edit from the web page
	kindRollback = "rollback" // restore of an earlier version
	kindOutside  = "outside"  // file changed outside trassa: over SSH or on deployment
)

var idPattern = regexp.MustCompile(`^\d{8}-\d{6}\.\d{3}-(page|rollback|outside)$`)

// Reader reads @path condition files only inside the rules directory dir.
func Reader(dir string) rules.ReadFile {
	return func(p string) (string, error) {
		if !filepath.IsLocal(p) {
			return "", errors.New("only a path inside the rules directory is allowed: no leading / and no ..")
		}
		b, err := os.ReadFile(filepath.Join(dir, p))
		return string(b), err
	}
}

// Load checks the rules text; @path condition files are read from dir.
func Load(dir, text string) (*rules.Config, []rules.Problem) {
	return rules.Load(text, Reader(dir))
}

// LoadFile reads and checks a rules file; condition files come from its directory.
func LoadFile(path string) (*rules.Config, []rules.Problem, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	cfg, ps := Load(filepath.Dir(path), string(b))
	return cfg, ps, nil
}

// Applied is what the daemon did with the saved rules.
type Applied int

const (
	NotAsked   Applied = iota // the daemon was never asked
	Running                   // the daemon runs with the new rules
	Partly                    // rules accepted, but address sets and routes are not built yet
	NotRunning                // daemon is not running: the rules take effect when it starts
	Unknown                   // daemon did not reply in time
	Rejected                  // daemon rejected the rules; the file is restored to the previous one
)

func (a Applied) String() string {
	return [...]string{"not-asked", "running", "partly", "not-running", "unknown", "rejected"}[a]
}

var defaultMessage = map[Applied]string{
	Running:    "rules applied",
	Partly:     "rules accepted, but address sets and routes are not built yet",
	NotRunning: "daemon is not running: the rules will take effect when it starts",
	Unknown:    "daemon did not reply in time: check its state",
	Rejected:   "daemon rejected the rules; the previous ones remain in effect",
}

// Result is the outcome of a save or a version restore.
type Result struct {
	Problems    []rules.Problem
	NeedConfirm bool // there are warnings but no confirmation: nothing was saved
	Unchanged   bool // the text matches the current one: nothing to save
	Saved       bool // the rules file was replaced
	Applied     Applied
	Message     string // daemon reply or an explanation
	Rules       int
	Exits       int
	Tests       int
}

// Version is a rules version in the history.
type Version struct {
	ID      string    `json:"id"`
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`    // page, rollback or outside
	Current bool      `json:"current"` // matches the current rules file
	Rules   int       `json:"rules"`
	Tests   int       `json:"tests"`
}

// Store is the rules directory on the router: rules.conf, @path condition files and the version history.
type Store struct {
	Dir string
	// Validate checks the rules against the router (whether the exit interfaces exist); nil means no check.
	Validate func(*rules.Config) []rules.Problem
	// Apply asks the daemon to reread the rules file; nil means there is no daemon.
	Apply func() (Applied, string)
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu sync.Mutex
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) rulesPath() string            { return filepath.Join(s.Dir, RulesFile) }
func (s *Store) historyPath() string          { return filepath.Join(s.Dir, historyDir) }
func (s *Store) versionPath(id string) string { return filepath.Join(s.historyPath(), id+".conf") }

// Check checks the whole text: parsing, expectations, warnings and exits on the router.
func (s *Store) Check(text string) (*rules.Config, []rules.Problem) {
	if len(text) > MaxSize {
		return nil, []rules.Problem{{Severity: rules.Error, Msg: fmt.Sprintf("rules text is larger than %d KB", MaxSize>>10)}}
	}
	cfg, ps := Load(s.Dir, text)
	if !rules.HasErrors(ps) {
		ps = append(ps, s.exitsChanged(cfg)...)
	}
	if s.Validate != nil && !rules.HasErrors(ps) {
		ps = append(ps, s.Validate(cfg)...)
	}
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Line < ps[j].Line })
	return cfg, ps
}

// exitsChanged warns when the list or the order of exits differs from the rules in effect:
// slot numbers follow that order, so tunnel connections in progress are cut and reconnect.
func (s *Store) exitsChanged(cfg *rules.Config) []rules.Problem {
	cur, err := s.Current()
	if err != nil {
		return nil
	}
	old, ps := Load(s.Dir, cur)
	if rules.HasErrors(ps) {
		return nil
	}
	if slices.EqualFunc(old.Exits, cfg.Exits, func(a, b rules.Exit) bool { return a.Name == b.Name }) {
		return nil
	}
	line := 0
	if len(cfg.Exits) > 0 {
		line = cfg.Exits[0].Line
	}
	return []rules.Problem{{Line: line, Severity: rules.Warning,
		Msg: "the list or order of exits changed: tunnel connections in progress will be cut and reconnect"}}
}

// Current returns the current rules text.
func (s *Store) Current() (string, error) {
	b, err := os.ReadFile(s.rulesPath())
	return string(b), err
}

// Save makes the text current if it has no errors and its warnings are confirmed.
func (s *Store) Save(text string, confirm bool) (Result, error) {
	return s.save(text, kindPage, confirm)
}

// Rollback restores a version from the history through the same checks as a save.
func (s *Store) Rollback(id string, confirm bool) (Result, error) {
	text, err := s.Version(id)
	if err != nil {
		return Result{}, err
	}
	return s.save(text, kindRollback, confirm)
}

func (s *Store) save(text, kind string, confirm bool) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock()
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	s.removeStaleTemp()

	var res Result
	cfg, ps := s.Check(text)
	res.Problems = ps
	if cfg != nil {
		res.Rules, res.Exits, res.Tests = len(cfg.Rules), len(cfg.Exits), len(cfg.Tests)
	}
	if rules.HasErrors(ps) {
		return res, nil
	}
	if len(ps) > 0 && !confirm {
		res.NeedConfirm = true
		return res, nil
	}
	prev, err := os.ReadFile(s.rulesPath())
	existed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, err
	}
	if existed && string(prev) == text {
		res.Unchanged, res.Message = true, "no changes"
		return res, nil
	}
	if existed {
		// The current text may have come from outside trassa: over SSH or on deployment.
		// If it is not in the history, it goes there, so the replaced edit can be restored.
		if err := s.archive(string(prev)); err != nil {
			return res, err
		}
	}
	id, err := s.addVersion(text, kind)
	if err != nil {
		return res, err
	}
	if err := writeAtomic(s.rulesPath(), []byte(text)); err != nil {
		os.Remove(s.versionPath(id))
		return res, err
	}

	res.Applied = NotRunning
	if s.Apply != nil {
		res.Applied, res.Message = s.Apply()
	}
	if res.Message == "" {
		res.Message = defaultMessage[res.Applied]
	}
	if res.Applied == Rejected {
		// The daemon runs with the previous rules, so the file must say the same.
		if existed {
			err = writeAtomic(s.rulesPath(), prev)
		} else {
			err = os.Remove(s.rulesPath())
		}
		os.Remove(s.versionPath(id))
		if err != nil {
			return res, fmt.Errorf("daemon rejected the rules, and restoring the previous file failed: %w", err)
		}
		return res, nil
	}
	res.Saved = true
	// Only now: a rejected save must not push the oldest version out of the history.
	s.prune()
	return res, nil
}

// archive puts the text into the history if the newest version there differs.
func (s *Store) archive(text string) error {
	ids, err := s.ids()
	if err != nil {
		return err
	}
	if n := len(ids); n > 0 {
		if b, err := os.ReadFile(s.versionPath(ids[n-1])); err == nil && string(b) == text {
			return nil
		}
	}
	_, err = s.addVersion(text, kindOutside)
	return err
}

// addVersion writes a version to the history. The name is the UTC time and the edit kind; each new
// version's time is later than the previous one's, even if the router clock was set back.
func (s *Store) addVersion(text, kind string) (string, error) {
	if err := os.MkdirAll(s.historyPath(), 0o755); err != nil {
		return "", err
	}
	ids, err := s.ids()
	if err != nil {
		return "", err
	}
	t := s.now().UTC().Truncate(time.Millisecond)
	if n := len(ids); n > 0 {
		if last, err := time.Parse(idTime, ids[n-1][:len(idTime)]); err == nil && !t.After(last) {
			t = last.Add(time.Millisecond)
		}
	}
	tmp, err := writeTemp(s.historyPath(), []byte(text))
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	for i := 0; i < 1000; i++ {
		id := t.Add(time.Duration(i)*time.Millisecond).Format(idTime) + "-" + kind
		// A hard link never replaces an existing file, so two versions cannot share a name.
		err := os.Link(tmp, s.versionPath(id))
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("could not find a free name for the version")
}

// ids returns version names from oldest to newest.
func (s *Store) ids() ([]string, error) {
	ents, err := os.ReadDir(s.historyPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range ents {
		if id, ok := strings.CutSuffix(e.Name(), ".conf"); ok && idPattern.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// prune keeps the Keep newest versions in the history.
func (s *Store) prune() {
	ids, err := s.ids()
	if err != nil {
		return
	}
	for len(ids) > Keep {
		os.Remove(s.versionPath(ids[0]))
		ids = ids[1:]
	}
}

// History returns versions from newest to oldest. The newest version that matches the
// rules file is marked current.
func (s *Store) History() ([]Version, error) {
	ids, err := s.ids()
	if err != nil {
		return nil, err
	}
	cur, curErr := s.Current()
	marked := curErr != nil
	out := []Version{}
	for i := len(ids) - 1; i >= 0; i-- {
		b, err := os.ReadFile(s.versionPath(ids[i]))
		if err != nil {
			continue
		}
		v := Version{ID: ids[i], Kind: ids[i][len(idTime)+1:]}
		v.Time, _ = time.Parse(idTime, ids[i][:len(idTime)])
		if !marked && string(b) == cur {
			v.Current, marked = true, true
		}
		if cfg, _ := Load(s.Dir, string(b)); cfg != nil {
			v.Rules, v.Tests = len(cfg.Rules), len(cfg.Tests)
		}
		out = append(out, v)
	}
	return out, nil
}

// Version returns the text of a version.
func (s *Store) Version(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", fmt.Errorf("no version %q", id)
	}
	b, err := os.ReadFile(s.versionPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("no version %q: it may have been pruned from the history", id)
	}
	return string(b), err
}

// Previous returns the newest version that differs from the current text.
func (s *Store) Previous() (string, error) {
	cur, err := s.Current()
	if err != nil {
		return "", err
	}
	ids, err := s.ids()
	if err != nil {
		return "", err
	}
	for i := len(ids) - 1; i >= 0; i-- {
		if b, err := os.ReadFile(s.versionPath(ids[i])); err == nil && string(b) != cur {
			return ids[i], nil
		}
	}
	return "", errors.New("history has no version different from the current one")
}

// lock keeps two processes (the web page and trassa rollback) from changing the rules at the same time.
func (s *Store) lock() (func(), error) {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, lockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil // closing the file releases the lock
}

const disabledText = "trassa is turned off: the daemon does not start while this file exists.\n" +
	"Turn it on from the web page or with: trassa enable\n"

// Disabled reports whether trassa is turned off.
func (s *Store) Disabled() bool {
	_, err := os.Lstat(filepath.Join(s.Dir, DisabledFile))
	return err == nil
}

// Disable turns trassa off. The mark is on flash, so trassa stays off after a reboot too.
func (s *Store) Disable() error {
	return writeAtomic(filepath.Join(s.Dir, DisabledFile), []byte(disabledText))
}

// Enable turns trassa on again.
func (s *Store) Enable() error {
	if err := os.Remove(filepath.Join(s.Dir, DisabledFile)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	syncDir(s.Dir)
	return nil
}

// syncDir flushes the directory itself, so that a rename or a removal survives a power cut.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

// writeTemp writes data to a temporary file in dir and flushes it to storage.
func writeTemp(dir string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", err
	}
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	if err := errors.Join(werr, f.Close(), os.Chmod(f.Name(), 0o644)); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// writeAtomic replaces the file as a whole: if writing fails midway, the old file remains.
// The directory is synced too, so the rename itself survives a power cut.
func writeAtomic(path string, data []byte) error {
	tmp, err := writeTemp(filepath.Dir(path), data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// staleTemp is how old a temporary file must be to count as left over from a crash: a save
// in progress in another process is never that slow.
const staleTemp = time.Hour

// removeStaleTemp removes temporary files left in the rules directory and the history by a crash.
func (s *Store) removeStaleTemp() {
	for _, dir := range []string{s.Dir, s.historyPath()} {
		matches, _ := filepath.Glob(filepath.Join(dir, ".tmp-*"))
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && time.Since(fi.ModTime()) > staleTemp {
				os.Remove(m)
			}
		}
	}
}
