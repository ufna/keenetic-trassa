// Package store хранит правила на роутере: проверка, сохранение, история версий и откат.
// Проверяет всегда один и тот же код: при сохранении со страницы, при trassa reload и при старте демона.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"trassa/internal/rules"
)

const (
	// RulesFile — файл правил в каталоге правил.
	RulesFile = "rules.conf"
	// Keep — сколько версий хранит история.
	Keep = 20
	// MaxSize — предельный размер текста правил.
	MaxSize = 256 << 10

	historyDir = "history"
	lockFile   = ".lock"
	idTime     = "20060102-150405.000" // время версии в UTC: по имени версии сортируются по времени
)

const (
	kindPage     = "page"     // правка со страницы
	kindRollback = "rollback" // возврат прежней версии
	kindOutside  = "outside"  // файл изменён не через trassa: по SSH или при доставке
)

var idPattern = regexp.MustCompile(`^\d{8}-\d{6}\.\d{3}-(page|rollback|outside)$`)

// Reader читает файлы условий @путь только внутри каталога правил dir.
func Reader(dir string) rules.ReadFile {
	return func(p string) (string, error) {
		if !filepath.IsLocal(p) {
			return "", errors.New("допустим только путь внутри каталога правил: без / в начале и без ..")
		}
		b, err := os.ReadFile(filepath.Join(dir, p))
		return string(b), err
	}
}

// Load проверяет текст правил; файлы условий @путь читаются из dir.
func Load(dir, text string) (*rules.Config, []rules.Problem) {
	return rules.Load(text, Reader(dir))
}

// LoadFile читает и проверяет файл правил; файлы условий — из его каталога.
func LoadFile(path string) (*rules.Config, []rules.Problem, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	cfg, ps := Load(filepath.Dir(path), string(b))
	return cfg, ps, nil
}

// Applied — что сделал демон с сохранёнными правилами.
type Applied int

const (
	NotAsked   Applied = iota // до демона дело не дошло
	Running                   // демон работает по новым правилам
	Partly                    // правила приняты, но списки и маршруты ещё не построены
	NotRunning                // демон не запущен: правила вступят в силу при запуске
	Unknown                   // демон не ответил вовремя
	Rejected                  // демон не принял правила; файл возвращён к прежнему
)

func (a Applied) String() string {
	return [...]string{"not-asked", "running", "partly", "not-running", "unknown", "rejected"}[a]
}

var defaultMessage = map[Applied]string{
	Running:    "правила применены",
	Partly:     "правила приняты, но списки и маршруты ещё не построены",
	NotRunning: "демон не запущен: правила вступят в силу при его запуске",
	Unknown:    "демон не ответил вовремя: проверьте его состояние",
	Rejected:   "демон не принял правила; действуют прежние",
}

// Result — чем кончилось сохранение или возврат версии.
type Result struct {
	Problems    []rules.Problem
	NeedConfirm bool // есть предупреждения, а подтверждения не было: ничего не сохранено
	Unchanged   bool // текст совпадает с действующим: сохранять нечего
	Saved       bool // файл правил заменён
	Applied     Applied
	Message     string // ответ демона или пояснение
	Rules       int
	Exits       int
	Tests       int
}

// Version — версия правил в истории.
type Version struct {
	ID      string    `json:"id"`
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`    // page, rollback или outside
	Current bool      `json:"current"` // совпадает с действующим файлом правил
	Rules   int       `json:"rules"`
	Tests   int       `json:"tests"`
}

// Store — каталог правил на роутере: rules.conf, файлы условий @путь и история версий.
type Store struct {
	Dir string
	// Validate проверяет правила на роутере — существуют ли интерфейсы выходов; nil — не проверять.
	Validate func(*rules.Config) []rules.Problem
	// Apply просит демон перечитать файл правил; nil — демона нет.
	Apply func() (Applied, string)
	// Now — часы; nil — time.Now.
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

// Check проверяет текст целиком: разбор, ожидания, предупреждения и выходы на роутере.
func (s *Store) Check(text string) (*rules.Config, []rules.Problem) {
	if len(text) > MaxSize {
		return nil, []rules.Problem{{Severity: rules.Error, Msg: fmt.Sprintf("текст правил больше %d КБ", MaxSize>>10)}}
	}
	cfg, ps := Load(s.Dir, text)
	if s.Validate != nil && !rules.HasErrors(ps) {
		ps = append(ps, s.Validate(cfg)...)
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].Line < ps[j].Line })
	}
	return cfg, ps
}

// Current возвращает действующий текст правил.
func (s *Store) Current() (string, error) {
	b, err := os.ReadFile(s.rulesPath())
	return string(b), err
}

// Save делает текст действующим, если в нём нет ошибок, а предупреждения подтверждены.
func (s *Store) Save(text string, confirm bool) (Result, error) {
	return s.save(text, kindPage, confirm)
}

// Rollback возвращает версию из истории через ту же проверку, что и сохранение.
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
		res.Unchanged, res.Message = true, "изменений нет"
		return res, nil
	}
	if existed {
		// Действующий текст мог появиться не через trassa — по SSH или при доставке.
		// Если в истории его нет, он попадает туда: заменённую правку можно вернуть.
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
	s.prune()

	res.Applied = NotRunning
	if s.Apply != nil {
		res.Applied, res.Message = s.Apply()
	}
	if res.Message == "" {
		res.Message = defaultMessage[res.Applied]
	}
	if res.Applied == Rejected {
		// Демон работает по прежним правилам — файл должен говорить то же самое.
		if existed {
			err = writeAtomic(s.rulesPath(), prev)
		} else {
			err = os.Remove(s.rulesPath())
		}
		os.Remove(s.versionPath(id))
		if err != nil {
			return res, fmt.Errorf("демон не принял правила, а вернуть прежний файл не удалось: %w", err)
		}
		return res, nil
	}
	res.Saved = true
	return res, nil
}

// archive кладёт текст в историю, если самая новая версия в ней — другая.
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

// addVersion записывает версию в историю. Имя — время в UTC и вид правки; время каждой новой
// версии позже предыдущей, даже если часы роутера перевели назад.
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
		// Жёсткая ссылка не заменяет существующий файл: две версии с одним именем не получатся.
		err := os.Link(tmp, s.versionPath(id))
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("не удалось подобрать имя для версии")
}

// ids возвращает имена версий от старой к новой.
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

// prune оставляет в истории Keep самых новых версий.
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

// History возвращает версии от новой к старой. Действующей отмечена самая новая версия,
// совпадающая с файлом правил.
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

// Version возвращает текст версии.
func (s *Store) Version(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", fmt.Errorf("нет версии %q", id)
	}
	b, err := os.ReadFile(s.versionPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("нет версии %q: возможно, она вытеснена из истории", id)
	}
	return string(b), err
}

// Previous возвращает самую новую версию, отличную от действующего текста.
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
	return "", errors.New("в истории нет версии, отличной от действующей")
}

// lock не даёт двум процессам — странице и trassa rollback — менять правила одновременно.
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
	return func() { f.Close() }, nil // закрытие файла снимает блокировку
}

// writeTemp записывает данные во временный файл в каталоге dir и сбрасывает их на накопитель.
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

// writeAtomic подменяет файл целиком: при сбое посреди записи остаётся прежний.
func writeAtomic(path string, data []byte) error {
	tmp, err := writeTemp(filepath.Dir(path), data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
