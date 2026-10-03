package web

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func node(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("node")
	if err != nil {
		t.Skip("нет node: проверка сценариев страницы пропущена")
	}
	return p
}

// Хеши на JavaScript должны совпадать с Go: иначе страница не войдёт ни с каким паролем.
func TestHashScript(t *testing.T) {
	src, err := staticFiles.ReadFile("static/hash.js")
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{"", "a", "abc", "message digest", "admin:Netcraze Giga:пароль",
		strings.Repeat("x", 55), strings.Repeat("x", 56), strings.Repeat("x", 63), strings.Repeat("x", 64),
		strings.Repeat("x", 65), strings.Repeat("я", 1000)}
	in, _ := json.Marshal(inputs)
	script := string(src) + `
const inputs = JSON.parse(process.argv[1]);
const out = inputs.map(s => [TrassaHash.md5hex(s), TrassaHash.sha256hex(s)]);
out.push([TrassaHash.response("admin", "пароль", "Netcraze Giga", "ABCDEF"), ""]);
process.stdout.write(JSON.stringify(out));`
	b, err := exec.Command(node(t), "-e", script, string(in)).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var got [][2]string
	if err := json.Unmarshal(b, &got); err != nil || len(got) != len(inputs)+1 {
		t.Fatalf("%s: %v", b, err)
	}
	for i, s := range inputs {
		m, h := md5.Sum([]byte(s)), sha256.Sum256([]byte(s))
		if got[i][0] != hex.EncodeToString(m[:]) || got[i][1] != hex.EncodeToString(h[:]) {
			t.Errorf("%.20q: md5 %s, sha256 %s", s, got[i][0], got[i][1])
		}
	}
	if want := answer("admin", "пароль", "Netcraze Giga", "ABCDEF"); got[len(inputs)][0] != want {
		t.Errorf("ответ на вызов: %s, ожидался %s", got[len(inputs)][0], want)
	}
}

func TestPageScriptsParse(t *testing.T) {
	n := node(t)
	for _, name := range []string{"app.js", "hash.js", "logic.js"} {
		src, err := staticFiles.ReadFile("static/" + name)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), name)
		os.WriteFile(p, src, 0o644)
		if out, err := exec.Command(n, "--check", p).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}

// Всё, на что ссылается страница, встроено; внешних ресурсов, innerHTML и встроенных стилей нет.
func TestPageIsSelfContained(t *testing.T) {
	page, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	refs := regexp.MustCompile(`(?:src|href)="([^"]+)"`).FindAllStringSubmatch(string(page), -1)
	if len(refs) < 3 {
		t.Fatalf("ссылок на файлы страницы: %d", len(refs))
	}
	for _, ref := range refs {
		if strings.Contains(ref[1], "//") {
			t.Errorf("внешний ресурс: %s", ref[1])
			continue
		}
		if _, err := staticFiles.ReadFile("static/" + ref[1]); err != nil {
			t.Errorf("нет файла %s", ref[1])
		}
	}
	for _, name := range []string{"index.html", "app.js"} {
		b, _ := staticFiles.ReadFile("static/" + name)
		for _, bad := range []string{"innerHTML", "style=", "<style", "onclick"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s: %s", name, bad)
			}
		}
	}
}

// Повторный вход (истёк сеанс, перезапустилась страница) не должен стирать несохранённую правку.
func TestLogicAdoptKeepsUnsavedEdit(t *testing.T) {
	src, err := staticFiles.ReadFile("static/logic.js")
	if err != nil {
		t.Fatal(err)
	}
	type tc struct{ Editor, Saved, Server, WantEditor, WantSaved, Note string }
	cases := []tc{
		{"", "", "A", "A", "A", ""},   // первая загрузка
		{"A", "A", "B", "B", "B", ""}, // правки нет — берём текст с роутера
		{"A+правка", "A", "A", "A+правка", "A", "осталась"},   // правка цела
		{"A+правка", "A", "B", "A+правка", "B", "изменились"}, // правка цела, роутер сменил текст
		{"B", "A", "B", "B", "B", ""}, // набранное совпало с текстом роутера
	}
	in, _ := json.Marshal(cases)
	script := string(src) + `
const cases = JSON.parse(process.argv[1]);
process.stdout.write(JSON.stringify(cases.map(c => TrassaLogic.adopt(c.Editor, c.Saved, c.Server))));`
	b, err := exec.Command(node(t), "-e", script, string(in)).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var got []struct{ Editor, Saved, Note string }
	if err := json.Unmarshal(b, &got); err != nil || len(got) != len(cases) {
		t.Fatalf("%s: %v", b, err)
	}
	for i, c := range cases {
		g := got[i]
		if g.Editor != c.WantEditor || g.Saved != c.WantSaved || (c.Note == "") != (g.Note == "") || !strings.Contains(g.Note, c.Note) {
			t.Errorf("%+v: получено %+v", c, g)
		}
	}
}
