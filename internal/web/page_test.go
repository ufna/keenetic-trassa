package web

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
		t.Skip("no node: page script checks skipped")
	}
	return p
}

// The JavaScript hashes must match Go, or the page cannot sign in with any password.
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
		t.Errorf("challenge response: %s, want %s", got[len(inputs)][0], want)
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

// Everything the page references is embedded; there are no external resources, innerHTML or inline styles.
func TestPageIsSelfContained(t *testing.T) {
	page, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	refs := regexp.MustCompile(`(?:src|href)="([^"]+)"`).FindAllStringSubmatch(string(page), -1)
	if len(refs) < 3 {
		t.Fatalf("references to page files: %d", len(refs))
	}
	for _, ref := range refs {
		if strings.Contains(ref[1], "//") {
			t.Errorf("external resource: %s", ref[1])
			continue
		}
		if _, err := staticFiles.ReadFile("static/" + ref[1]); err != nil {
			t.Errorf("missing file %s", ref[1])
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

// Signing in again (session expired, page reloaded) must not wipe an unsaved edit.
func TestLogicAdoptKeepsUnsavedEdit(t *testing.T) {
	src, err := staticFiles.ReadFile("static/logic.js")
	if err != nil {
		t.Fatal(err)
	}
	type tc struct{ Editor, Saved, Server, WantEditor, WantSaved, Note string }
	cases := []tc{
		{"", "", "A", "A", "A", ""},                                        // first load
		{"A", "A", "B", "B", "B", ""},                                      // no edit: take the router text
		{"A+edit", "A", "A", "A+edit", "A", "kept in the editor"},          // the edit is intact
		{"A+edit", "A", "B", "A+edit", "B", "changed while you were away"}, // the edit is intact, the router text changed
		{"B", "A", "B", "B", "B", ""},                                      // what was typed matches the router text
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
			t.Errorf("%+v: got %+v", c, g)
		}
	}
}

// The page's "add a rule" window and its filter: the parts that need no page.
func TestLogicRulesAndFilter(t *testing.T) {
	src, err := staticFiles.ReadFile("static/logic.js")
	if err != nil {
		t.Fatal(err)
	}
	script := string(src) + `
const L = TrassaLogic, out = {};
out.parents = [
  L.parents("rr3---sn-4g5e.googlevideo.com"), L.parents("www.youtube.com"), L.parents("youtube.com"),
  L.parents("news.bbc.co.uk"), L.parents("a.b.example.com.tr"), L.parents("сайт.рф"),
];
out.lines = [
  L.ruleLine({name: "googlevideo.com", exit: "vpn"}),
  L.ruleLine({name: "t.me", exit: "vpn", strict: true, scope: "only", list: "tv"}),
  L.ruleLine({name: "x.example", exit: "direct", strict: true, scope: "except", list: "office"}),
  L.ruleLine({name: "ads.example", exit: "none", strict: true}),
];
out.appended = [L.appendRule("", "a -> vpn"), L.appendRule("x\n", "a -> vpn"), L.appendRule("x", "a -> vpn"), L.appendRule("x\n\n\n", "a -> vpn")];
const rows = [
  {name: "www.youtube.com", client: "192.168.1.94", device: "Desktop"},
  {name: "t.me", client: "192.168.1.61", device: "Pixel"},
  {name: "i.ytimg.com", client: "192.168.1.94"},
];
out.filtered = [
  L.filter(rows, "", "").length, L.filter(rows, "YouTube", "").length, L.filter(rows, "y", "192.168.1.94").length,
  L.filter(rows, "", "192.168.1.61").length, L.filter(rows, "t.me", "192.168.1.94").length,
];
process.stdout.write(JSON.stringify(out));`
	b, err := exec.Command(node(t), "-e", script).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var got struct {
		Parents  [][]string
		Lines    []string
		Appended []string
		Filtered []int
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	wantParents := `[[googlevideo.com] [youtube.com] [] [bbc.co.uk] [b.example.com.tr example.com.tr] []]`
	if fmt.Sprint(got.Parents) != wantParents {
		t.Errorf("parents %v\nwant    %s", got.Parents, wantParents)
	}
	wantLines := []string{"googlevideo.com -> vpn", "t.me -> vpn strict for tv", "x.example -> direct for !office", "ads.example -> none"}
	if fmt.Sprint(got.Lines) != fmt.Sprint(wantLines) {
		t.Errorf("lines %q, want %q", got.Lines, wantLines)
	}
	wantAppended := []string{"a -> vpn\n", "x\na -> vpn\n", "x\na -> vpn\n", "x\na -> vpn\n"}
	if fmt.Sprint(got.Appended) != fmt.Sprint(wantAppended) {
		t.Errorf("appended %q, want %q", got.Appended, wantAppended)
	}
	if fmt.Sprint(got.Filtered) != "[3 1 2 1 0]" {
		t.Errorf("filtered %v", got.Filtered)
	}
}
