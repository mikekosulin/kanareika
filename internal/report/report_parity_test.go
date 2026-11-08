package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// Parity with the former Python implementation: testdata/fixture holds a small synthetic environment and the
// goldens Python computed from it. Recorded once with the former Python implementation (removed from the repo; the
// Go port had to match it) and kept as a frozen fixture: a change here is a behaviour change — review it as such.

func TestFixtureParity(t *testing.T) { checkParity(t, "testdata/fixture") }

func checkParity(t *testing.T, root string) {
	envs, err := os.ReadDir(filepath.Join(root, "env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range envs {
		env := filepath.Join(root, "env", e.Name())
		gold := filepath.Join(root, "golden", e.Name())
		for _, run := range runDirs(env) {
			t.Run(e.Name()+"/"+filepath.Base(run), func(t *testing.T) { checkRun(t, run, filepath.Join(gold, filepath.Base(run))) })
		}
		t.Run(e.Name()+"/current", func(t *testing.T) { checkCurrent(t, env, filepath.Join(gold, Current)) })
	}
}

func checkRun(t *testing.T, run, gold string) {
	meta, findings, err := LoadRun(run)
	if err != nil {
		t.Fatal(err)
	}
	var prev *Prev
	if !IsPartial(meta) {
		if prev, err = PreviousRun(run, true); err != nil {
			t.Fatal(err)
		}
	}
	view := BuildView(run, meta, findings, prev)
	sameJSON(t, "view", readFile(t, filepath.Join(gold, "view.json")), mustJSON(t, view))

	if got, want := Summary(meta, findings), string(readFile(t, filepath.Join(gold, "summary.md"))); got != want {
		t.Errorf("summary.md differs:\n%s", firstDiff(got, want))
	}
	sameJSON(t, "counts", readFile(t, filepath.Join(gold, "counts.json")), mustJSON(t, CountsOf(findings)))
	sameJSON(t, "patch_plan", readFile(t, filepath.Join(gold, "plan.json")), mustJSON(t, planJSON(PatchPlan(findings))))

	var want struct {
		Prev string     `json:"prev"`
		New  [][]string `json:"new"`
		Gone [][]string `json:"gone"`
	}
	b := readFile(t, filepath.Join(gold, "diff.json"))
	if string(b) == "null" {
		if prev != nil {
			t.Errorf("diff: Python had no previous run, Go has %s", prev.ID)
		}
		return
	}
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if prev == nil || prev.ID != want.Prev {
		t.Fatalf("previous run: want %s, got %+v", want.Prev, prev)
	}
	newF, gone := Diff(prev.Findings, findings, comparableHosts(meta, findings, prev))
	byKey := func(fs []finding.Finding) [][]string {
		out := [][]string{}
		for i := range fs {
			k := KeyOf(&fs[i])
			out = append(out, k[:])
		}
		return out
	}
	// Python orders ties of (priority, host, pkg, id) by set order: compare as sorted lists of keys
	if !sameKeys(want.New, byKey(newF)) || !sameKeys(want.Gone, byKey(gone)) {
		t.Errorf("diff differs: new %d/%d, gone %d/%d", len(newF), len(want.New), len(gone), len(want.Gone))
	}
}

// comparableHosts: hosts scanned successfully in both runs, plus org-level targets (as build_view computes it).
func comparableHosts(meta *Meta, findings []finding.Finding, prev *Prev) map[string]bool {
	ok := func(m *Meta) map[string]bool {
		s := map[string]bool{}
		for _, h := range m.HostsScanned {
			if !m.HostsFailed.Has(h) {
				s[h] = true
			}
		}
		return s
	}
	a, b := ok(meta), ok(prev.Meta)
	both := map[string]bool{}
	for h := range a {
		if b[h] {
			both[h] = true
		}
	}
	for _, fs := range [][]finding.Finding{findings, prev.Findings} {
		for i := range fs {
			if strings.Contains(fs[i].Host, ":") {
				both[fs[i].Host] = true
			}
		}
	}
	return both
}

func sameKeys(a, b [][]string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.SortFunc(a, slices.Compare)
	slices.SortFunc(b, slices.Compare)
	return slices.EqualFunc(a, b, slices.Equal)
}

func planJSON(p Plan) map[string]any {
	hosts := []string{}
	groups := map[string]any{}
	for _, h := range p {
		hosts = append(hosts, h.Host)
		var gs []map[string]any
		for _, g := range h.Groups {
			gs = append(gs, map[string]any{"host": g.Host, "target": g.Target, "pkg": g.Pkg, "installed": g.Installed,
				"fixed": sortedKeys(g.Fixed), "cves": sortedKeys(g.CVEs), "priority": g.Priority, "due": g.Due,
				"kev": g.KEV, "unfixed": g.Unfixed, "preauth_rce": g.PreauthRCE, "preauth": g.Preauth,
				"inactive": g.Inactive, "kernel": g.Kernel, "module": g.Module, "pending": g.Pending,
				"fix_state": optional(g.FixState), "repo_version": optional(g.RepoVersion)})
		}
		groups[h.Host] = gs
	}
	return map[string]any{"hosts": hosts, "groups": groups}
}

// optional: Python's patch_plan sets fix_state / repo_version only when known.
func optional(p *string) any {
	if p == nil {
		return absent{}
	}
	return *p
}

type absent struct{}

func checkCurrent(t *testing.T, env, gold string) {
	var steps [][]string
	if err := json.Unmarshal(readFile(t, filepath.Join(gold, "steps.json")), &steps); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(t.TempDir(), "env")
	var cur string
	for _, step := range steps {
		for _, r := range step {
			copyTree(t, filepath.Join(env, r), filepath.Join(work, r))
		}
		var err error
		if cur, err = UpdateCurrent(work, false, true); err != nil {
			t.Fatal(err)
		}
	}
	sameJSON(t, "current/run.json", readFile(t, filepath.Join(gold, "run.json")), readFile(t, filepath.Join(cur, "run.json")))
	sameJSON(t, "current/view.json", readFile(t, filepath.Join(gold, "view.json")), readFile(t, filepath.Join(cur, "view.json")))
	want, err := LoadFindings(gold)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadFindings(cur)
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, "current/findings", mustJSON(t, want), mustJSON(t, got))
}

// --- helpers ---------------------------------------------------------------------------------------------------

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	v = dropAbsent(v)
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dropAbsent(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if _, ok := e.(absent); !ok {
				out[k] = dropAbsent(e)
			}
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = dropAbsent(e)
		}
		return out
	}
	return v
}

// sameJSON compares semantically (numbers as float64: Python's 1.0 equals Go's 1) and reports the first paths
// that differ. Rows of "new" / "resolved" are compared ignoring the order of ties Python leaves to set order.
func sameJSON(t *testing.T, what string, want, got []byte) {
	t.Helper()
	var w, g any
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("%s: python: %v", what, err)
	}
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("%s: go: %v", what, err)
	}
	for _, v := range []any{w, g} {
		if m, ok := v.(map[string]any); ok {
			for _, k := range []string{"new", "resolved"} {
				if d, ok := m[k].(map[string]any); ok {
					d["rows"] = sortTies(d["rows"])
				}
			}
		}
	}
	sinceGo(g)
	var diffs []string
	walk("", w, g, &diffs)
	if len(diffs) > 0 {
		t.Errorf("%s differs (%d):\n  %s", what, len(diffs), strings.Join(diffs[:min(15, len(diffs))], "\n  "))
	}
}

func sortTies(v any) any {
	rows, _ := v.([]any)
	rank := func(r map[string]any) int { p, _ := r["priority"].(string); return prioRank(p) }
	str := func(r map[string]any, k string) string { s, _ := r[k].(string); return s }
	num := func(r map[string]any, k string) float64 { n, _ := r[k].(float64); return n }
	slices.SortStableFunc(rows, func(x, y any) int {
		a, b := x.(map[string]any), y.(map[string]any)
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		return cmp.Or(cmp.Compare(rank(a), rank(b)), cmp.Compare(num(b, "count"), num(a, "count")),
			cmp.Compare(str(a, "host"), str(b, "host")), cmp.Compare(str(a, "pkg"), str(b, "pkg")),
			strings.Compare(string(ja), string(jb)))
	})
	return rows
}

func walk(path string, w, g any, out *[]string) {
	if len(*out) > 50 {
		return
	}
	switch wv := w.(type) {
	case map[string]any:
		gv, ok := g.(map[string]any)
		if !ok {
			*out = append(*out, fmt.Sprintf("%s: want object, got %s", path, short(g)))
			return
		}
		for k, x := range wv {
			y, ok := gv[k]
			if !ok {
				*out = append(*out, fmt.Sprintf("%s.%s: missing in Go (want %s)", path, k, short(x)))
				continue
			}
			walk(path+"."+k, x, y, out)
		}
		for k, y := range gv {
			if _, ok := wv[k]; !ok {
				*out = append(*out, fmt.Sprintf("%s.%s: only in Go (%s)", path, k, short(y)))
			}
		}
	case []any:
		gv, ok := g.([]any)
		if !ok {
			*out = append(*out, fmt.Sprintf("%s: want list, got %s", path, short(g)))
			return
		}
		if len(wv) != len(gv) {
			*out = append(*out, fmt.Sprintf("%s: want %d items, got %d", path, len(wv), len(gv)))
		}
		for i := range min(len(wv), len(gv)) {
			walk(fmt.Sprintf("%s[%d]", path, i), wv[i], gv[i], out)
		}
	default:
		if !reflect.DeepEqual(w, g) {
			*out = append(*out, fmt.Sprintf("%s: want %s, got %s", path, short(w), short(g)))
		}
	}
}

func short(v any) string {
	b, _ := json.Marshal(v)
	if len(b) > 120 {
		return string(b[:120]) + "…"
	}
	return string(b)
}

func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := range max(len(g), len(w)) {
		var a, b string
		if i < len(g) {
			a = g[i]
		}
		if i < len(w) {
			b = w[i]
		}
		if a != b {
			return fmt.Sprintf("line %d\n  go:     %q\n  python: %q", i+1, a, b)
		}
	}
	return "(equal)"
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
}

// sinceGo drops what the Go views add to the Python ones: the message key and arguments of findings shown as
// rows (other, inventory, exceptions, new, resolved), so the interfaces render their titles in any language; and
// the totals (0.5: fixes to apply and unique CVEs, in view.json and run.json; TestTotalsAgree checks them).
func sinceGo(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	delete(m, "totals")
	if meta, ok := m["meta"].(map[string]any); ok {
		delete(meta, "totals")
	}
	var lists []any
	for _, k := range []string{"other", "inventory", "exceptions"} {
		lists = append(lists, m[k])
	}
	for _, k := range []string{"new", "resolved"} {
		if d, ok := m[k].(map[string]any); ok {
			lists = append(lists, d["rows"])
		}
	}
	for _, l := range lists {
		rows, _ := l.([]any)
		for _, r := range rows {
			if row, ok := r.(map[string]any); ok {
				delete(row, "msg")
				delete(row, "args")
			}
		}
	}
}
