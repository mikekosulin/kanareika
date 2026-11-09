package checktest

// Case-directory goldens: testdata/<case>/case.json, the command outputs it replays (raw.txt, ...) and golden/ with
// what the Python module produced from them: findings.json, calls.json, log.txt, error.txt and every file it wrote.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
)

// Call: one command the module ran.
type Call struct {
	Command string `json:"command"`
	Timeout int    `json:"timeout"`
	Check   bool   `json:"check"`
}

// Runner returns recorded outputs in call order and records the calls (a check.Runner).
type Runner struct {
	Outputs []string
	Calls   []Call
}

func (r *Runner) Run(_ context.Context, _ config.Host, command string, timeout time.Duration, chk bool) (string, error) {
	r.Calls = append(r.Calls, Call{command, int(timeout / time.Second), chk})
	if len(r.Calls) > len(r.Outputs) {
		return "", fmt.Errorf("unexpected call %d: %s", len(r.Calls), command)
	}
	return r.Outputs[len(r.Calls)-1], nil
}

func (r *Runner) Stream(context.Context, config.Host, string, io.Writer, int64, time.Duration, func(int64)) (int64, error) {
	return 0, fmt.Errorf("not recorded")
}

// Case: case.json.
type Case struct {
	Dir  string
	Host struct {
		Org, Name, Group, Address, User, Privilege string
		Exposure                                   int
	} `json:"host"`
	ScannerTS *float64 `json:"scanner_ts"`
	Now       string   `json:"now"`
}

func (c Case) ConfigHost() config.Host {
	h := c.Host
	return config.Host{Org: h.Org, Name: h.Name, Group: h.Group, Address: h.Address, User: h.User,
		Privilege: h.Privilege, Exposure: h.Exposure}
}

// NowTime: the pinned local clock ("now" as naive wall time).
func (c Case) NowTime(t testing.TB) time.Time {
	n, err := time.Parse("2006-01-02T15:04:05", c.Now)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Cases: every testdata/<case> of the calling package.
func Cases(t testing.TB) []Case {
	dirs, err := filepath.Glob("testdata/*/case.json")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no cases: %v", err)
	}
	var out []Case
	for _, p := range dirs {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		c := Case{Dir: filepath.Dir(p)}
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// Read a case file, transparently from <name>.gz.
func Read(t testing.TB, path string) string {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		f, err2 := os.Open(path + ".gz")
		if err2 != nil {
			t.Fatal(err)
		}
		defer f.Close()
		z, err2 := gzip.NewReader(f)
		if err2 != nil {
			t.Fatal(err2)
		}
		b, err = io.ReadAll(z)
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Org from testdata/org.json (nil without one), as the Python harness built it.
func Org(t testing.TB) *config.Org {
	b, err := os.ReadFile("testdata/org.json")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		ID    string
		Hosts []struct{ Name, Address, Env string }
		Jumps map[string]any
		Ext   map[string]any `json:"external"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	o := &config.Org{ID: d.ID, Data: map[string]any{"access": map[string]any{"jumps": d.Jumps}, "external": d.Ext}}
	for _, h := range d.Hosts {
		o.Hosts = append(o.Hosts, config.Host{Name: h.Name, Address: h.Address, Env: h.Env})
	}
	return o
}

// Module runs one check on a case.
type Module func(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, facts check.Facts) ([]finding.Finding, error)

// Check runs mod on case c with the recorded inputs (file names in call order) and compares findings, the files it
// wrote, its log and the commands it ran with the Python goldens.
func Check(t testing.TB, c Case, mod Module, inputs ...string) {
	t.Helper()
	r := &Runner{}
	for _, in := range inputs {
		r.Outputs = append(r.Outputs, Read(t, filepath.Join(c.Dir, in)))
	}
	var logs []string
	ctx := &check.Ctx{Context: context.Background(), Org: Org(t), SSH: r, RunDir: t.TempDir(),
		Log: func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }}
	out := t.TempDir()
	gold := filepath.Join(c.Dir, "golden")
	f, err := mod(ctx, c.ConfigHost(), map[string]any{}, out, check.Facts{})

	if want, e := os.ReadFile(filepath.Join(gold, "error.txt")); e == nil {
		if err == nil || err.Error() != UpgradeError(c.ConfigHost(), string(want)) {
			t.Fatalf("error: got %v, want %q", err, want)
		}
	} else {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		CompareFindings(t, f, upgradeFindings(c.ConfigHost(), Read(t, filepath.Join(gold, "findings.json"))))
	}

	var calls []Call
	if err := json.Unmarshal([]byte(Read(t, filepath.Join(gold, "calls.json"))), &calls); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Calls, calls) {
		t.Errorf("calls differ:\n got %+v\nwant %+v", r.Calls, calls)
	}
	if got, want := strings.Join(logs, "\n"), UpgradeLog(Read(t, filepath.Join(gold, "log.txt"))); got != want {
		t.Errorf("log:\n got %q\nwant %q", got, want)
	}

	// every file the Python module wrote, byte for byte, and nothing more
	entries, _ := os.ReadDir(gold)
	wantFiles := map[string]bool{}
	for _, e := range entries {
		switch e.Name() {
		case "findings.json", "calls.json", "log.txt", "error.txt":
			continue
		}
		wantFiles[e.Name()] = true
		got, err := os.ReadFile(filepath.Join(out, e.Name()))
		if err != nil {
			t.Errorf("%s not written: %v", e.Name(), err)
			continue
		}
		want := Read(t, filepath.Join(gold, e.Name()))
		if string(got) != want {
			t.Errorf("%s differs: %s", e.Name(), firstDiff(string(got), want))
		}
	}
	written, _ := os.ReadDir(out)
	for _, e := range written {
		if !wantFiles[e.Name()] {
			t.Errorf("extra file %s", e.Name())
		}
	}
}

func firstDiff(got, want string) string {
	n := min(len(got), len(want))
	i := 0
	for i < n && got[i] == want[i] {
		i++
	}
	lo := max(0, i-200)
	return fmt.Sprintf("at byte %d (len got %d, want %d)\n got …%q…\nwant …%q…", i, len(got), len(want),
		got[lo:min(len(got), i+200)], want[lo:min(len(want), i+200)])
}

// goOnly: fields the Go finding always has and the Python module dicts did not (prioritization fills them later).
var goOnly = []string{"kev", "epss", "priority", "due", "accepted", "exception"}

// advisoryOnly: fields added in 0.5 (advisory facts from trivy.VulnFindings, the k8s workload's image, an OS
// package's source package); fixtures recorded before them have none. A fixture that has one of them is compared
// on it as usual.
var advisoryOnly = []string{"published", "cvss_score", "description", "image", "src_pkg"}

// DropAdvisory removes from got the advisory facts that want does not have.
func DropAdvisory(got, want map[string]any) {
	for _, k := range advisoryOnly {
		if _, ok := want[k]; !ok {
			delete(got, k)
		}
	}
}

// CompareFindings: same findings in the same order, field by field as JSON. Python's empty "args": {} and the Go
// zero-valued prioritization fields are not differences (encoding/json omits empty maps; the report layer sets
// the rest).
func CompareFindings(t testing.TB, got []finding.Finding, wantJSON string) {
	t.Helper()
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var g, w []map[string]any
	_ = json.Unmarshal(b, &g) // b is json.Marshal of findings: always a valid array of objects, never an error here
	if err := json.Unmarshal([]byte(wantJSON), &w); err != nil {
		t.Fatal(err)
	}
	if len(g) != len(w) {
		t.Errorf("findings: got %d, want %d", len(g), len(w))
	}
	for i := range min(len(g), len(w)) {
		DropAdvisory(g[i], w[i])
		for _, k := range goOnly {
			if _, ok := w[i][k]; !ok {
				switch v := g[i][k]; v {
				case nil, false:
					delete(g[i], k)
				}
			}
		}
		for _, k := range []string{"args", "target_args"} {
			if m, ok := w[i][k].(map[string]any); ok && len(m) == 0 {
				if _, ok := g[i][k]; !ok {
					delete(w[i], k)
				}
			}
		}
		if !reflect.DeepEqual(g[i], w[i]) {
			t.Errorf("finding %d:\n got %s\nwant %s", i, canon(g[i]), canon(w[i]))
		}
	}
}

func canon(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for _, k := range keys {
		v, _ := json.Marshal(m[k])
		fmt.Fprintf(&b, "%s=%s ", k, v)
	}
	return b.String()
}
