package checktest

// Replays of testdata/python.json: per case the recorded SSH / stream outputs and trivy reports, the module runs
// and what the Python module did with them (findings, written files as digests, logs, SSH and trivy calls).

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// Entry: a recorded answer — the text, a file under testdata, or an error.
type Entry struct {
	File *string `json:"file"`
	Text string  `json:"text"`
	Err  *string `json:"err"`
}

// ReplayRun: one module run of a case (Host nil for org-level modules).
type ReplayRun struct {
	Host  map[string]any `json:"host"`
	Cfg   map[string]any `json:"cfg"`
	Facts check.Facts    `json:"facts"`
	Env   string         `json:"env"`
}

// ReplayResult: what the Python module returned for a run.
type ReplayResult struct {
	Findings []finding.Finding `json:"findings"`
	Error    *string           `json:"error"`
}

// Replay: one case of testdata/python.json.
type Replay struct {
	Name       string            `json:"name"`
	Runs       []ReplayRun       `json:"runs"`
	SSH        map[string]Entry  `json:"ssh"`
	Stream     map[string]Entry  `json:"stream"`
	Trivy      map[string]Entry  `json:"trivy"`
	Results    []ReplayResult    `json:"results"`
	Files      map[string]string `json:"files"`
	Logs       []string          `json:"logs"`
	Calls      []any             `json:"calls"`
	TrivyCalls []any             `json:"trivy_calls"`
}

var uuidRE = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// Norm replaces temp paths with tokens and UUIDs with "UUID", as the recording did.
type Norm struct{ Roots [][2]string }

// S normalizes a string.
func (n *Norm) S(s string) string {
	for _, r := range n.Roots {
		s = strings.ReplaceAll(s, r[0], r[1])
	}
	return uuidRE.ReplaceAllString(s, "UUID")
}

// P normalizes a local path argument: S, and the OS's separators as the recordings have them (made on Unix).
func (n *Norm) P(s string) string { return filepath.ToSlash(n.S(s)) }

// Digest: sha256 of data, normalized first when it is text.
func (n *Norm) Digest(data []byte) string {
	if utf8.Valid(data) {
		data = []byte(n.S(string(data)))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func gunzip(data []byte) []byte {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		panic(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		panic(err)
	}
	return out
}

func gzipBytes(data []byte) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return b.Bytes()
}

// listing: rel path -> digest; symlinks "-> target"; directories "rel/" -> "dir".
func listing(root string, n *Norm) map[string]string {
	out := map[string]string{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == root {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel) // the recordings were made on Unix
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			out[rel] = "-> " + l
		case d.IsDir():
			out[rel+"/"] = "dir"
		default:
			data, _ := os.ReadFile(p)
			if strings.HasSuffix(p, ".gz") {
				data = gunzip(data)
			}
			out[rel] = n.Digest(data)
		}
		return nil
	})
	return out
}

// FakeSSH answers commands from the case's ssh / stream tables (Here: the testdata dir their files are in) and
// records the calls.
type FakeSSH struct {
	Here  string
	Case  *Replay
	mu    sync.Mutex
	calls []any
}

func (f *FakeSSH) entry(table map[string]Entry, command string) ([]byte, error) {
	e, ok := table[command]
	if !ok {
		return nil, fmt.Errorf("unexpected command: %s", command)
	}
	if e.Err != nil {
		return nil, errors.New(*e.Err)
	}
	if e.File != nil {
		return os.ReadFile(filepath.Join(f.Here, *e.File))
	}
	return []byte(e.Text), nil
}

func (f *FakeSSH) Run(_ context.Context, h config.Host, command string, timeout time.Duration, check bool) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, []any{"run", h.Name, command, int(timeout.Seconds()), check})
	f.mu.Unlock()
	b, err := f.entry(f.Case.SSH, command)
	return string(b), err
}

func (f *FakeSSH) Stream(_ context.Context, h config.Host, command string, w io.Writer, maxBytes int64,
	timeout time.Duration, _ func(mb int64)) (int64, error) {
	f.mu.Lock()
	f.calls = append(f.calls, []any{"stream", h.Name, command, maxBytes, int(timeout.Seconds())})
	f.mu.Unlock()
	b, err := f.entry(f.Case.Stream, command)
	if err != nil {
		return 0, err
	}
	if int64(len(b)) > maxBytes {
		_, _ = w.Write(b[:maxBytes])
		return maxBytes, fmt.Errorf("%s: output exceeds %d MB, aborted", h.Name, maxBytes>>20)
	}
	n, err := w.Write(b)
	return int64(n), err
}

// TrivyFunc: the signature of the modules' trivyRun hook.
type TrivyFunc = func(ctx context.Context, args []string, output string, timeout time.Duration) ([]byte, error)

// FakeTrivy serves the case's recorded reports by output file name and records each call with a digest of its
// target (files, or a listing of a staged directory).
func FakeTrivy(here string, c *Replay, n *Norm, calls *[]any) TrivyFunc {
	return func(_ context.Context, args []string, output string, timeout time.Duration) ([]byte, error) {
		target := map[string]any{}
		stage := ""
		for _, a := range args {
			st, err := os.Stat(a)
			if !filepath.IsAbs(a) || err != nil || n.S(a) == a {
				continue
			}
			if st.IsDir() {
				target[n.P(a)] = listing(a, n)
				stage = a
			} else {
				data, _ := os.ReadFile(a)
				target[n.P(a)] = n.Digest(data)
			}
		}
		normArgs := make([]any, len(args))
		for i, a := range args {
			normArgs[i] = n.P(a)
		}
		*calls = append(*calls, map[string]any{"args": normArgs, "output": n.P(output),
			"timeout": int(timeout.Seconds()), "target": target})
		e, ok := c.Trivy[filepath.Base(output)]
		if !ok {
			return nil, &trivy.Error{Msg: fmt.Sprintf("trivy %s: no recorded report for %s", args[0], filepath.Base(output))}
		}
		if e.Err != nil {
			return nil, &trivy.Error{Msg: *e.Err}
		}
		raw, err := os.ReadFile(filepath.Join(here, *e.File))
		if err != nil {
			return nil, err
		}
		text := gunzip(raw)
		if stage != "" {
			text = bytes.ReplaceAll(text, []byte("@STAGE@"), []byte(stage))
		}
		if err := os.WriteFile(output+".gz", gzipBytes(text), 0o644); err != nil {
			return nil, err
		}
		if len(text) == 0 {
			text = []byte("{}")
		}
		return text, nil
	}
}

// HostOf: the host a run spec describes, with the defaults the recording used.
func HostOf(spec map[string]any) config.Host {
	str := func(k, def string) string {
		if v, ok := spec[k].(string); ok {
			return v
		}
		return def
	}
	exp := 2
	if v, ok := spec["exposure"].(float64); ok {
		exp = int(v)
	}
	return config.Host{Org: str("org", "acme"), Env: str("env", "production"), Name: str("name", ""),
		Group: str("group", "g"), Role: str("role", "app"), Address: "192.0.2.1", Port: 22, User: "audit",
		Exposure: exp, Privilege: str("privilege", "none")}
}

// asJSON: v through JSON, for comparing values decoded from Python with Go ones.
func asJSON(t testing.TB, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// LoadReplays reads the cases of testdata/python.json.
func LoadReplays(t testing.TB) []Replay {
	t.Helper()
	b, err := os.ReadFile("testdata/python.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Cases []Replay `json:"cases"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g.Cases
}

var timing = regexp.MustCompile(`\(\d+s\)`)

// RunReplay replays c: setTrivy installs the fake trivy and returns a restore func; call runs one module run; roots:
// more (path, token) normalizations.
func RunReplay(t testing.TB, c *Replay, org *config.Org, setTrivy func(TrivyFunc) func(),
	call func(ctx *check.Ctx, r ReplayRun, out string) ([]finding.Finding, error), roots ...[2]string) {
	t.Helper()
	here, _ := filepath.Abs("testdata")
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n := &Norm{Roots: append([][2]string{{tmp, "$OUT"}}, roots...)}
	var logs []string
	var mu sync.Mutex
	ssh := &FakeSSH{Here: here, Case: c, calls: []any{}}
	ctx := &check.Ctx{Context: context.Background(), Org: org, SSH: ssh, RunDir: tmp, Log: func(format string, args ...any) {
		mu.Lock()
		logs = append(logs, n.S(fmt.Sprintf(format, args...)))
		mu.Unlock()
	}}
	tcalls := []any{}
	defer setTrivy(FakeTrivy(here, c, n, &tcalls))()
	for i, r := range c.Runs {
		name := "org"
		if r.Host != nil {
			name, _ = r.Host["name"].(string)
		}
		out := filepath.Join(tmp, "hosts", name)
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Fatal(err)
		}
		got, err := call(ctx, r, out)
		want := c.Results[i]
		if want.Error != nil || err != nil {
			if want.Error == nil || err == nil || n.S(err.Error()) != *want.Error {
				t.Errorf("%s[%d]: error %v, want %v", c.Name, i, err, strOr(want.Error))
			}
			continue
		}
		var gotN []finding.Finding
		b, _ := json.Marshal(got)
		if err := json.Unmarshal([]byte(n.S(string(b))), &gotN); err != nil {
			t.Fatal(err)
		}
		if len(gotN) != len(want.Findings) {
			t.Errorf("%s[%d]: %d findings, want %d", c.Name, i, len(gotN), len(want.Findings))
		}
		bad := 0
		for j := range min(len(gotN), len(want.Findings)) {
			if g, w := asJSON(t, gotN[j]), asJSON(t, want.Findings[j]); !reflect.DeepEqual(g, w) && bad < 5 {
				bad++
				gb, _ := json.Marshal(g)
				wb, _ := json.Marshal(w)
				t.Errorf("%s[%d]: finding %d:\n got %s\nwant %s", c.Name, i, j, gb, wb)
			}
		}
	}
	if files := listing(tmp, n); !reflect.DeepEqual(files, c.Files) && !(len(files) == 0 && len(c.Files) == 0) {
		t.Errorf("%s: files\n got %v\nwant %v", c.Name, files, c.Files)
	}
	norml := func(l []string) []string {
		out := make([]string, len(l))
		for i, s := range l {
			out[i] = timing.ReplaceAllString(s, "(Ns)")
		}
		return out
	}
	if g, w := norml(logs), norml(c.Logs); !slices.Equal(g, w) && !(len(g) == 0 && len(w) == 0) {
		t.Errorf("%s: logs\n got %q\nwant %q", c.Name, g, w)
	}
	for i := range ssh.calls {
		call := ssh.calls[i].([]any)
		call[2] = n.S(call[2].(string))
	}
	if g, w := asJSON(t, ssh.calls), asJSON(t, c.Calls); !reflect.DeepEqual(g, w) {
		t.Errorf("%s: ssh calls\n got %v\nwant %v", c.Name, g, w)
	}
	if g, w := asJSON(t, tcalls), asJSON(t, c.TrivyCalls); !reflect.DeepEqual(g, w) {
		t.Errorf("%s: trivy calls\n got %v\nwant %v", c.Name, g, w)
	}
}

func strOr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
