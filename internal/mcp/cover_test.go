package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
	"github.com/mikekosulin/kanareika/internal/report"
)

// fixtureHome: a private copy of the fixture home, free to break.
func fixtureHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.CopyFS(home, os.DirFS(filepath.Join(fixture, "home"))); err != nil {
		t.Fatal(err)
	}
	return home
}

func newTestServer(home string) (*Server, *bytes.Buffer) {
	s := NewServer(config.PathsAt(home), "1.0.0")
	log := &bytes.Buffer{}
	s.Log = log
	return s, log
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// tcall runs a tools/call through Handle and returns the text of the result and whether it is a tool error.
func tcall(t *testing.T, s *Server, name string, a map[string]any) (string, bool) {
	t.Helper()
	req, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": a}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := pyfmt.Marshal(s.Handle(req))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Result struct {
			Content []struct{ Text string }
			IsError bool
		}
	}
	if err := json.Unmarshal(b, &r); err != nil || len(r.Result.Content) != 1 {
		t.Fatalf("%s: unexpected response %s", name, b)
	}
	return r.Result.Content[0].Text, r.Result.IsError
}

func wantToolError(t *testing.T, s *Server, name string, a map[string]any, contains string) {
	t.Helper()
	text, isErr := tcall(t, s, name, a)
	if !isErr || !strings.HasPrefix(text, "Error: ") || !strings.Contains(text, contains) {
		t.Errorf("%s %v: got %q (isError %v), want an error containing %q", name, a, text, isErr, contains)
	}
}

func TestToolArgumentErrors(t *testing.T) {
	s, _ := newTestServer(fixtureHome(t))
	nope := map[string]any{"org": "nope"}
	for _, name := range []string{"list_actions", "get_host", "search_packages", "fix_prompt", "fix_plan"} {
		wantToolError(t, s, name, nope, "no organization 'nope'. Known: acme, beta")
	}
	wantToolError(t, s, "list_actions", map[string]any{"org": "acme", "env": "production", "limit": "many"}, "invalid limit: many")
	wantToolError(t, s, "search_packages", map[string]any{"org": "acme", "env": "production", "query": "linux", "limit": "1.5"},
		"invalid limit: 1.5")
	// a configured host of an environment that has never been scanned
	wantToolError(t, s, "get_host", map[string]any{"org": "acme", "env": "dr", "host": "dr-01"}, "no runs")
}

func TestBrokenPolicyIsReportedNotFatal(t *testing.T) {
	home := fixtureHome(t)
	writeFile(t, filepath.Join(home, "policy", "profiles.yml"), "default: [\n")
	s, _ := newTestServer(home)
	text, isErr := tcall(t, s, "list_orgs", map[string]any{})
	if isErr {
		t.Fatal(text)
	}
	var o struct {
		Orgs   []any
		Errors []string
	}
	if err := json.Unmarshal([]byte(text), &o); err != nil {
		t.Fatal(err)
	}
	if len(o.Orgs) != 0 || len(o.Errors) != 1 || !strings.Contains(o.Errors[0], "profiles.yml") {
		t.Fatalf("got %s", text)
	}
	wantToolError(t, s, "get_summary", map[string]any{"org": "acme"}, "no organization 'acme'. Known: ")
}

func TestRunStates(t *testing.T) {
	home := fixtureHome(t)
	env := filepath.Join(home, "reports", "acme", "production")
	writeFile(t, filepath.Join(env, "2026-11-03_000000", "run.json"), "{broken")
	writeFile(t, filepath.Join(env, "2026-11-03_010000", "status.json"), `{"state": "running", "updated": "2026-11-02T09:00:00Z"}`)
	writeFile(t, filepath.Join(env, "2026-11-03_020000", "status.json"), `{"state": "running", "updated": "not a time"}`)
	writeFile(t, filepath.Join(env, "2026-11-03_030000", "run.json"), `{"started": "2026-11-02T10:00:00Z", "finished": "2026-11-02T10:04:00Z"}`)
	writeFile(t, filepath.Join(env, "2026-11-03_030000", "status.json"), `{"state": "running", "updated": "2026-11-02T10:05:20Z"}`)
	s, _ := newTestServer(home)
	text, isErr := tcall(t, s, "list_runs", map[string]any{"org": "acme", "env": "production"})
	if isErr {
		t.Fatal(text)
	}
	var runs []Run
	if err := json.Unmarshal([]byte(text), &runs); err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, r := range runs {
		states[r.RunID] = r.State
	}
	if _, ok := states["2026-11-03_000000"]; ok {
		t.Error("a run with a broken run.json and no status is listed")
	}
	for id, want := range map[string]string{"2026-11-03_010000": "stale", "2026-11-03_020000": "stale", "2026-11-03_030000": "done"} {
		if states[id] != want {
			t.Errorf("%s: state %q, want %q", id, states[id], want)
		}
	}

	// an environment without a reports directory has no runs
	if err := os.RemoveAll(filepath.Join(home, "reports", "acme", "dr")); err != nil {
		t.Fatal(err)
	}
	if text, isErr := tcall(t, s, "list_runs", map[string]any{"org": "acme", "env": "dr"}); isErr || text != "[]" {
		t.Fatalf("dr runs: %q (isError %v)", text, isErr)
	}
}

func TestCurrentErrors(t *testing.T) {
	staging := map[string]any{"org": "acme", "env": "staging"}

	t.Run("broken current run.json", func(t *testing.T) {
		home := fixtureHome(t)
		writeFile(t, filepath.Join(home, "reports", "acme", "staging", "current", "run.json"), "{broken")
		s, _ := newTestServer(home)
		wantToolError(t, s, "get_summary", staging, "invalid character")
	})

	// while a scan holds the environment, the existing snapshot is read as is
	busy := func(t *testing.T, home string) {
		l, err := report.EnvLock(filepath.Join(home, "reports", "acme", "staging"), false)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Unlock() })
	}
	t.Run("view.json is a directory", func(t *testing.T) {
		home := fixtureHome(t)
		view := filepath.Join(home, "reports", "acme", "staging", "current", "view.json")
		if err := os.Remove(view); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(view, 0o755); err != nil {
			t.Fatal(err)
		}
		busy(t, home)
		s, _ := newTestServer(home)
		wantToolError(t, s, "get_summary", staging, "is a directory")
	})
	t.Run("broken view.json", func(t *testing.T) {
		home := fixtureHome(t)
		writeFile(t, filepath.Join(home, "reports", "acme", "staging", "current", "view.json"), `{"version": 11, "meta": [`)
		busy(t, home)
		s, _ := newTestServer(home)
		wantToolError(t, s, "get_summary", staging, "unexpected EOF")
	})
	t.Run("snapshot gone after the update", func(t *testing.T) {
		gone := filepath.Join(t.TempDir(), "current")
		orig := updateCurrent
		updateCurrent = func(string, bool, bool) (string, error) { return gone, nil }
		t.Cleanup(func() { updateCurrent = orig })
		s, _ := newTestServer(fixtureHome(t))
		wantToolError(t, s, "get_summary", staging, "view.json")
	})
}

// editView rewrites current/view.json of an environment; the version stays, so the view is used as stored.
func editView(t *testing.T, home, env string, edit func(v map[string]any)) {
	t.Helper()
	path := filepath.Join(home, "reports", "acme", env, "current", "view.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v map[string]any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	edit(v)
	if b, err = json.Marshal(v); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(b))
}

func TestViewEdgeData(t *testing.T) {
	home := fixtureHome(t)
	var id string
	editView(t, home, "production", func(v map[string]any) {
		a := v["actions"].([]any)[0].(map[string]any)
		id = a["id"].(string)
		delete(a, "priority") // an action without a priority is a background one
		p := v["plan"].([]any)[0].(map[string]any)
		p["cve_top"] = nil
	})
	s, _ := newTestServer(home)

	text, isErr := tcall(t, s, "list_actions", map[string]any{"org": "acme", "env": "production", "priority": []any{"P4"}})
	if isErr {
		t.Fatal(text)
	}
	var acts struct {
		Total   int
		Actions []map[string]any
	}
	if err := json.Unmarshal([]byte(text), &acts); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range acts.Actions {
		if a["id"] == id {
			found = true
			if _, has := a["priority"]; has {
				t.Errorf("action without priority shows one: %v", a)
			}
		}
	}
	if !found {
		t.Errorf("action %s without priority is not among P4: %s", id, text)
	}

	text, isErr = tcall(t, s, "search_packages", map[string]any{"org": "acme", "env": "production", "query": "linux-image", "host": "web-01"})
	if isErr {
		t.Fatal(text)
	}
	var pk struct{ Packages []map[string]any }
	if err := json.Unmarshal([]byte(text), &pk); err != nil {
		t.Fatal(err)
	}
	if len(pk.Packages) == 0 {
		t.Fatalf("no packages: %s", text)
	}
	if l, ok := pk.Packages[0]["cve_top"].([]any); !ok || len(l) != 0 {
		t.Errorf("cve_top of a row without one: %#v, want []", pk.Packages[0]["cve_top"])
	}
}

func TestCallTurnsFailuresIntoToolErrors(t *testing.T) {
	s, _ := newTestServer(t.TempDir())
	text := func(o any) (string, bool) {
		m := o.(pyfmt.Obj)
		c := m.Get("content").([]any)[0].(pyfmt.Obj)
		isErr, _ := m.Get("isError").(bool)
		return c.Get("text").(string), isErr
	}
	got, isErr := text(s.call(func(args) (any, error) { panic("index out of range") }, args{}))
	if !isErr || got != "Error: index out of range" {
		t.Errorf("panic: %q %v", got, isErr)
	}
	got, isErr = text(s.call(func(args) (any, error) { return make(chan int), nil }, args{}))
	if !isErr || !strings.Contains(got, "unsupported type") {
		t.Errorf("unmarshalable result: %q %v", got, isErr)
	}
}

func TestParamsNotAnObject(t *testing.T) {
	s, log := newTestServer(t.TempDir())
	b, err := pyfmt.MarshalLine(s.Handle([]byte(`{"jsonrpc": "2.0", "id": 7, "method": "ping", "params": [1]}`)), false)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}}`; string(b) != want {
		t.Errorf("got %s, want %s", b, want)
	}
	if !strings.Contains(log.String(), "mcp: params: ") {
		t.Errorf("log: %q", log.String())
	}
}

var errSink = errors.New("sink closed")

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errSink }

func TestServeWriteErrors(t *testing.T) {
	s, _ := newTestServer(t.TempDir())
	// a short response stays in the buffer and fails on flush; tools/list is larger than the buffer and fails on write
	for _, method := range []string{"ping", "tools/list"} {
		in := strings.NewReader(`{"jsonrpc": "2.0", "id": 1, "method": "` + method + `"}` + "\n")
		if err := s.Serve(context.Background(), in, failWriter{}); !errors.Is(err, errSink) {
			t.Errorf("%s: %v, want %v", method, err, errSink)
		}
	}
}

// blockWriter blocks the first write until released, then fails it.
type blockWriter struct {
	entered, release chan struct{}
}

func (w blockWriter) Write([]byte) (int, error) {
	close(w.entered)
	<-w.release
	return 0, errSink
}

func TestServeReaderStopsOnContext(t *testing.T) {
	base := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	defer pw.Close()
	out := blockWriter{make(chan struct{}), make(chan struct{})}
	done := make(chan error)
	go func() { done <- NewServer(config.PathsAt(t.TempDir()), "x").Serve(ctx, pr, out) }()
	ping := []byte(`{"jsonrpc": "2.0", "id": 1, "method": "ping"}` + "\n")
	if _, err := pw.Write(ping); err != nil {
		t.Fatal(err)
	}
	<-out.entered // the answer to the first request is being written: nobody takes the next line
	if _, err := pw.Write(ping); err != nil {
		t.Fatal(err)
	}
	cancel() // the reader gives up the line it holds
	close(out.release)
	if err := <-done; !errors.Is(err, errSink) {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			t.Fatal("the reader goroutine did not stop")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestServeEntryPoint(t *testing.T) {
	var out bytes.Buffer
	in := strings.NewReader("\n" + `{"jsonrpc": "2.0", "id": "a", "method": "initialize", "params": {}}` + "\n")
	if err := Serve(context.Background(), in, &out, config.PathsAt(t.TempDir()), "9.9.9"); err != nil {
		t.Fatal(err)
	}
	var r struct {
		ID     string
		Result struct {
			ProtocolVersion string
			ServerInfo      struct{ Name, Version string }
		}
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.ID != "a" || r.Result.ProtocolVersion != DefaultProtocol || r.Result.ServerInfo.Version != "9.9.9" {
		t.Errorf("got %s", out.String())
	}
}

func TestLooseHelpers(t *testing.T) {
	if o := action(&report.Action{}, "en"); o == nil || len(o) != 0 {
		t.Errorf("empty action: %#v, want an empty object", o)
	}
	if deref(nil) != "" {
		t.Error("deref(nil)")
	}
	for _, c := range []struct {
		in   any
		want float64
		ok   bool
	}{
		{2.5, 2.5, true}, {7, 7, true}, {json.Number("3"), 3, true}, {" 12 ", 12, true}, {"1.5", 1, false},
		{true, 0, false}, {nil, 0, false},
	} {
		if f, ok := num(c.in); f != c.want || ok != c.ok {
			t.Errorf("num(%#v) = %v, %v; want %v, %v", c.in, f, ok, c.want, c.ok)
		}
	}
}
