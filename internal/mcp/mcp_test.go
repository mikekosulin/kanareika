package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/prompt"
	"github.com/mikekosulin/kanareika/internal/remediate"
)

// Parity with `kanareika mcp` of the former Python reference: golden/mcp.jsonl (requests) went through the Python
// server against the fixture home of package remediate (golden/mcp.out.jsonl, recorded then and frozen since); the
// Go server gets the same lines against a copy of that home and must answer the same, byte for byte. On a mismatch
// the JSON inside text results is compared as data too, to tell a real difference from key order or number
// formatting.

const fixture = "../remediate/testdata/fixture"

func TestMain(m *testing.M) {
	remediate.Now = func() time.Time { return time.Date(2026, 11, 2, 12, 34, 56, 0, time.Local) }
	// the fixture's running scans last reported at 10:05 UTC: half a minute later they are still running
	Now = func() time.Time { return time.Date(2026, 11, 2, 10, 5, 30, 0, time.UTC) }
	os.Exit(m.Run())
}

func TestFixtureParity(t *testing.T) { checkParity(t, fixture) }

func checkParity(t *testing.T, root string) {
	home := t.TempDir() // a copy: reading current/ takes the env lock (writes .lock)
	if err := os.CopyFS(home, os.DirFS(filepath.Join(root, "home"))); err != nil {
		t.Fatal(err)
	}
	in, err := os.ReadFile(filepath.Join(root, "golden", "mcp.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(root, "golden", "mcp.out.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s := NewServer(config.PathsAt(home), "1.0.0")
	s.Log = &bytes.Buffer{}
	if err := s.Serve(context.Background(), bytes.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	reqs := nonBlank(string(in))
	// newer than the recordings: the rule in fix tasks and the sentence in the instructions that hosts' text is data
	body := out.String()
	for _, lang := range []string{"en", "ru", "zh"} {
		b, _ := json.Marshal("\n" + prompt.Boundary(lang))
		body = strings.ReplaceAll(body, strings.Trim(string(b), `"`), "")
	}
	b, _ := json.Marshal(instructionsData)
	body = strings.ReplaceAll(body, strings.Trim(string(b), `"`), "")
	got, exp := strings.Split(strings.TrimSuffix(body, "\n"), "\n"), strings.Split(strings.TrimSuffix(string(want), "\n"), "\n")
	if len(got) != len(exp) {
		t.Fatalf("%d responses, want %d", len(got), len(exp))
	}
	byID := map[string]string{}
	for _, r := range reqs {
		var m struct{ ID json.RawMessage }
		if json.Unmarshal([]byte(r), &m) == nil && len(m.ID) > 0 {
			byID[string(m.ID)] = r
		}
	}
	exact := 0
	for i := range got {
		if got[i] == exp[i] {
			exact++
			continue
		}
		var id struct{ ID json.RawMessage }
		_ = json.Unmarshal([]byte(exp[i]), &id)
		if d := diff(got[i], exp[i]); d != "" {
			t.Errorf("request %s\n%s", byID[string(id.ID)], d)
		} else { // the same data: only key order or number formatting differs
			t.Errorf("request %s: same data, other bytes:\n%s\nwant\n%s", byID[string(id.ID)], got[i], exp[i])
		}
	}
	t.Logf("%d responses, %d byte-identical", len(got), exact)
}

func nonBlank(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func decode(s string) any {
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return s
	}
	return v
}

// diff compares two responses as data, with the text of tool results decoded when it is JSON; "" when equal.
func diff(got, want string) string {
	g, w := decode(got), decode(want)
	texts := func(v any) []any {
		var out []any
		res, _ := v.(map[string]any)["result"].(map[string]any)
		for _, c := range list(res["content"]) {
			m := mapOf(c)
			out = append(out, decode(str(m["text"])))
			m["text"] = nil
		}
		return out
	}
	gt, wt := texts(g), texts(w)
	if !reflect.DeepEqual(g, w) {
		return "envelope:\n" + got + "\nwant\n" + want
	}
	for i := range wt {
		if i >= len(gt) || !reflect.DeepEqual(norm(gt[i]), norm(wt[i])) {
			gs, _ := json.MarshalIndent(gt, "", " ")
			ws, _ := json.MarshalIndent(wt, "", " ")
			return "text:\n" + string(gs) + "\nwant\n" + string(ws)
		}
	}
	return ""
}

// norm: numbers as float64, so 1 and 1.0 are equal.
func norm(v any) any {
	switch t := v.(type) {
	case json.Number:
		f, _ := t.Float64()
		return f
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = norm(x)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			out[k] = norm(x)
		}
		return out
	}
	return v
}

func str(v any) string { s, _ := v.(string); return s }

func TestServeStopsOnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	done := make(chan error)
	go func() { done <- NewServer(config.PathsAt(t.TempDir()), "x").Serve(ctx, r, &bytes.Buffer{}) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func mapOf(v any) map[string]any { m, _ := v.(map[string]any); return m }
