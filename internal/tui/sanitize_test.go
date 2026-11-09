package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// evil: what a host could report to take over a terminal: the clipboard (OSC 52), a cleared screen, a fake zone.
const evil = "\x1b]52;c;ZXZpbA==\a\x1b[2J\x1b]8999;key:1\abad\u009b2J\x07\r"

// noEscapes: the frame has only the TUI's own styles.
func noEscapes(t *testing.T, where, frame string) {
	t.Helper()
	for _, bad := range []string{"\x1b]", "\x1b[2J", "\a", "\u009b", "\r"} {
		if strings.Contains(frame, bad) {
			t.Errorf("%s: %q reached the frame", where, bad)
		}
	}
}

// TestCleanDecoded: every string the client decodes, in structs, slices, maps (keys too) and any, without control
// characters; line breaks stay, a tab is a space.
func TestCleanDecoded(t *testing.T) {
	esc, _ := json.Marshal(evil)
	body := `{"nodes":[{"id":"n1","label":"web` + string(esc[1:len(esc)-1]) + `","title":"a\tb\nc"}],
		"jobs":[{"id":"j","output":["line ` + string(esc[1:len(esc)-1]) + `"]}],
		"rows":[{"host":"h","cells":{"k` + string(esc[1:len(esc)-1]) + `":{"v":"x` + string(esc[1:len(esc)-1]) + `","s":"` + string(esc[1:len(esc)-1]) + `"}}}]}`
	c := Local(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/err") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"no` + string(esc[1:len(esc)-1]) + `","errors":["x` + string(esc[1:len(esc)-1]) + `"]}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	var tr treeResp
	var jobs jobsResp
	var lens lensResp
	for _, out := range []any{&tr, &jobs, &lens} {
		must(t, c.Get(context.Background(), "/x", out))
	}
	all, _ := json.Marshal([]any{tr, jobs, lens})
	if bytes.Contains(all, []byte(`\u001b`)) || bytes.Contains(all, []byte(`\u0007`)) || bytes.Contains(all, []byte(`\u009b`)) {
		t.Fatalf("control characters kept: %s", all)
	}
	if tr.Nodes[0].Title != "a b\nc" || !strings.HasSuffix(tr.Nodes[0].Label, "bad2J") || jobs.Jobs[0].Output[0] == "" {
		t.Fatalf("%q %q", tr.Nodes[0].Title, tr.Nodes[0].Label)
	}
	err := c.Get(context.Background(), "/err", &tr)
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\a") {
		t.Fatalf("%q", err)
	}
}

// TestNoInjectionInFrame: text with escape sequences in a tree label (through the API), in a job's output and in a
// lens cell (put straight into the model: the backstops) never reaches the frame, nor makes a zone.
func TestNoInjectionInFrame(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(140, 34)
	// the tree through the API, every label with the sequences in it
	inner := h.m.c
	h.m.c = labelled{inner}
	h.key("2")
	h.m.treeKey = ""
	h.run(h.m.sync())
	if !strings.Contains(h.screen(), "bad2J") {
		t.Fatal("the tree is not the labelled one")
	}
	noEscapes(t, "tree", h.m.View())
	h.m.c = inner

	// a job's output, decoded elsewhere: the frame's own backstop
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	h.m.jobs = jobsResp{Enabled: true, Jobs: []jobInfo{{ID: "j1", State: "running", Started: now, Output: []string{"ok " + evil, evil}}}}
	h.m.open = "j1"
	h.show(vScans)
	noEscapes(t, "job output", h.m.View())

	// a lens cell
	var d lensResp
	must(t, json.Unmarshal([]byte(`{"lenses":[{"id":"disks","title":"disks"}],
		"lens":{"id":"disks","columns":[{"key":"mount","title":"mount"}]},
		"rows":[{"host":"web-01","cells":{"mount":{"s":`+jsonStr(evil)+`}}}]}`), &d))
	h.m.lensAPI = true
	h.key("1")
	h.m.lens = "disks"
	h.m.lensData, h.m.lensFor = &d, h.m.lensKey()
	h.m.setLens("disks")
	frame := h.m.View()
	noEscapes(t, "lens", frame)
	for _, z := range h.m.zones {
		if z.id == "key:1" && h.m.handlers[z.id] == nil {
			t.Error("a zone from the data")
		}
	}
	h.has("web-01")
}

func jsonStr(s string) string { b, _ := json.Marshal(s); return string(b) }

// labelled: a client whose tree answers carry the sequences in every label, as a hostile host's names would.
type labelled struct{ Client }

func (l labelled) Get(ctx context.Context, path string, out any) error {
	if !strings.HasPrefix(path, "/api/tree") {
		return l.Client.Get(ctx, path, out)
	}
	rec := httptest.NewRecorder()
	var raw map[string]any
	if err := l.Client.Get(ctx, path, &raw); err != nil {
		return err
	}
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, x := range v {
				if s, ok := x.(string); ok && k == "label" {
					v[k] = s + evil
				}
				walk(x)
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(raw)
	if err := json.NewEncoder(rec).Encode(raw); err != nil {
		return err
	}
	return Local(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(rec.Body.Bytes()) })).Get(ctx, path, out)
}
