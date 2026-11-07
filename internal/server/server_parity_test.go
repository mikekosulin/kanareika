package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/ipinfo"
)

// Parity with the former Python dashboard. testdata/parity/golden.json holds its responses for a
// synthetic home: the org in org.yml, the runs of internal/report/testdata/fixture and the synthetic runs in
// extra/. Recorded once with the former Python implementation (removed from the repo; the Go port had to match it)
// and kept as a frozen fixture: a change here is a behaviour change — review it as such.

// -update-page: rewrite the SHA-256 of the HTML page cases (the page changes on purpose; API answers stay frozen).
var updatePage = flag.Bool("update-page", false, "rewrite the page hashes in testdata/parity/golden.json")

type golden struct {
	Extra string `json:"extra"` // org/env the extra/ runs go into
	Cases []struct {
		Path    string            `json:"path"`
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		JSON    json.RawMessage   `json:"json"`
		SHA256  string            `json:"sha256"`
	} `json:"cases"`
}

func TestFixtureParity(t *testing.T) {
	home := t.TempDir()
	must(t, copyDir("../../assets/schemas", filepath.Join(home, "schemas")))
	must(t, copyDir("../../assets/policy", filepath.Join(home, "policy")))
	must(t, copyDir("../report/testdata/fixture/env/acme-production", filepath.Join(home, "reports/acme/production")))
	must(t, os.MkdirAll(filepath.Join(home, "orgs"), 0o755))
	b, err := os.ReadFile("testdata/parity/org.yml")
	must(t, err)
	must(t, os.WriteFile(filepath.Join(home, "orgs/acme.yml"), b, 0o644))
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(home, "no-feeds")) // recorded without IP databases
	replay(t, home, "testdata/parity/golden.json")
}

func replay(t *testing.T, home, goldenPath string) {
	b, err := os.ReadFile(goldenPath)
	must(t, err)
	var g golden
	must(t, json.Unmarshal(b, &g))
	must(t, installExtra(filepath.Join(home, "reports", g.Extra)))
	ipinfo.Reload()
	s, err := New(Options{Paths: config.PathsAt(home)})
	must(t, err)
	h := s.Handler()
	for _, c := range g.Cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", c.Path, nil))
		var diffs []string
		if rec.Code != c.Status {
			diffs = append(diffs, fmt.Sprintf("status %d, Python %d", rec.Code, c.Status))
		}
		for k, v := range c.Headers {
			if got := rec.Header().Get(k); got != v {
				diffs = append(diffs, fmt.Sprintf("%s: %q, Python %q", k, got, v))
			}
		}
		if c.SHA256 != "" {
			// the page carries a CSRF token fresh per server: hashed with the placeholder back in its place
			body := bytes.Replace(rec.Body.Bytes(), []byte(`"`+s.csrf+`"`), []byte(`/*CSRF*/""`), 1)
			sum := sha256.Sum256(body)
			if got := hex.EncodeToString(sum[:]); got != c.SHA256 {
				if *updatePage {
					b = bytes.ReplaceAll(b, []byte(c.SHA256), []byte(got))
				} else {
					diffs = append(diffs, "body differs (page changed on purpose? go test -run Parity -update-page)")
				}
			}
		} else if d := jsonDiff(c.JSON, pythonLangs(c.JSON, rec.Body.Bytes())); d != "" {
			diffs = append(diffs, d)
		}
		if len(diffs) > 0 {
			t.Errorf("%s: %s", c.Path, strings.Join(diffs, "; "))
		}
	}
	if *updatePage {
		must(t, os.WriteFile(goldenPath, b, 0o644))
	}
}

// pythonLangs: an /api/i18n answer cut to the languages Python had (languages added since are checked by
// i18n's TestLocalesComplete); other answers as they are.
func pythonLangs(want, got []byte) []byte {
	var w, g struct {
		Langs    []string                     `json:"langs"`
		Messages map[string]map[string]string `json:"messages"`
	}
	if json.Unmarshal(want, &w) != nil || json.Unmarshal(got, &g) != nil || w.Langs == nil || g.Langs == nil {
		return got
	}
	g.Langs = slices.DeleteFunc(g.Langs, func(l string) bool { return !slices.Contains(w.Langs, l) })
	for _, m := range g.Messages {
		maps.DeleteFunc(m, func(l, _ string) bool { return !slices.Contains(w.Langs, l) })
	}
	b, err := json.Marshal(g)
	if err != nil {
		return got
	}
	return b
}

// installExtra copies testdata/parity/extra into an environment, with __NOW__ set to the current time (a
// fresh heartbeat: that run shows as running, the other one as stale).
func installExtra(envDir string) error {
	now := []byte(time.Now().UTC().Format("2006-01-02T15:04:05+00:00"))
	src := "testdata/parity/extra"
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(envDir, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(envDir, rel), bytes.ReplaceAll(b, []byte("__NOW__"), now), 0o644)
	})
}

// jsonDiff: "" when equal as JSON values. Heartbeat times are ignored, and the rows of new/resolved diffs are
// compared as sets: Python orders their ties by set iteration (random per process).
func jsonDiff(want, got []byte) string {
	var w, g any
	if err := json.Unmarshal(want, &w); err != nil {
		return "golden: " + err.Error()
	}
	if err := json.Unmarshal(got, &g); err != nil {
		return fmt.Sprintf("not JSON: %.200s", got)
	}
	w, g = normalize(w, ""), normalize(g, "")
	if reflect.DeepEqual(w, g) {
		return ""
	}
	return firstDiff(w, g, "$")
}

func normalize(v any, key string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if k == "updated" {
				x[k] = "<time>"
			} else {
				x[k] = normalize(e, k)
			}
		}
		if rows, ok := x["rows"].([]any); ok && (key == "new" || key == "resolved") {
			if len(rows) >= diffRowsLimit {
				// which of the tied rows made the cut is random too: compare the sort keys, in order
				for i, r := range rows {
					m, _ := r.(map[string]any)
					rows[i] = []any{m["priority"], m["count"], m["host"], m["pkg"]}
				}
			} else {
				sort.Slice(rows, func(i, j int) bool { return canon(rows[i]) < canon(rows[j]) })
			}
		}
	case []any:
		for i, e := range x {
			x[i] = normalize(e, "")
		}
	}
	return v
}

// diffRowsLimit: report.BuildView keeps this many rows of a diff.
const diffRowsLimit = 3000

func canon(v any) string { b, _ := json.Marshal(v); return string(b) }

func firstDiff(w, g any, path string) string {
	switch wx := w.(type) {
	case map[string]any:
		gx, ok := g.(map[string]any)
		if !ok {
			return fmt.Sprintf("%s: %.100s, Python %.100s", path, canon(g), canon(w))
		}
		keys := map[string]bool{}
		for k := range wx {
			keys[k] = true
		}
		for k := range gx {
			keys[k] = true
		}
		ks := make([]string, 0, len(keys))
		for k := range keys {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			if !reflect.DeepEqual(wx[k], gx[k]) {
				_, inW := wx[k]
				_, inG := gx[k]
				if inW != inG {
					return fmt.Sprintf("%s.%s: present in Go %v, in Python %v", path, k, inG, inW)
				}
				return firstDiff(wx[k], gx[k], path+"."+k)
			}
		}
	case []any:
		gx, ok := g.([]any)
		if !ok || len(gx) != len(wx) {
			return fmt.Sprintf("%s: %.100s, Python %.100s", path, canon(g), canon(w))
		}
		for i := range wx {
			if !reflect.DeepEqual(wx[i], gx[i]) {
				return firstDiff(wx[i], gx[i], fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	return fmt.Sprintf("%s: %.100s, Python %.100s", path, canon(g), canon(w))
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
