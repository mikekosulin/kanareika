package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/dbget"
)

// TestDBProgress: /api/db shows each download of a running update (bytes, total, speed, time left, state, note) and
// the totals; the last update's stay after it ended; before any update "progress" is null.
func TestDBProgress(t *testing.T) {
	t.Setenv("TRIVY_CACHE_DIR", t.TempDir())
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	half, release := make(chan struct{}), make(chan struct{})
	s, _ := newTest(t, Options{UpdateDB: func(ctx context.Context, out io.Writer) error {
		tr := dbget.TrackerFrom(ctx)
		if tr == nil {
			return errors.New("no tracker in the context")
		}
		tr.Run(ctx, []dbget.Job{
			{Name: "db", Label: dbget.Labels["db"], Run: func(_ context.Context, p *dbget.Progress) error {
				p.Start(1000)
				_, _ = io.Copy(io.Discard, p.Reader(strings.NewReader(strings.Repeat("x", 400))))
				close(half)
				<-release
				return nil
			}},
			{Name: "kev", Label: dbget.Labels["kev"], Run: func(_ context.Context, p *dbget.Progress) error {
				p.Cached("already up to date (cached)")
				return nil
			}},
			{Name: "dbip-city", Label: dbget.Labels["dbip-city"], Optional: true, Run: func(context.Context, *dbget.Progress) error {
				return &dbget.StatusError{Code: 429, Host: "download.db-ip.com"}
			}},
		})
		return nil
	}})
	raw := func() map[string]json.RawMessage {
		var m map[string]json.RawMessage
		must(t, json.Unmarshal([]byte(do(s.Handler(), "GET", "/api/db", nil, nil).body), &m))
		return m
	}
	if p, ok := raw()["progress"]; !ok || string(p) != "null" {
		t.Fatalf("before any update: %s", p)
	}
	if r := do(s.Handler(), "POST", "/api/db/update", nil, s.postHdr()); r.code != 202 {
		t.Fatal(r.code)
	}
	<-half
	type item struct {
		Name, Label, State, Note string
		Bytes, Total, Speed      int64
		ETA                      *int64 `json:"eta_s"`
	}
	type progress struct {
		Items  []item `json:"items"`
		Totals struct {
			Bytes, Total, Speed int64
			ETA                 *int64 `json:"eta_s"`
		} `json:"totals"`
		Running bool `json:"running"`
	}
	read := func() (progress, map[string]json.RawMessage) {
		m := raw()
		var p progress
		must(t, json.Unmarshal(m["progress"], &p))
		var items []map[string]json.RawMessage
		var wrap struct {
			Items  []map[string]json.RawMessage `json:"items"`
			Totals map[string]json.RawMessage   `json:"totals"`
		}
		must(t, json.Unmarshal(m["progress"], &wrap))
		items = wrap.Items
		for _, it := range items { // the contract: these keys, always
			var keys []string
			for k := range it {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			if strings.Join(keys, ",") != "bytes,eta_s,label,name,note,speed,state,total" {
				t.Fatalf("item keys %v", keys)
			}
		}
		var tk []string
		for k := range wrap.Totals {
			tk = append(tk, k)
		}
		slices.Sort(tk)
		if strings.Join(tk, ",") != "bytes,eta_s,speed,total" {
			t.Fatalf("totals keys %v", tk)
		}
		return p, m
	}
	byName := map[string]item{}
	var p progress
	var m map[string]json.RawMessage
	for i := 0; i < 400 && (byName["kev"].State != "cached" || byName["dbip-city"].State != "failed"); i++ { // the others run beside db
		time.Sleep(5 * time.Millisecond)
		p, m = read()
		for _, it := range p.Items {
			byName[it.Name] = it
		}
	}
	if string(m["updating"]) != "true" || !p.Running || len(p.Items) != 3 {
		t.Fatalf("%+v", p)
	}
	if it := byName["db"]; it.State != "downloading" || it.Bytes != 400 || it.Total != 1000 || it.Label != "Vulnerability DB (trivy-db)" {
		t.Fatalf("%+v", it)
	}
	if it := byName["kev"]; it.State != "cached" || it.Note != "already up to date (cached)" {
		t.Fatalf("%+v", it)
	}
	if p.Totals.Bytes != 400 || p.Totals.Total != 1000 {
		t.Fatalf("%+v", p.Totals)
	}
	close(release)
	for i := 0; i < 200 && string(raw()["updating"]) == "true"; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	p, _ = read()
	for _, it := range p.Items {
		byName[it.Name] = it
	}
	if p.Running || byName["db"].State != "done" || byName["dbip-city"].State != "failed" ||
		byName["dbip-city"].Note != "too many requests (429)" || byName["db"].ETA != nil || p.Totals.ETA != nil {
		t.Fatalf("%+v", p)
	}
}
