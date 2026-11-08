package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/priority"
)

type dbAnswer struct {
	DBs []struct {
		Name     string `json:"name"`
		Updated  string `json:"updated"`
		Next     string `json:"next_update"`
		Outdated bool   `json:"outdated"`
	} `json:"dbs"`
	Trivy        string   `json:"trivy"`
	FeedsUpdated string   `json:"feeds_updated"`
	FeedsOld     bool     `json:"feeds_outdated"`
	Enabled      bool     `json:"enabled"`
	Updating     bool     `json:"updating"`
	Output       []string `json:"output"`
	Error        string   `json:"error"`
	Finished     string   `json:"finished"`
}

func dbOf(t *testing.T, s *Server) dbAnswer {
	t.Helper()
	var d dbAnswer
	must(t, json.Unmarshal([]byte(do(s.Handler(), "GET", "/api/db", nil, nil).body), &d))
	return d
}

// TestDBStatusAndUpdate: what the DBs are (missing, current, a newer build out) and an update started from an
// interface: one at a time, its output and outcome kept, CSRF and read-only rules as for scans.
func TestDBStatusAndUpdate(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("TRIVY_CACHE_DIR", cache)
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	release, fail := make(chan struct{}), error(nil)
	s, h := newTest(t, Options{UpdateDB: func(ctx context.Context, out io.Writer) error {
		fmt.Fprintln(out, "KEV: 2 CVEs")
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		fmt.Fprintln(out, "trivy db: done\nmore")
		return fail
	}})

	d := dbOf(t, s)
	if !d.Enabled || d.Updating || len(d.DBs) != 2 || d.DBs[0].Name != "db" || d.DBs[0].Updated != "" || !d.DBs[0].Outdated ||
		!d.FeedsOld {
		t.Fatalf("%+v", d)
	}
	feeds := t.TempDir()
	t.Setenv("KANAREIKA_FEEDS_DIR", feeds)
	for name, body := range map[string]string{"kev.json": `[]`, "epss.json": `{}`,
		"updated": time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00")} {
		must(t, os.WriteFile(filepath.Join(feeds, name), []byte(body), 0o644))
	}
	if d := dbOf(t, s); d.FeedsOld || d.FeedsUpdated == "" {
		t.Fatalf("fresh feeds: %+v", d)
	}
	meta := func(name string, updated, next time.Time) {
		must(t, os.MkdirAll(filepath.Join(cache, name), 0o755))
		b, _ := json.Marshal(map[string]any{"UpdatedAt": updated, "NextUpdate": next})
		must(t, os.WriteFile(filepath.Join(cache, name, "metadata.json"), b, 0o644))
	}
	now := time.Now().UTC()
	meta("db", now.Add(-2*time.Hour), now.Add(4*time.Hour))
	meta("java-db", now.Add(-30*time.Hour), now.Add(-6*time.Hour)) // a newer build is out
	d = dbOf(t, s)
	if d.DBs[0].Outdated || !d.DBs[1].Outdated || d.DBs[0].Next == "" {
		t.Fatalf("%+v", d.DBs)
	}

	if r := do(h, "POST", "/api/db/update", nil, map[string]string{"Content-Type": "application/json"}); r.code != 403 {
		t.Fatalf("no CSRF: %d", r.code)
	}
	if r := do(h, "POST", "/api/db/update", nil, s.postHdr()); r.code != 202 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	if r := do(h, "POST", "/api/db/update", nil, s.postHdr()); r.code != 409 || !strings.Contains(r.body, "already running") {
		t.Fatalf("second: %d %s", r.code, r.body)
	}
	if d = dbOf(t, s); !d.Updating {
		t.Fatal("not updating")
	}
	close(release)
	for i := 0; i < 200 && dbOf(t, s).Updating; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	d = dbOf(t, s)
	if d.Updating || d.Error != "" || d.Finished == "" || strings.Join(d.Output, "|") != "KEV: 2 CVEs|trivy db: done|more" {
		t.Fatalf("%+v", d)
	}

	// a failing one keeps its error; a long output keeps its end
	fail, release = errors.New("no repository worked"), make(chan struct{})
	close(release)
	s.db.fn = func(ctx context.Context, out io.Writer) error {
		for i := range 250 {
			fmt.Fprintf(out, "line %d\n", i)
		}
		return fail
	}
	do(h, "POST", "/api/db/update", nil, s.postHdr())
	for i := 0; i < 200 && dbOf(t, s).Finished == "" || dbOf(t, s).Updating; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if d = dbOf(t, s); d.Error != "no repository worked" || len(d.Output) != 200 || d.Output[199] != "line 249" {
		t.Fatalf("%+v", d.Error)
	}

	// shutdown stops a running one
	s.db.fn = func(ctx context.Context, _ io.Writer) error { <-ctx.Done(); return ctx.Err() }
	do(h, "POST", "/api/db/update", nil, s.postHdr())
	s.db.stop()
	if dbOf(t, s).Updating {
		t.Fatal("still running after stop")
	}

	// without the function (read-only, or not offered): status yes, updates no
	s2, h2 := newTest(t, Options{})
	if dbOf(t, s2).Enabled {
		t.Fatal("enabled")
	}
	if r := do(h2, "POST", "/api/db/update", nil, s2.postHdr()); r.code != 403 {
		t.Fatalf("%d", r.code)
	}
	(&dbUpdater{}).stop() // nothing running: nothing to wait for
}

// TestDBTrivyVersion: /api/db names the trivy built into the server, so an interface attached to it shows that one.
func TestDBTrivyVersion(t *testing.T) {
	old := embeddedTrivy
	t.Cleanup(func() { embeddedTrivy = old })
	embeddedTrivy = func() string { return "0.76.2" }
	s, _ := newTest(t, Options{})
	if d := dbOf(t, s); d.Trivy != "0.76.2" {
		t.Fatalf("trivy %q", d.Trivy)
	}
}

func TestDBSize(t *testing.T) {
	old := sizeLookup
	t.Cleanup(func() { sizeLookup, dbSizes = old, nil })
	calls := 0
	sizeLookup = func(context.Context, priority.Policy) map[string]int64 {
		calls++
		return map[string]int64{"db": 100, "java-db": 1000, "kev": 1, "epss": 2, "dbip-city": 3}
	}
	dbSizes = nil
	t.Setenv("TRIVY_CACHE_DIR", t.TempDir()) // nothing downloaded: everything needed
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	_, h := newTest(t, Options{UpdateDB: func(context.Context, io.Writer) error { return nil }})
	var d struct {
		Sizes map[string]int64
		Need  []string
		Total int64
	}
	for range 2 {
		must(t, json.Unmarshal([]byte(do(h, "GET", "/api/db/size", nil, nil).body), &d))
	}
	if calls != 1 {
		t.Errorf("looked up %d times, want 1 (cached)", calls)
	}
	if d.Total != 1106 || len(d.Need) != 6 {
		t.Errorf("total %d need %v", d.Total, d.Need)
	}
	_, ro := newTest(t, Options{})
	if c := do(ro, "GET", "/api/db/size", nil, nil).code; c != 403 {
		t.Errorf("read-only: %d", c)
	}
}

// TestScanWaitsForDBUpdate: a scan started while the page's DB update runs waits for it (two trivy downloads into
// one cache break each other), and says so in its output.
func TestScanWaitsForDBUpdate(t *testing.T) {
	t.Setenv("TRIVY_CACHE_DIR", t.TempDir())
	release := make(chan struct{})
	f := &fakeScan{release: make(chan struct{})}
	s, h := newTest(t, Options{Scan: f.run, UpdateDB: func(ctx context.Context, out io.Writer) error {
		<-release
		return nil
	}})
	if r := do(h, "POST", "/api/db/update", nil, s.postHdr()); r.code != 202 {
		t.Fatal(r.code, r.body)
	}
	r := do(h, "POST", "/api/scan", ScanRequest{Org: "acme", Env: "production"}, s.postHdr())
	if r.code != 202 {
		t.Fatal(r.code, r.body)
	}
	var started struct{ ID string }
	must(t, json.Unmarshal([]byte(r.body), &started))
	time.Sleep(50 * time.Millisecond)
	if len(f.requests()) != 0 {
		t.Fatal("the scan started while the DB update ran")
	}
	j := waitState(t, h, started.ID, JobRunning)
	if !strings.Contains(strings.Join(j.Output, "\n"), "waiting for the vulnerability DB download") {
		t.Errorf("output: %q", j.Output)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for len(f.requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(f.requests()) != 1 {
		t.Fatal("the scan did not start after the update")
	}
	close(f.release)
}
