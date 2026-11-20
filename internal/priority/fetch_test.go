package priority

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/dbget"
	"github.com/mikekosulin/kanareika/internal/finding"
)

// hits: a feed server's requests, safe to read while it serves.
type hits struct {
	mu   sync.Mutex
	list []string
}

func (h *hits) add(s string) { h.mu.Lock(); h.list = append(h.list, s); h.mu.Unlock() }
func (h *hits) get() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.list)
}

// TestIPDBCached: this month's file in place: nothing is asked for, the download says so; a feeds directory that
// can't be made fails before asking.
func TestIPDBCached(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "feeds")
	t.Setenv("KANAREIKA_FEEDS_DIR", dir)
	var h hits
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.add(r.URL.Path); http.NotFound(w, r) }))
	t.Cleanup(srv.Close)
	old := ipdbURL
	ipdbURL = srv.URL + "/dbip-%s-%s.mmdb.gz"
	t.Cleanup(func() { ipdbURL = old })
	month := time.Now().Format("2006-01")
	must(t, os.MkdirAll(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "dbip-city.mmdb"), []byte("CITY"), 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "dbip-city.month"), []byte(month+"\n"), 0o644))
	m, cached, err := FetchIPDB(context.Background(), "city", nil)
	if err != nil || !cached || m != month {
		t.Fatal(m, cached, err)
	}
	tr := dbget.NewTracker() // as db update runs it
	errs := tr.Run(context.Background(), []dbget.Job{{Name: "dbip-city", Run: func(ctx context.Context, p *dbget.Progress) error {
		_, _, err := FetchIPDB(ctx, "city", p)
		return err
	}}})
	if it := tr.Snapshot().Items[0]; errs != nil || it.State != dbget.Cached || it.Note != "already up to date (cached)" {
		t.Fatalf("%+v %v", it, errs)
	}
	if len(h.get()) != 0 {
		t.Fatal("asked for a cached file:", h.get())
	}

	blocker := filepath.Join(t.TempDir(), "file")
	must(t, os.WriteFile(blocker, nil, 0o644))
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(blocker, "feeds"))
	if _, _, err := FetchIPDB(context.Background(), "asn", nil); err == nil || len(h.get()) != 0 {
		t.Fatal("a feeds directory under a file", err, h.get())
	}
}

// TestIPDBCancelled: Ctrl-C while this month's file is asked for stops there: last month's is not tried.
func TestIPDBCancelled(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(t.TempDir(), "feeds"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var h hits
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.add(r.URL.Path)
		cancel()
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	old := ipdbURL
	ipdbURL = srv.URL + "/dbip-%s-%s.mmdb.gz"
	t.Cleanup(func() { ipdbURL = old })
	if _, _, err := FetchIPDB(ctx, "asn", nil); err == nil {
		t.Fatal("no error")
	}
	if got := h.get(); !slices.Equal(got, []string{"/dbip-asn-" + time.Now().Format("2006-01") + ".mmdb.gz"}) {
		t.Fatal(got)
	}
}

// TestFeedJobsAlone: KEV and EPSS run as separate jobs, each checks the policy itself; CISA's due dates that can't
// be stored fail the KEV download.
func TestFeedJobsAlone(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KANAREIKA_FEEDS_DIR", dir)
	srv := feedServer(t, map[string][]byte{"/kev.json": []byte(kevJSON), "/epss.csv.gz": gz(epssCSV)})
	if _, err := FetchEPSS(context.Background(), &Policy{KEVURL: srv.URL + "/kev.json"}, nil); err == nil ||
		err.Error() != "priority.yml: feeds.kev_url and feeds.epss_url are required" {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "epss.json")); !os.IsNotExist(err) {
		t.Fatal("epss.json written", err)
	}
	must(t, os.Mkdir(filepath.Join(dir, "kev_due.json.tmp"), 0o755)) // its temp name taken by a directory
	if _, err := FetchKEV(context.Background(), &Policy{KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz"}, nil); err == nil ||
		!strings.Contains(err.Error(), "kev_due.json.tmp") {
		t.Fatal(err)
	}
}

// TestDownloadSizeHEAD: the sizes come from HEAD requests that say who asks and accept gzip (what goes over the
// wire); a feed whose server does not say its size, that is not there or whose URL is broken is missing, and one
// without a URL is not asked.
func TestDownloadSizeHEAD(t *testing.T) {
	var h hits
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.add(r.Method + " " + r.URL.Path)
		if r.UserAgent() != UserAgent || r.Header.Get("Accept-Encoding") != "gzip" {
			http.Error(w, "headers", http.StatusBadRequest)
			return
		}
		switch {
		case r.URL.Path == "/kev.json":
			w.Header().Set("Content-Length", "1300000")
		case r.URL.Path == "/epss.csv.gz":
			w.Header().Set("Content-Length", "2100000")
		case strings.HasPrefix(r.URL.Path, "/dbip-city-"):
			w.Header().Set("Content-Length", "30000000")
		case strings.HasPrefix(r.URL.Path, "/dbip-asn-"): // no size said
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := ipdbURL
	ipdbURL = srv.URL + "/dbip-%s-%s.mmdb.gz"
	t.Cleanup(func() { ipdbURL = old })
	got := DownloadSize(context.Background(), Policy{KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz"})
	if len(got) != 3 || got["kev"] != 1_300_000 || got["epss"] != 2_100_000 || got["dbip-city"] != 30_000_000 {
		t.Fatal(got)
	}
	month := time.Now().Format("2006-01")
	asked := h.get()
	slices.Sort(asked)
	if !slices.Equal(asked, []string{"HEAD /dbip-asn-" + month + ".mmdb.gz", "HEAD /dbip-city-" + month + ".mmdb.gz", "HEAD /epss.csv.gz", "HEAD /kev.json"}) {
		t.Fatal(asked)
	}
	got = DownloadSize(context.Background(), Policy{KEVURL: srv.URL + "/gone.json", EPSSURL: "http://bad host/"})
	if _, ok := got["kev"]; ok || len(got) != 1 {
		t.Fatal(got)
	}
	n := len(h.get())
	if got := DownloadSize(context.Background(), Policy{}); len(got) != 1 || len(h.get()) != n+2 { // the IP databases only
		t.Fatal(got, h.get()[n:])
	}
}

// TestDueFromNoPriority: a finding that had no priority before (no rule matched it) and has one now has gone up:
// with escalation: restart its clock starts today.
func TestDueFromNoPriority(t *testing.T) {
	was := finding.Finding{FirstSeen: "2026-06-01"}
	got := prioritized(t, f("CVE-1", nil), prevOf(&was), "2026-11-08")
	if got.PriorityOr() != "P2" || due(got) != "2026-12-08 escalated 2026-11-08" || got.FirstSeen != "2026-06-01" {
		t.Fatalf("%s %+v", due(got), got)
	}
	if addDays("2026-11-08", 30) != "2026-12-08" || addDays("2026-11", 30) != "" {
		t.Fatal("addDays: a date that is not one has no due date")
	}
}
