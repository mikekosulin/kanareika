package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/dbget"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/scan"
	"github.com/mikekosulin/kanareika/internal/store"
	"github.com/mikekosulin/kanareika/internal/trivy"
	"github.com/mikekosulin/kanareika/internal/trivy/ocitest"
)

// roundTrip: an http.RoundTripper from a function.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func gzipped(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

// TestRealDownloadJobs: the real downloads, against made-up servers: in the order every screen shows, with their
// labels, only the IP databases optional; each lands where scans read it; an IP database that could not be updated
// keeps the file of an earlier month in use.
func TestRealDownloadJobs(t *testing.T) {
	sandbox(t)
	t.Setenv("TRIVY_DB_REPOSITORY", "")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "")
	reg := ocitest.New(t)
	upd := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	next := upd.Add(6 * time.Hour)
	t.Setenv("KANAREIKA_TRIVY_DB_REPOS", reg.Push("a/trivy-db", "2", "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
		ocitest.Layer(map[string][]byte{"trivy.db": []byte("db"), "metadata.json": ocitest.Metadata(2, next, upd)})))
	t.Setenv("KANAREIKA_TRIVY_JAVA_DB_REPOS", reg.Push("a/trivy-java-db", "1", "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip",
		ocitest.Layer(map[string][]byte{"trivy-java.db": []byte("java"), "metadata.json": ocitest.Metadata(1, next, upd)})))
	// KEV, EPSS and DB-IP answered here, whatever the host: no network
	feed := func(path string) []byte {
		switch {
		case path == "/kev.json":
			return []byte(`{"vulnerabilities":[{"cveID":"CVE-2026-0001","dueDate":"2026-12-01"}]}`)
		case path == "/epss.csv.gz":
			return gzipped("cve,epss,percentile\nCVE-2026-0001,0.5,0.9\nCVE-2026-0002,0.1,0.2\n")
		case strings.Contains(path, "/dbip-asn-lite-"):
			return gzipped("ASN")
		}
		return nil // the city file of this month and the last is not published
	}
	regRT := dbget.Transport
	t.Cleanup(func() { dbget.Transport = regRT })
	dbget.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == reg.Host() {
			return regRT.RoundTrip(r) //nolint:bodyclose // returned: the client closes it
		}
		status, body := http.StatusOK, feed(r.URL.Path)
		if body == nil {
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Header: http.Header{}, ContentLength: int64(len(body)),
			Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
	})
	dir := priority.FeedsDir()
	write(t, filepath.Join(dir, "dbip-city.mmdb"), "CITY")
	write(t, filepath.Join(dir, "dbip-city.month"), "2026-01\n")

	pol := &priority.Policy{KEVURL: "https://feeds.example/kev.json", EPSSURL: "https://feeds.example/epss.csv.gz"}
	jobs := downloadJobs(pol, []string{"kev", "epss", "dbip-city", "dbip-asn", "java-db", "db", "nope"})
	if names := dbget.Names(jobs); !slices.Equal(names, dbget.Order) {
		t.Fatal(names)
	}
	for _, j := range jobs {
		if j.Label != dbget.Labels[j.Name] || j.Optional != strings.HasPrefix(j.Name, "dbip-") {
			t.Errorf("%s: %q optional %v", j.Name, j.Label, j.Optional)
		}
	}
	var out bytes.Buffer
	errs := runDownloads(context.Background(), &out, jobs)
	var kept *dbget.KeptError
	if len(errs) != 1 || !errors.As(errs["dbip-city"], &kept) || dbget.Fatal(jobs, errs) != nil {
		t.Fatal(errs, out.String())
	}
	for _, want := range []string{"Vulnerability DB (trivy-db): done", "Java DB (trivy-java-db): done", "CISA KEV: done",
		"EPSS scores: done", "IP networks (DB-IP ASN): done",
		"IP locations (DB-IP city): failed: not found (404); the file from 2026-01 stays in use"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("no %q in\n%s", want, out.String())
		}
	}
	f, err := priority.LoadFeeds()
	if err != nil || !f.KEV["CVE-2026-0001"] || len(f.EPSS) != 2 || f.KEVDue["CVE-2026-0001"] != "2026-12-01" {
		t.Fatal(f, err)
	}
	if priority.IPDBMonth("asn") != time.Now().Format("2006-01") || priority.IPDBMonth("city") != "2026-01" {
		t.Fatal(priority.IPDBMonth("asn"), priority.IPDBMonth("city"))
	}
	for _, d := range trivy.DBStatus() {
		if !d.Updated.Equal(upd) {
			t.Errorf("trivy %s: %v", d.Name, d.Updated)
		}
	}
}

// TestDBUpdateStampFails: the feeds came, but the time of the update can't be recorded: the update fails, saying
// why.
func TestDBUpdateStampFails(t *testing.T) {
	sandbox(t)
	fakeDownloads(t, nil, nil)
	must(t, os.MkdirAll(filepath.Join(priority.FeedsDir(), "updated.tmp"), 0o755)) // its temp name taken by a directory
	if code, _, errs := cli(t, "db", "update", "--skip-trivy"); code != 1 || !strings.Contains(errs, "updated.tmp") {
		t.Fatal(code, errs)
	}
}

// TestDBUpdateInterruptedLate: an update cancelled (Ctrl-C) whose downloads ended all the same reports the
// interruption, not a success.
func TestDBUpdateInterruptedLate(t *testing.T) {
	sandbox(t)
	fakeDownloads(t, nil, nil) // they finish whatever the context says
	a := &app{paths: config.PathsAt(home())}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := a.updateDBs(ctx, &out, &out, true, false); !errors.Is(err, context.Canceled) || !strings.Contains(out.String(), "KEV: 3 CVEs") {
		t.Fatal(err, out.String())
	}
}

// TestScanNothingToDownloadFirst: on a terminal, a scan with everything up to date asks nothing and downloads
// nothing first.
func TestScanNothingToDownloadFirst(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	asked := stubScan(t)
	now := time.Now().UTC()
	dir := priority.FeedsDir()
	for name, body := range map[string]string{"kev.json": `["CVE-2026-0001"]`, "epss.json": `{"CVE-2026-0001": 0.5}`,
		"updated": now.Format("2006-01-02T15:04:05.000000-07:00"), "dbip-city.mmdb": "CITY", "dbip-asn.mmdb": "ASN"} {
		write(t, filepath.Join(dir, name), body)
	}
	write(t, filepath.Join(trivy.CacheDir(), "db", "metadata.json"), `{"UpdatedAt":"`+now.Add(-time.Hour).Format(time.RFC3339)+
		`","NextUpdate":"`+now.Add(5*time.Hour).Format(time.RFC3339)+`"}`)
	onProgressTTY(t, 100)
	tty := onTTY(t, "n\n")
	code, _, errs := cli(t, "scan", "acme", "--env", "production")
	if code != 0 || *asked != nil || tty.Len() != 0 || strings.Contains(errs, "Downloading") {
		t.Fatal(code, *asked, tty, errs)
	}
}

// TestScanBrokenPolicyDownloadsNothingFirst: with a broken policy the downloads before the scan are skipped (they
// need its feed URLs); the scan reports the policy where it uses it.
func TestScanBrokenPolicyDownloadsNothingFirst(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	asked := stubScan(t)
	write(t, filepath.Join(home(), "policy", "priority.yml"), "rules: [")
	onProgressTTY(t, 100)
	code, _, errs := cli(t, "scan", "acme", "--env", "production", "--yes")
	if code != 0 || *asked != nil || strings.Contains(errs, "Downloading") {
		t.Fatal(code, *asked, errs)
	}
}

// stubScan: scans that do nothing and downloads that are only recorded (their names, nil when none was made).
func stubScan(t *testing.T) *[]string {
	t.Helper()
	oldR, oldJ := runOrg, downloadJobs
	t.Cleanup(func() { runOrg, downloadJobs = oldR, oldJ })
	runOrg = func(context.Context, *scan.Scanner, *config.Org, string, scan.Options) int { return 0 }
	var asked []string
	downloadJobs = func(_ *priority.Policy, names []string) []dbget.Job { asked = names; return nil }
	return &asked
}

// TestFindingsDBError: when current/'s findings can't be copied into the findings database after a scan, stderr
// says so; the scan's result stands (the interfaces import the files when they first read them).
func TestFindingsDBError(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	stubScan(t)
	reports := filepath.Join(home(), "reports")
	must(t, os.MkdirAll(filepath.Join(store.Path(reports), "x"), 0o755)) // a directory where the database should be
	runOrg = func(context.Context, *scan.Scanner, *config.Org, string, scan.Options) int {
		report.OnCurrent(filepath.Join(reports, "acme", "production", "current"), []string{"web-01"}) // as the scan does
		return 0
	}
	code, _, errs := cli(t, "scan", "acme", "--env", "production", "--offline")
	if code != 0 || !strings.HasPrefix(errs, "kanareika: findings database: ") {
		t.Fatal(code, errs)
	}
}

// TestRedrawShorter: a frame shorter than the one on screen clears the lines left below it.
func TestRedrawShorter(t *testing.T) {
	var b bytes.Buffer
	drawn := 0
	redraw(&b, &drawn, []string{"a", "b", "c"})
	redraw(&b, &drawn, []string{"x"})
	want := "\r\x1b[2Ka\n\r\x1b[2Kb\n\r\x1b[2Kc\n" + "\x1b[3A\r\x1b[2Kx\n\r\x1b[2K\n\r\x1b[2K\n"
	if b.String() != want || drawn != 3 {
		t.Fatalf("%q %d", b.String(), drawn)
	}
}
