package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/dbget"
	"github.com/mikekosulin/kanareika/internal/priority"
)

// fakeDownloads: db update without network; the "downloads" write what the real ones would. The city IP database
// is never published; feedsErr fails KEV, dbErr the vulnerability DBs.
func fakeDownloads(t *testing.T, feedsErr, dbErr error) {
	t.Helper()
	old := downloadJobs
	t.Cleanup(func() { downloadJobs = old })
	downloadJobs = func(_ *priority.Policy, names []string) []dbget.Job {
		var jobs []dbget.Job
		for _, n := range names {
			jobs = append(jobs, dbget.Job{Name: n, Label: dbget.Labels[n], Optional: strings.HasPrefix(n, "dbip-"),
				Run: func(_ context.Context, p *dbget.Progress) error {
					p.Start(4)
					_, _ = io.Copy(io.Discard, p.Reader(strings.NewReader("data")))
					dir := priority.FeedsDir()
					switch n {
					case "kev":
						if feedsErr != nil {
							return feedJob("kev", func(context.Context, *dbget.Progress) error { return feedsErr }).Run(context.Background(), nil)
						}
						write(t, filepath.Join(dir, "kev.json"), `["CVE-2021-44228","CVE-2021-1","CVE-2021-2"]`)
					case "epss":
						write(t, filepath.Join(dir, "epss.json"), `{"CVE-2021-44228": 0.97, "CVE-1": 0, "CVE-2": 0, "CVE-3": 0}`)
					case "dbip-asn":
						write(t, filepath.Join(dir, "dbip-asn.mmdb"), "mmdb")
						write(t, filepath.Join(dir, "dbip-asn.month"), "2026-11\n")
					case "dbip-city":
						return errors.New("not published")
					case "db", "java-db":
						if dbErr != nil {
							return dbErr
						}
						for _, d := range []string{"db", "java-db"} {
							write(t, filepath.Join(os.Getenv("TRIVY_CACHE_DIR"), d, "metadata.json"), `{"UpdatedAt":"2026-11-05T19:01:45Z"}`)
							write(t, filepath.Join(os.Getenv("TRIVY_CACHE_DIR"), d, d+".file"), "data")
						}
					}
					return nil
				}})
		}
		return jobs
	}
}

func TestDBLifecycle(t *testing.T) {
	sandbox(t)
	code, out, _ := cli(t, "db", "status")
	if code != 0 || !strings.Contains(out, "trivy (embedded): none (KANAREIKA_TRIVY)") ||
		!strings.Contains(out, "trivy db: not downloaded") || !strings.Contains(out, "feeds: not downloaded") ||
		!strings.Contains(out, "trivy java-db: not needed yet") {
		t.Fatalf("%d\n%s", code, out)
	}
	bundle := filepath.Join(t.TempDir(), "b.tar.gz")
	if code, _, errs := cli(t, "db", "export", bundle); code != 1 || !strings.Contains(errs, "nothing to export") {
		t.Fatal(code, errs)
	}

	fakeDownloads(t, nil, nil)
	code, out, errs := cli(t, "db", "update")
	if code != 0 || !strings.Contains(out, "KEV: 3 CVEs, EPSS: 4 scores, IP DB (DB-IP Lite): city none, asn 2026-11") ||
		!strings.Contains(out, "trivy db: 2026-11-05 19:01Z") || !strings.Contains(out, "trivy java-db: 2026-11-05 19:01Z") ||
		!strings.Contains(errs, "Vulnerability DB (trivy-db): done, 1 KB") ||
		!strings.Contains(errs, "IP locations (DB-IP city): failed: not published") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	if code, _, errs := cli(t, "db", "update", "--java"); code != 0 || !strings.Contains(errs, "Java DB (trivy-java-db): done") {
		t.Fatal(code, errs)
	}
	if code, out, _ := cli(t, "db", "export", bundle); code != 0 || !strings.Contains(out, "[trivy-db trivy-java-db feeds]") {
		t.Fatal(code, out)
	}

	// the isolated machine: empty caches, then import
	sandbox(t)
	if code, _, errs := cli(t, "db", "import", filepath.Join(t.TempDir(), "missing.tgz")); code != 1 || errs == "" {
		t.Fatal(code, errs)
	}
	code, out, _ = cli(t, "db", "import", bundle)
	if code != 0 || !strings.Contains(out, "imported [feeds trivy-db trivy-java-db]") || !strings.Contains(out, "trivy java-db: 2026-11-05") {
		t.Fatal(code, out)
	}
	if b, _ := os.ReadFile(filepath.Join(os.Getenv("TRIVY_CACHE_DIR"), "java-db", "java-db.file")); string(b) != "data" {
		t.Fatal("java-db not imported")
	}
	if code, _, errs := cli(t, "db", "export"); code != 1 || !strings.Contains(errs, "accepts 1 arg") {
		t.Fatal(code, errs)
	}
}

func TestDBUpdateVariants(t *testing.T) {
	sandbox(t)
	fakeDownloads(t, nil, errors.New("registry down"))
	if code, _, errs := cli(t, "db", "update"); code != 1 || !strings.Contains(errs, "registry down") {
		t.Fatal(code, errs)
	}
	code, out, _ := cli(t, "db", "update", "--skip-trivy")
	if code != 0 || strings.Contains(out, "trivy db") {
		t.Fatal(code, out)
	}
	// the old name still works, with a deprecation note, and is not listed
	code, out, errs := cli(t, "feeds", "--skip-trivy")
	if code != 0 || !strings.Contains(out, "KEV: 3") || !strings.Contains(out+errs, "deprecated") {
		t.Fatal(code, out, errs)
	}
	if _, out, _ := cli(t, "--help"); strings.Contains(out, "\n  feeds ") || !strings.Contains(out, "\n  db ") {
		t.Fatal(out)
	}
	// KEV down: the copy on disk stays in use; with none, the update fails
	fakeDownloads(t, errors.New("kev down"), nil)
	if code, _, errs := cli(t, "db", "update"); code != 0 || !strings.Contains(errs, "CISA KEV: failed: kev down; the copy from") {
		t.Fatal(code, errs)
	}
	sandbox(t)
	if code, _, errs := cli(t, "db", "update"); code != 1 || !strings.Contains(errs, "CISA KEV: kev down") {
		t.Fatal(code, errs)
	}
	// a broken policy stops the update before any download
	write(t, filepath.Join(os.Getenv("KANAREIKA_HOME"), "policy", "priority.yml"), "rules: [")
	if code, _, _ := cli(t, "db", "update"); code != 1 {
		t.Fatal(code)
	}
}

func TestDBStatusWithFeeds(t *testing.T) {
	sandbox(t)
	fakeDownloads(t, nil, nil)
	_, _, _ = cli(t, "db", "update")
	t.Setenv("KANAREIKA_TRIVY", os.Args[0]) // any existing file: an external trivy
	_, out, _ := cli(t, "db", "status")
	if !strings.Contains(out, "trivy db: 2026-11-05") || !strings.Contains(out, "feeds: KEV 3, EPSS 4, updated 20") {
		t.Fatal(out)
	}
}

func TestOrNone(t *testing.T) {
	if orNone("0.75.0") != "0.75.0" || orNone("") != "none (KANAREIKA_TRIVY)" {
		t.Fatal()
	}
}
