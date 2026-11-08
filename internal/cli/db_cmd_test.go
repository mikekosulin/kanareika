package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/priority"
)

// fakeDownloads: db update without network; the "downloads" write what the real ones would.
func fakeDownloads(t *testing.T, feedsErr, dbErr error) {
	t.Helper()
	oldF, oldP, oldJ := updateFeeds, prepareDB, fetchJavaDB
	t.Cleanup(func() { updateFeeds, prepareDB, fetchJavaDB = oldF, oldP, oldJ })
	fetchJavaDB = func(_ context.Context, logf func(string, ...any)) error {
		logf("trivy %s: downloaded", "java-db")
		return nil
	}
	updateFeeds = func(context.Context, *priority.Policy) (priority.Stats, error) {
		if feedsErr != nil {
			return priority.Stats{}, feedsErr
		}
		write(t, filepath.Join(priority.FeedsDir(), "kev.json"), `["CVE-2021-44228"]`)
		write(t, filepath.Join(priority.FeedsDir(), "epss.json"), `{"CVE-2021-44228": 0.97}`)
		write(t, filepath.Join(priority.FeedsDir(), "updated"), "2026-11-06T00:00:00+00:00\n")
		return priority.Stats{KEV: 3, EPSS: 4, IPDBASN: "2026-11"}, nil
	}
	prepareDB = func(_ context.Context, logf func(string, ...any)) error {
		if dbErr != nil {
			return dbErr
		}
		logf("trivy %s: downloaded", "db")
		for _, d := range []string{"db", "java-db"} {
			write(t, filepath.Join(os.Getenv("TRIVY_CACHE_DIR"), d, "metadata.json"), `{"UpdatedAt":"2026-11-05T19:01:45Z"}`)
			write(t, filepath.Join(os.Getenv("TRIVY_CACHE_DIR"), d, d+".file"), "data")
		}
		return nil
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
		!strings.Contains(errs, "trivy db: downloaded") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	if code, _, errs := cli(t, "db", "update", "--java"); code != 0 || !strings.Contains(errs, "trivy java-db: downloaded") {
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
	fakeDownloads(t, errors.New("kev down"), nil)
	if code, _, errs := cli(t, "db", "update"); code != 1 || !strings.Contains(errs, "kev down") {
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
	if !strings.Contains(out, "trivy db: 2026-11-05") || !strings.Contains(out, "feeds: KEV 1, EPSS 1, updated 2026-11-06T00:00:00+00:00") {
		t.Fatal(out)
	}
}

func TestOrNone(t *testing.T) {
	if orNone("0.75.0") != "0.75.0" || orNone("") != "none (KANAREIKA_TRIVY)" {
		t.Fatal()
	}
}
