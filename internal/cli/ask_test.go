package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/dbsize"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/scan"
)

// fakeTTY: the terminal: what the user types, and what was written to it.
type fakeTTY struct {
	in  *strings.Reader
	out *bytes.Buffer
}

func (f *fakeTTY) Read(p []byte) (int, error)  { return f.in.Read(p) }
func (f *fakeTTY) Write(p []byte) (int, error) { return f.out.Write(p) }
func (f *fakeTTY) Close() error                { return nil }

// onTTY: a terminal where the user answers answer; the sizes of the downloads made up.
func onTTY(t *testing.T, answer string) *bytes.Buffer {
	t.Helper()
	oldT, oldO, oldL := stdinIsTTY, openTTY, dbsize.Lookup
	t.Cleanup(func() { stdinIsTTY, openTTY, dbsize.Lookup = oldT, oldO, oldL; dbsize.Reset() })
	out := &bytes.Buffer{}
	stdinIsTTY = func() bool { return true }
	openTTY = func() (io.ReadWriteCloser, error) { return &fakeTTY{strings.NewReader(answer), out}, nil }
	dbsize.Reset()
	dbsize.Lookup = func(context.Context, priority.Policy) map[string]int64 {
		return map[string]int64{"db": 800e6, "java-db": 400e6, "kev": 1e6, "epss": 2e6, "dbip-city": 30e6, "dbip-asn": 8e6}
	}
	return out
}

// TestDownloadQuestion: db update on a terminal says how much it downloads, and asks; --yes, KANAREIKA_YES
// and no terminal don't ask.
func TestDownloadQuestion(t *testing.T) {
	sandbox(t)
	fakeDownloads(t, nil, nil)
	tty := onTTY(t, "n\n")
	if code, _, errs := cli(t, "db", "update"); code != 1 || !strings.Contains(errs, "nothing downloaded") {
		t.Fatal(code, errs)
	}
	if tty.String() != "Download the vulnerability list (841 MB)? [Y/n] " { // the Java DB: only when a scan meets .jar files
		t.Fatalf("%q", tty)
	}
	// Enter: yes
	onTTY(t, "\n")
	if code, out, _ := cli(t, "db", "update"); code != 0 || !strings.Contains(out, "KEV: 3 CVEs") {
		t.Fatal(code, out)
	}
	// the vulnerability DBs are there now; the IP database that failed (db-ip.com blocked) is optional: not asked
	tty = onTTY(t, "n\n")
	if code, _, _ := cli(t, "db", "update"); code != 0 || tty.Len() != 0 {
		t.Fatal(code, tty)
	}
	// not asked: --yes, KANAREIKA_YES, no terminal, no /dev/tty
	for _, c := range []struct {
		args []string
		env  string
	}{{[]string{"db", "update", "--yes"}, ""}, {[]string{"db", "update"}, "1"}} {
		tty = onTTY(t, "n\n")
		t.Setenv("KANAREIKA_YES", c.env)
		if code, _, _ := cli(t, c.args...); code != 0 || tty.Len() != 0 {
			t.Fatal(c, code, tty)
		}
	}
	t.Setenv("KANAREIKA_YES", "")
	tty = onTTY(t, "n\n")
	stdinIsTTY = func() bool { return false }
	if code, _, _ := cli(t, "db", "update"); code != 0 || tty.Len() != 0 {
		t.Fatal(code, tty)
	}
	stdinIsTTY = func() bool { return true }
	openTTY = func() (io.ReadWriteCloser, error) { return nil, errors.New("no tty") }
	if code, _, _ := cli(t, "db", "update"); code != 0 {
		t.Fatal(code)
	}
}

// TestDownloadNo: Ctrl-D is no, and KANAREIKA_YES=0 does not say yes.
func TestDownloadNo(t *testing.T) {
	sandbox(t)
	fakeDownloads(t, nil, nil)
	tty := onTTY(t, "") // Ctrl-D: EOF
	if code, _, errs := cli(t, "db", "update"); code != 1 || !strings.Contains(errs, "nothing downloaded") || !strings.Contains(tty.String(), "[Y/n]") {
		t.Fatal(code, errs, tty)
	}
	for _, v := range []string{"0", "false", "no"} {
		t.Setenv("KANAREIKA_YES", v)
		tty = onTTY(t, "n\n")
		if code, _, _ := cli(t, "db", "update"); code != 1 || !strings.Contains(tty.String(), "[Y/n]") {
			t.Fatal(v, code, tty)
		}
	}
	for _, v := range []string{"true", "YES", "y"} {
		t.Setenv("KANAREIKA_YES", v)
		tty = onTTY(t, "n\n")
		if code, _, _ := cli(t, "db", "update"); code != 0 || tty.Len() != 0 {
			t.Fatal(v, code, tty)
		}
	}
}

// TestScanDeclinedWithCache: no to the download with an outdated cached DB scans with it, as --offline.
func TestScanDeclinedWithCache(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	old := runOrg
	t.Cleanup(func() { runOrg = old })
	var opts []scan.Options
	runOrg = func(_ context.Context, _ *scan.Scanner, _ *config.Org, _ string, o scan.Options) int {
		opts = append(opts, o)
		return 0
	}
	write(t, filepath.Join(os.Getenv("TRIVY_CACHE_DIR"), "db", "metadata.json"),
		`{"UpdatedAt":"2026-10-01T00:00:00Z","NextUpdate":"2026-10-01T06:00:00Z"}`)
	tty := onTTY(t, "n\n")
	code, _, errs := cli(t, "scan", "acme", "--env", "production")
	if code != 0 || len(opts) != 1 || !opts[0].Offline || !strings.Contains(tty.String(), "[Y/n]") ||
		!strings.Contains(errs, "Scanning with the cached vulnerability DB from 2026-") {
		t.Fatal(code, opts, errs, tty)
	}
	if age(50*time.Hour) != "2d" || age(5*time.Hour) != "5h" || age(time.Minute) != "under an hour" {
		t.Fatal(age(50 * time.Hour))
	}
}

// TestScanAsksForDBs: a scan that would download the DBs asks first on a terminal; no: it does not start.
func TestScanAsksForDBs(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	old := runOrg
	t.Cleanup(func() { runOrg = old })
	ran := 0
	runOrg = func(context.Context, *scan.Scanner, *config.Org, string, scan.Options) int { ran++; return 0 }
	tty := onTTY(t, "no\n")
	code, _, errs := cli(t, "scan", "acme", "--env", "production")
	if ran != 0 {
		t.Fatal("scanned")
	}
	if code != 1 || !strings.Contains(errs, "refusing to scan: the vulnerability DBs are not downloaded") || !strings.Contains(tty.String(), "[Y/n]") {
		t.Fatal(code, errs, tty)
	}
	onTTY(t, "y\n")
	if code, _, _ := cli(t, "scan", "acme", "--env", "production"); code != 0 || ran != 1 {
		t.Fatal(code, ran)
	}
	tty = onTTY(t, "n\n") // --offline and --dry-run download nothing: not asked
	if code, _, _ := cli(t, "scan", "acme", "--env", "production", "--dry-run"); code != 0 || tty.Len() != 0 {
		t.Fatal(code, tty)
	}
}
