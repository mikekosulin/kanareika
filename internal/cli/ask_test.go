package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

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
	// the vulnerability DBs are there now: only the rest is asked about
	tty = onTTY(t, "y\n")
	if code, _, _ := cli(t, "db", "update"); code != 0 || tty.String() != "Download the vulnerability list (41 MB)? [Y/n] " {
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
