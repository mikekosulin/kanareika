package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/dbget"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/scan"
)

// onProgressTTY: stderr is a terminal of width columns, redrawn quickly.
func onProgressTTY(t *testing.T, width int) {
	t.Helper()
	oldP, oldR := progressTTY, redrawEvery
	t.Cleanup(func() { progressTTY, redrawEvery = oldP, oldR })
	progressTTY = func(io.Writer) (int, bool) { return width, true }
	redrawEvery = 5 * time.Millisecond
}

// TestProgressScreen: on a terminal the downloads are redrawn in place: a bar, MB, speed and time left per
// download, a total line; lines never wrap.
func TestProgressScreen(t *testing.T) {
	onProgressTTY(t, 140)
	var out bytes.Buffer
	half := make(chan struct{})
	jobs := []dbget.Job{
		{Name: "db", Label: dbget.Labels["db"], Run: func(_ context.Context, p *dbget.Progress) error {
			p.Start(139e6)
			_, _ = io.Copy(io.Discard, p.Reader(io.LimitReader(zeros{}, 71e6)))
			p.Note("ghcr.io: too many requests (429), trying mirror.gcr.io")
			<-half
			_, _ = io.Copy(io.Discard, p.Reader(io.LimitReader(zeros{}, 68e6)))
			p.Note("from mirror.gcr.io")
			return nil
		}},
		{Name: "kev", Label: dbget.Labels["kev"], Run: func(_ context.Context, p *dbget.Progress) error {
			p.Cached("already up to date (cached)")
			return nil
		}},
		{Name: "dbip-city", Label: dbget.Labels["dbip-city"], Optional: true, Run: func(context.Context, *dbget.Progress) error {
			return &dbget.TimeoutError{What: "timed out", After: 30 * time.Second}
		}},
	}
	go func() { time.Sleep(60 * time.Millisecond); close(half) }()
	errs := runDownloads(context.Background(), &out, jobs)
	if len(errs) != 1 {
		t.Fatal(errs)
	}
	s := out.String()
	for _, want := range []string{"\x1b[?25l", "\x1b[4A", "\r\x1b[2K", "Vulnerability DB (trivy-db)", "71.0 / 139.0 MB",
		"ghcr.io: too many requests (429), trying mirror.gcr.io", "█", "░", "CISA KEV", "✓ already up to date (cached)",
		"IP locations (DB-IP city)", "✗ timed out after 30 s", "Total", "139.0 / 139.0 MB", "139.0 MB  done from mirror.gcr.io", "\x1b[?25h"} {
		if !strings.Contains(s, want) {
			t.Fatalf("no %q in\n%s", want, s)
		}
	}
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimPrefix(strings.TrimPrefix(l, "\x1b[4A"), "\r\x1b[2K")
		if n := utf8.RuneCountInString(l); n > 140 {
			t.Fatalf("%d columns: %q", n, l)
		}
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// TestScreenLines: one frame, with speed and time left, and lines cut to the width.
func TestScreenLines(t *testing.T) {
	eta := int64(8)
	big := int64(4000)
	s := dbget.Snapshot{Items: []dbget.Item{
		{Name: "db", Label: "Vulnerability DB (trivy-db)", Bytes: 71e6, Total: 139e6, Speed: 8_200_000, ETA: &eta, State: dbget.Downloading},
		{Name: "dbip-asn", Label: "IP networks (DB-IP ASN)", State: dbget.Queued},
		{Name: "epss", Label: "EPSS scores", Bytes: 2e6, Total: 2e6, State: dbget.Done, Note: "in 1 s"},
		{Name: "kev", Label: "CISA KEV", Bytes: 5e5, State: dbget.Downloading},
	}, Totals: dbget.Totals{Bytes: 73.5e6, Total: 141e6, Speed: 8_200_000, ETA: &big}}
	lines := screen(s, 200)
	want := []string{
		"  Vulnerability DB (trivy-db)  [███████████░░░░░░░░░░░] 71.0 / 139.0 MB  8.2 MB/s  0:08 left",
		"  IP networks (DB-IP ASN)      queued",
		"  EPSS scores                  [██████████████████████] 2.0 MB  done in 1 s",
		"  CISA KEV                     [······················] 0.5 MB",
		"  Total                        [███████████░░░░░░░░░░░] 73.5 / 141.0 MB  8.2 MB/s  1:06:40 left",
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("%q", lines)
	}
	// 80 columns: a shorter bar, the numbers stay
	if l := screen(s, 80)[0]; utf8.RuneCountInString(l) > 79 || !strings.HasSuffix(l, "8.2 MB/s  0:08 left") {
		t.Fatal(l)
	}
	if l := screen(s, 40)[0]; utf8.RuneCountInString(l) != 39 || !strings.HasSuffix(l, "…") {
		t.Fatal(l)
	}
	if screen(dbget.Snapshot{}, 80) != nil {
		t.Fatal("lines without downloads")
	}
}

// TestPlainLines: without a terminal, a line per start, change and end.
func TestPlainLines(t *testing.T) {
	for it, want := range map[dbget.Item]string{
		{Label: "DB", State: dbget.Downloading, Total: 139e6}:                            "DB: downloading 139 MB",
		{Label: "DB", State: dbget.Downloading}:                                          "DB: downloading",
		{Label: "DB", State: dbget.Downloading, Note: "a: unauthorized (401), trying b"}: "DB: a: unauthorized (401), trying b",
		{Label: "DB", State: dbget.Done, Bytes: 139e6, Note: "from b"}:                   "DB: done, 139 MB from b",
		{Label: "DB", State: dbget.Cached, Note: "already up to date (cached)"}:          "DB: already up to date (cached)",
		{Label: "DB", State: dbget.Failed, Note: "no mirror worked: a: x; b: y"}:         "DB: failed: no mirror worked: a: x; b: y",
		{Label: "DB", State: dbget.Queued}:                                               "",
	} {
		if got := plainLine(it); got != want {
			t.Errorf("%q, want %q", got, want)
		}
	}
}

// TestScanDownloadsFirst: a scan on a terminal downloads what it needs first, with the progress screen, after the
// question; without a terminal it leaves the downloads to the scan.
func TestScanDownloadsFirst(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	old := runOrg
	t.Cleanup(func() { runOrg = old })
	runOrg = func(context.Context, *scan.Scanner, *config.Org, string, scan.Options) int { return 0 }
	oldJ := downloadJobs
	t.Cleanup(func() { downloadJobs = oldJ })
	var asked []string
	downloadJobs = func(_ *priority.Policy, names []string) []dbget.Job {
		asked = names
		var jobs []dbget.Job
		for _, n := range names {
			jobs = append(jobs, dbget.Job{Name: n, Label: dbget.Labels[n], Run: func(context.Context, *dbget.Progress) error {
				if n == "db" {
					return errors.New("registry down")
				}
				return nil
			}})
		}
		return jobs
	}
	if code, _, _ := cli(t, "scan", "acme", "--env", "production", "--yes"); code != 0 || asked != nil {
		t.Fatal("downloaded without a terminal", code, asked)
	}
	onProgressTTY(t, 100)
	onTTY(t, "y\n")
	code, _, errs := cli(t, "scan", "acme", "--env", "production")
	if code != 0 || !slices.Contains(asked, "db") || !slices.Contains(asked, "kev") ||
		!strings.Contains(errs, "Downloading the vulnerability databases first") || !strings.Contains(errs, "✗ registry down") {
		t.Fatal(code, asked, errs)
	}
}
