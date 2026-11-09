package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/mikekosulin/kanareika/internal/dbget"
	"github.com/mikekosulin/kanareika/internal/dbsize"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// downloadJobs: the downloads by name ("db", "java-db", "kev", "epss", "dbip-city", "dbip-asn"), in dbget.Order;
// tests replace it (the real ones need the network).
var downloadJobs = func(pol *priority.Policy, names []string) []dbget.Job {
	var jobs []dbget.Job
	for _, n := range names {
		switch n {
		case "db", "java-db":
			jobs = append(jobs, trivy.Job(n, nil)) // its progress is the log
		case "kev":
			jobs = append(jobs, feedJob(n, func(ctx context.Context, p *dbget.Progress) error {
				_, err := priority.FetchKEV(ctx, pol, p)
				return err
			}))
		case "epss":
			jobs = append(jobs, feedJob(n, func(ctx context.Context, p *dbget.Progress) error {
				_, err := priority.FetchEPSS(ctx, pol, p)
				return err
			}))
		case "dbip-city", "dbip-asn":
			kind := strings.TrimPrefix(n, "dbip-")
			j := feedJob(n, func(ctx context.Context, p *dbget.Progress) error {
				_, _, err := priority.FetchIPDB(ctx, kind, p)
				if err != nil && priority.IPDBMonth(kind) != "" {
					return dbget.Kept(err, "the file from "+priority.IPDBMonth(kind)+" stays in use")
				}
				return err
			})
			j.Optional = true // IP lookups are a nicety: an update without them still succeeds
			jobs = append(jobs, j)
		}
	}
	dbget.Sort(jobs)
	return jobs
}

// feedJob: KEV or EPSS; a failure keeps the copy on disk when there is one.
func feedJob(name string, run func(context.Context, *dbget.Progress) error) dbget.Job {
	return dbget.Job{Name: name, Label: dbget.Labels[name], Run: func(ctx context.Context, p *dbget.Progress) error {
		err := run(ctx, p)
		if err == nil || ctx.Err() != nil || strings.HasPrefix(name, "dbip-") {
			return err
		}
		// the other feed may be writing its file right now: only this one's file and the stamp are read
		stamp, _ := os.ReadFile(filepath.Join(priority.FeedsDir(), "updated"))
		at, terr := priority.FeedsTime(string(stamp))
		if _, serr := os.Stat(filepath.Join(priority.FeedsDir(), name+".json")); terr == nil && serr == nil {
			return dbget.Kept(err, "the copy from "+at.UTC().Format("2006-01-02 15:04Z")+" stays in use")
		}
		return err
	}}
}

// downloadFirst: on a terminal, what a scan would download (dbsize.Need: the same list the download question
// named) is downloaded before it starts, with the live progress screen; the scan's own preparation then finds it
// fresh. A failure is left to the scan, which goes on with a cached copy or refuses. Elsewhere the scan downloads
// by itself and logs it.
func (a *app) downloadFirst(ctx context.Context, w io.Writer) {
	if _, tty := progressTTY(w); !tty {
		return
	}
	need := dbsize.Need(time.Now())
	if len(need) == 0 {
		return
	}
	pol, err := priority.LoadPolicy(a.paths)
	if err != nil {
		return // the scan reports a broken policy where it is used
	}
	fmt.Fprintln(w, "Downloading the vulnerability databases first:")
	errs := runDownloads(ctx, w, downloadJobs(pol, need))
	if slices.Contains(need, "kev") && errs["kev"] == nil && errs["epss"] == nil {
		_ = priority.Stamp()
	}
}

// progressTTY: whether w is a terminal to redraw progress on, and its width; tests replace it.
var progressTTY = func(w io.Writer) (int, bool) {
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return 0, false
	}
	width, _, err := term.GetSize(int(f.Fd()))
	if err != nil || width < 40 {
		width = 80
	}
	return width, true
}

// redrawEvery: how often the terminal progress is redrawn.
var redrawEvery = 200 * time.Millisecond

// runDownloads: the jobs in parallel. On a terminal a live screen (a bar, MB, speed and time left per download, a
// total line) is redrawn in place on w; elsewhere a line per start, mirror change and end. The context's tracker
// (an update started from the web page or the TUI) gets the progress for /api/db.
func runDownloads(ctx context.Context, w io.Writer, jobs []dbget.Job) map[string]error {
	t := dbget.TrackerFrom(ctx)
	if t == nil {
		t = dbget.NewTracker()
	}
	width, tty := progressTTY(w)
	if !tty {
		var mu sync.Mutex
		t.OnEvent = func(it dbget.Item) {
			if line := plainLine(it); line != "" {
				mu.Lock()
				fmt.Fprintln(w, line)
				mu.Unlock()
			}
		}
		return t.Run(ctx, jobs)
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		fmt.Fprint(w, "\x1b[?25l") // no cursor blinking over the bars
		defer fmt.Fprint(w, "\x1b[?25h")
		tick := time.NewTicker(redrawEvery)
		defer tick.Stop()
		drawn := 0
		for {
			select {
			case <-done:
				redraw(w, &drawn, screen(t.Snapshot(), width))
				return
			case <-tick.C:
				redraw(w, &drawn, screen(t.Snapshot(), width))
			}
		}
	}()
	errs := t.Run(ctx, jobs)
	close(done)
	<-finished
	return errs
}

// redraw: lines over the drawn ones (the cursor goes back up), each cleared first.
func redraw(w io.Writer, drawn *int, lines []string) {
	var b strings.Builder
	if *drawn > 0 {
		fmt.Fprintf(&b, "\x1b[%dA", *drawn)
	}
	for _, l := range lines {
		b.WriteString("\r\x1b[2K" + l + "\n")
	}
	for i := len(lines); i < *drawn; i++ {
		b.WriteString("\r\x1b[2K\n")
	}
	*drawn = max(len(lines), *drawn)
	_, _ = io.WriteString(w, b.String())
}

// plainLine: one event as a log line; "" for none.
func plainLine(it dbget.Item) string {
	switch it.State {
	case dbget.Downloading:
		if it.Note != "" {
			return it.Label + ": " + it.Note
		}
		if it.Total > 0 {
			return it.Label + ": downloading " + dbget.Size(it.Total)
		}
		return it.Label + ": downloading"
	case dbget.Done:
		s := it.Label + ": done, " + dbget.Size(it.Bytes)
		if it.Note != "" {
			s += " " + it.Note
		}
		return s
	case dbget.Cached:
		return it.Label + ": " + it.Note
	case dbget.Failed:
		return it.Label + ": failed: " + it.Note
	}
	return ""
}

// barWidth: the bar's cells at most; a narrow terminal gets a shorter bar, so the numbers stay on screen.
const barWidth = 22

func bar(done, total int64, w int) string {
	if total <= 0 {
		return "[" + strings.Repeat("·", w) + "]"
	}
	n := int(float64(w) * float64(min(done, total)) / float64(total))
	return "[" + strings.Repeat("█", n) + strings.Repeat("░", w-n) + "]"
}

func mb(n int64) string { return fmt.Sprintf("%.1f", float64(n)/1e6) }

func clock(eta *int64) string {
	if eta == nil {
		return ""
	}
	s := *eta
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d left", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%d:%02d left", s/60, s%60)
}

// screen: the progress as terminal lines, each at most width-1 columns (a wrapped line would break the redraw).
func screen(s dbget.Snapshot, width int) []string {
	if len(s.Items) == 0 {
		return nil
	}
	lw := len("Total")
	for _, it := range s.Items {
		lw = max(lw, utf8.RuneCountInString(it.Label))
	}
	row := func(label, rest string) string {
		return fit(fmt.Sprintf("  %-*s  %s", lw, label, rest), width-1)
	}
	// after the bar: " 138.6 / 138.6 MB  12.3 MB/s  1:23 left" (39 columns)
	bw := max(8, min(barWidth, width-1-(lw+4)-2-39))
	var out []string
	for _, it := range s.Items {
		var rest string
		switch it.State {
		case dbget.Queued:
			rest = "queued"
		case dbget.Downloading:
			rest = fmt.Sprintf("%s %s", bar(it.Bytes, it.Total, bw), amount(it.Bytes, it.Total))
			if it.Speed > 0 {
				rest += fmt.Sprintf("  %s MB/s", mb(it.Speed))
			}
			if c := clock(it.ETA); c != "" {
				rest += "  " + c
			}
			if it.Note != "" {
				rest += "  " + it.Note
			}
		case dbget.Done:
			rest = fmt.Sprintf("%s %s MB  done %s", bar(1, 1, bw), mb(it.Bytes), it.Note)
		case dbget.Cached:
			rest = "✓ " + it.Note
		case dbget.Failed:
			rest = "✗ " + it.Note
		}
		out = append(out, row(it.Label, strings.TrimRight(rest, " ")))
	}
	tot := s.Totals
	rest := fmt.Sprintf("%s %s", bar(tot.Bytes, tot.Total, bw), amount(tot.Bytes, tot.Total))
	if tot.Speed > 0 {
		rest += fmt.Sprintf("  %s MB/s", mb(tot.Speed))
	}
	if c := clock(tot.ETA); c != "" {
		rest += "  " + c
	}
	return append(out, row("Total", rest))
}

func amount(done, total int64) string {
	if total > 0 {
		return mb(done) + " / " + mb(total) + " MB"
	}
	return mb(done) + " MB"
}

// fit: s cut to n columns (one column per rune: the bars and marks are narrow).
func fit(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
