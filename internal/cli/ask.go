package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/mikekosulin/kanareika/internal/dbsize"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/trivy"
)

// The terminal a download question goes to; tests replace them.
var (
	stdinIsTTY = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	openTTY    = func() (io.ReadWriteCloser, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }
)

// envYes: the variable says yes (1, true, yes, y); KANAREIKA_YES=0 does not.
func envYes(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "y":
		return true
	}
	return false
}

// answer: to the download question.
type answer int

const (
	download answer = iota // yes, or not asked
	declined               // n, or Ctrl-D
	aborted                // Ctrl-C at the question
)

// confirmDownload: whether to download the DBs, asked on the terminal with how much (dbsize, as the setup says
// it) — on mobile data that matters. Yes without asking with --yes, KANAREIKA_YES=1, without a terminal, or when
// only the optional IP databases are missing (where db-ip.com is blocked, they'd be asked about every time).
// Enter is yes; n and Ctrl-D are no; Ctrl-C (ctx cancelled) aborts.
func (a *app) confirmDownload(ctx context.Context, yes bool) answer {
	if yes || envYes("KANAREIKA_YES") || !stdinIsTTY() {
		return download
	}
	tty, err := openTTY()
	if err != nil {
		return download
	}
	defer tty.Close()
	pol := priority.Policy{}
	if p, err := priority.LoadPolicy(a.paths); err == nil {
		pol = *p
	}
	r := dbsize.Check(ctx, pol, time.Now(), true)
	if len(dbsize.Required(r.Need)) == 0 {
		return download
	}
	fmt.Fprintf(tty, "Download the vulnerability list (%s)? [Y/n] ", dbsize.Bytes(r.Total))
	type read struct {
		line string
		err  error
	}
	got := make(chan read, 1)
	go func() { // blocks until Enter; Ctrl-C cancels ctx meanwhile
		line, err := bufio.NewReader(tty).ReadString('\n')
		got <- read{line, err}
	}()
	select {
	case <-ctx.Done():
		fmt.Fprintln(tty)
		return aborted
	case r := <-got:
		if r.err != nil { // Ctrl-D, or the terminal went away: not a yes
			fmt.Fprintln(tty)
			return declined
		}
		switch strings.ToLower(strings.TrimSpace(r.line)) {
		case "", "y", "yes":
			return download
		}
		return declined
	}
}

// cachedDB: when the cached vulnerability DB (trivy-db) was downloaded; zero: there is none.
func cachedDB() time.Time {
	for _, d := range trivy.DBStatus() {
		if d.Name == "db" {
			return d.Updated
		}
	}
	return time.Time{}
}

// age: 3d, 5h, under an hour.
func age(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	return "under an hour"
}
