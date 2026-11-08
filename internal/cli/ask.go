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
)

// The terminal a download question goes to; tests replace them.
var (
	stdinIsTTY = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	openTTY    = func() (io.ReadWriteCloser, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }
)

// confirmDownload: whether to download the DBs, asked on the terminal with how much (dbsize, as the setup says
// it) — on mobile data that matters. Yes without asking with --yes,
// KANAREIKA_YES=1, without a terminal, or when nothing is needed.
func (a *app) confirmDownload(ctx context.Context, yes bool) bool {
	if yes || os.Getenv("KANAREIKA_YES") != "" || !stdinIsTTY() {
		return true
	}
	tty, err := openTTY()
	if err != nil {
		return true
	}
	defer tty.Close()
	pol := priority.Policy{}
	if p, err := priority.LoadPolicy(a.paths); err == nil {
		pol = *p
	}
	r := dbsize.Check(ctx, pol, time.Now(), true)
	if len(r.Need) == 0 {
		return true
	}
	fmt.Fprintf(tty, "Download the vulnerability list (%s)? [Y/n] ", dbsize.Bytes(r.Total))
	line, _ := bufio.NewReader(tty).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true
	}
	return false
}
