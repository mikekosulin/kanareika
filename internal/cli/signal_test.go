//go:build unix

package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/dbsize"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/scan"
)

// TestScanInterrupted: Ctrl+C during a scan stops before the next environment, exit code 130.
func TestScanInterrupted(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	old := runOrg
	t.Cleanup(func() { runOrg = old })
	var envs []string
	runOrg = func(ctx context.Context, _ *scan.Scanner, _ *config.Org, env string, _ scan.Options) int {
		envs = append(envs, env)
		must(t, syscall.Kill(os.Getpid(), syscall.SIGINT))
		<-ctx.Done() // the scan notices the cancelled context and returns
		return 0
	}
	if code, _, errs := cli(t, "scan", "--all"); code != 130 || errs != "interrupted\n" || len(envs) != 1 {
		t.Fatal(code, errs, envs)
	}
}

// ctrlCTTY: a terminal where the user presses Ctrl-C at the question: SIGINT, and no line ever comes.
type ctrlCTTY struct {
	out    *bytes.Buffer
	closed chan struct{}
}

func (c *ctrlCTTY) Read([]byte) (int, error) {
	_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	<-c.closed
	return 0, io.EOF
}
func (c *ctrlCTTY) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *ctrlCTTY) Close() error                { close(c.closed); return nil }

// TestDownloadQuestionCtrlC: Ctrl-C at the question aborts (130), it is not an empty answer, i.e. a yes.
func TestDownloadQuestionCtrlC(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	fakeDownloads(t, nil, nil)
	onTTY(t, "")
	tty := &ctrlCTTY{&bytes.Buffer{}, make(chan struct{})}
	openTTY = func() (io.ReadWriteCloser, error) { return tty, nil }
	dbsize.Lookup = func(context.Context, priority.Policy) map[string]int64 { return map[string]int64{"db": 1} }
	old := runOrg
	t.Cleanup(func() { runOrg = old })
	ran := 0
	runOrg = func(context.Context, *scan.Scanner, *config.Org, string, scan.Options) int { ran++; return 0 }
	code, _, errs := cli(t, "scan", "acme", "--env", "production")
	if code != 130 || errs != "interrupted\n" || ran != 0 || !strings.Contains(tty.out.String(), "[Y/n]") {
		t.Fatal(code, errs, ran, tty.out)
	}
}
