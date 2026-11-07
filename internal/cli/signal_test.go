//go:build unix

package cli

import (
	"context"
	"os"
	"syscall"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
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
