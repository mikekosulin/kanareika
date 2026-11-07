// Package engine is trivy itself, linked into kanareika: `kanareika __trivy <trivy args>` behaves exactly as the
// trivy binary of the same version (its cmd/trivy/main.go, minus plugins, which kanareika never runs).
//
// Only cmd/kanareika imports this package: trivy brings a large dependency tree, and the rest of kanareika (and
// its tests) talks to trivy through package trivy, as a child process.
package engine

import (
	"context"
	"errors"
	"os"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB, as trivy's own main imports it
)

// run is commands.Run; tests replace it.
var run = commands.Run

// Main runs trivy with args (what follows the hidden command) and returns the process exit code. Fatal errors are
// logged by trivy's logger and end the process with code 1, as in trivy.
func Main(args []string) int {
	os.Args = append([]string{"trivy"}, args...) // trivy's cobra root reads os.Args
	err := func() error {
		defer func() { _ = commands.Cleanup() }()
		return run(commands.NotifyContext(context.Background()))
	}()
	if err == nil {
		return 0
	}
	if exitError, ok := errors.AsType[*types.ExitError](err); ok {
		return exitError.Code
	}
	if userErr, ok := errors.AsType[*types.UserError](err); ok {
		fatal("Error", log.Err(userErr))
		return 1
	}
	fatal("Fatal error", log.Err(err))
	return 1
}

// fatal is log.Fatal (which exits); tests replace it.
var fatal = func(msg string, args ...any) { log.Fatal(msg, args...) }
