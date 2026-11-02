// Package cli: the kanareika command line (cobra). Commands and flags match the earlier Python CLI, so Makefile
// targets and habits keep working.
package cli

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mikekosulin/kanareika/internal/config"
)

// exitError carries an exit code through cobra.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func fail(code int, format string, a ...any) error {
	return &exitError{code, fmt.Sprintf(format, a...)}
}

type app struct {
	version string
	paths   config.Paths
}

// Execute runs the CLI and returns the process exit code.
func Execute(version string, args []string) int {
	a := &app{version: version, paths: config.NewPaths()}
	root := &cobra.Command{
		Use:           "kanareika",
		Short:         "Read-only vulnerability audit of our servers, per organization",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(a.validateCmd(), a.showCmd(), a.migrateCmd(), a.helperCmd(),
		a.scanCmd(), a.historyCmd(), a.diffCmd(), a.pruneCmd(), a.feedsCmd(), a.serveCmd(), a.mcpCmd())
	root.SetArgs(args)
	err := root.Execute()
	var ee *exitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		if ee.msg != "" {
			fmt.Fprintln(os.Stderr, ee.msg)
		}
		return ee.code
	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
}

// load validates ALL orgs: a cross-org address overlap blocks every scan. Unknown org ids are an error.
func (a *app) load(ids []string) ([]*config.Org, map[string]*config.Org, error) {
	l, err := config.NewLoader(a.paths)
	if err != nil {
		return nil, nil, fail(2, "config error:\n%v", err)
	}
	orgs, errs := l.LoadAll()
	if len(errs) > 0 {
		return nil, nil, fail(2, "validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	byID := map[string]*config.Org{}
	for _, o := range orgs {
		byID[o.ID] = o
		for _, m := range o.Migrated {
			fmt.Fprintf(os.Stderr, "note: %s is in an older format (%s); `kanareika migrate` updates the file\n", o.Path, m)
		}
	}
	for _, id := range ids {
		if byID[id] == nil {
			known := make([]string, 0, len(byID))
			for k := range byID {
				known = append(known, k)
			}
			sort.Strings(known)
			if len(known) == 0 {
				known = []string{"none"}
			}
			return nil, nil, fail(1, "unknown org '%s' (known: %s)", id, strings.Join(known, ", "))
		}
	}
	return orgs, byID, nil
}

// envs: one environment per run; an org with several must name one.
func envs(o *config.Org, env string) ([]string, error) {
	all := o.Envs()
	if env != "" {
		for _, e := range all {
			if e == env {
				return []string{env}, nil
			}
		}
		return nil, fail(1, "%s: unknown env '%s' (known: %s)", o.ID, env, strings.Join(all, ", "))
	}
	if len(all) > 1 {
		return nil, fail(1, "%s has several environments (%s): specify --env", o.ID, strings.Join(all, ", "))
	}
	return all, nil
}
