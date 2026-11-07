// Package cli: the kanareika command line (cobra). Everything kanareika does is a command of the binary; the
// Makefile only builds and tests it.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	home    string // --home
	paths   config.Paths
}

// Execute runs the CLI and returns the process exit code.
func Execute(version string, args []string) int {
	return execute(version, args, os.Stdin, os.Stdout, os.Stderr)
}

func execute(version string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	a := &app{version: version}
	root := &cobra.Command{
		Use:   "kanareika",
		Short: "Read-only vulnerability audit of our servers, per organization",
		Long: `Agentless, read-only security audit of servers over SSH, one YAML per organization.

Three interfaces over the same data:
  kanareika            full-screen terminal interface (TUI); same as "kanareika tui"
  kanareika web        web interface at http://127.0.0.1:8088
  kanareika <command>  commands, for scripts and cron (below)

Start:   kanareika init && kanareika org new acme   (then describe hosts in orgs/acme.yml)
Check:   kanareika validate acme
Scan:    kanareika db update && kanareika scan acme

The working directory holds orgs/, secrets/, reports/ (and optional policy/ overrides): the current
directory, or KANAREIKA_HOME, or --home.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		// no command: the TUI in a terminal, the help elsewhere (a script must never hang on a screen)
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !isTerminal() {
				return cmd.Help()
			}
			return a.tuiRun(cmd, tuiFlags{})
		},
		Args: cobra.NoArgs,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			home := a.home
			if home == "" {
				home = os.Getenv("KANAREIKA_HOME")
			}
			if home == "" {
				home = "."
			}
			abs, err := filepath.Abs(home)
			if err != nil {
				return err
			}
			a.paths = config.PathsAt(abs)
			return nil
		},
	}
	root.PersistentFlags().StringVar(&a.home, "home", "", "working directory with orgs/, secrets/, reports/ (default: KANAREIKA_HOME, else the current directory)")
	root.AddCommand(a.initCmd(), a.orgCmd(), a.validateCmd(), a.showCmd(), a.migrateCmd(), a.helperCmd(),
		a.scanCmd(), a.historyCmd(), a.diffCmd(), a.pruneCmd(), a.dbCmd(), a.feedsCmd(), a.webCmd(), a.tuiCmd(), a.mcpCmd(),
		a.versionCmd())
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.Execute()
	var ee *exitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		if ee.msg != "" {
			fmt.Fprintln(stderr, ee.msg)
		}
		return ee.code
	default:
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
}

// orgIDs: orgs named as arguments and with --org (the older spelling), in order, without repeats.
func orgIDs(args, flags []string) []string {
	var out []string
	for _, id := range append(append([]string{}, args...), flags...) {
		if !contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// oneOrg: exactly one org, as an argument or --org.
func oneOrg(args []string, flag string) (string, error) {
	var flags []string
	if flag != "" {
		flags = []string{flag}
	}
	if ids := orgIDs(args, flags); len(ids) == 1 {
		return ids[0], nil
	}
	return "", fail(1, "specify one org: <org> or --org <org>")
}

// load validates ALL orgs: a cross-org address overlap blocks every scan. Unknown org ids are an error.
func (a *app) load(ids []string, stderr io.Writer) ([]*config.Org, map[string]*config.Org, error) {
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
			fmt.Fprintf(stderr, "note: %s is in an older format (%s); `kanareika migrate` updates the file\n", o.Path, m)
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
				known = []string{"none: `kanareika org new <id>` creates one"}
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

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
