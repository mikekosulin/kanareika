package cli

import (
	"io"
	"log"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/prompt"
	"github.com/mikekosulin/kanareika/internal/server"
	"github.com/mikekosulin/kanareika/internal/tui"
)

// isTerminal: stdin and stdout are a terminal (the TUI can run); tests replace it.
var isTerminal = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// runTUI runs the program; tests replace it.
var runTUI = func(m *tui.Model, in io.Reader, out io.Writer) error {
	_, err := tea.NewProgram(m, tea.WithAltScreen(), tea.WithInput(in), tea.WithOutput(out)).Run()
	return err
}

// langFromEnv: the interface language from LANG/LC_ALL (ru_RU.UTF-8 -> ru), "" when unknown.
func langFromEnv() string {
	for _, k := range []string{"KANAREIKA_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" && v != "C" && v != "POSIX" {
			l, _, _ := strings.Cut(v, "_")
			l, _, _ = strings.Cut(l, ".")
			return strings.ToLower(l)
		}
	}
	return ""
}

type tuiFlags struct {
	url, token, lang, org, env string
}

func (a *app) tuiRun(cmd *cobra.Command, f tuiFlags) error {
	limitReaderMemory()
	var c tui.Client
	if f.url != "" {
		c = tui.Remote(f.url, f.token)
	} else {
		s, err := newServer(server.Options{Paths: a.paths, Prompt: prompt.Build, Warm: true, Scan: a.dashboardScan, UpdateDB: a.updateDBFunc,
			Log: log.New(io.Discard, "", 0)}) // nothing may write to the terminal under the TUI
		if err != nil {
			return err
		}
		defer s.Close()
		c = tui.Local(s.Handler())
	}
	if f.lang == "" {
		f.lang = langFromEnv()
	}
	out := tui.SyncWriter(cmd.OutOrStdout()) // the frames and the clipboard sequence, never one inside the other
	m := tui.New(tui.Options{Client: c, Lang: f.lang, Org: f.org, Env: f.env, Clip: out,
		Settings: tui.DefaultSettingsPath()})
	return runTUI(m, cmd.InOrStdin(), out)
}

func (a *app) tuiCmd() *cobra.Command {
	var f tuiFlags
	c := &cobra.Command{
		Use:   "tui",
		Short: "full-screen terminal interface (also: kanareika with no command)",
		Long: `The terminal interface: organizations and environments, the to-do list by priority, hosts,
packages, runs, and scans started and watched from it. Keys: ? in the interface.

By default it works on the local working directory. --url connects to a running "kanareika web"
instead (with --token when it has one).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return a.tuiRun(cmd, f) },
	}
	c.Flags().StringVar(&f.url, "url", "", "a running kanareika web, e.g. http://127.0.0.1:8088")
	c.Flags().StringVar(&f.token, "token", os.Getenv("KANAREIKA_TOKEN"), "its access token (env KANAREIKA_TOKEN)")
	c.Flags().StringVar(&f.lang, "lang", "", "interface language: "+strings.Join(i18n.Langs(), ", ")+" (default: from LANG)")
	c.Flags().StringVar(&f.org, "org", "", "open this org")
	c.Flags().StringVar(&f.env, "env", "", "open this environment")
	return c
}
