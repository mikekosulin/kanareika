package cli

import (
	"context"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/prompt"
	"github.com/mikekosulin/kanareika/internal/scan"
	"github.com/mikekosulin/kanareika/internal/server"
)

// serveFunc is (*server.Server).Serve; tests replace it.
var serveFunc = func(ctx context.Context, s *server.Server, host string, port int, out io.Writer) error {
	return s.Serve(ctx, host, port, out)
}

// dashboardScan: a scan started from the dashboard, run like `kanareika scan` (plan, log and summary go to the
// job's output on the page).
func (a *app) dashboardScan(ctx context.Context, o *config.Org, req server.ScanRequest, out io.Writer) int {
	s := &scan.Scanner{Paths: a.paths, Out: out, Err: out}
	return runOrg(ctx, s, o, req.Env, scan.Options{Groups: req.Groups, Hosts: req.Hosts, Modules: req.Modules,
		DryRun: req.DryRun, IgnoreWindow: req.IgnoreWindow, Offline: req.Offline, Parallel: 4, Version: a.version})
}

func (a *app) serveCmd() *cobra.Command {
	var host, token string
	var port int
	var noScans bool
	c := &cobra.Command{
		Use:   "serve",
		Short: "web dashboard over reports/; scans can be started from it",
		Long: `The dashboard: findings, hosts, trends, ready fix tasks, and scans started from the page (with
the same options and consent rules as "kanareika scan"; their progress shows live).

It listens on 127.0.0.1 and answers only requests addressed to localhost. To reach it from
elsewhere, bind another --host and set --token (or KANAREIKA_TOKEN): the printed URL carries it
once, the browser keeps it in a cookie. Without a token such a dashboard is read-only.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := server.Options{Paths: a.paths, Prompt: prompt.Build, Token: token}
			if !noScans {
				opts.Scan = a.dashboardScan
			}
			s, err := server.New(opts)
			if err != nil {
				return err
			}
			ctx, stop := interruptible()
			defer stop()
			return serveFunc(ctx, s, host, port, cmd.ErrOrStderr())
		},
	}
	c.Flags().StringVar(&host, "host", server.DefaultHost, "address to listen on (localhost: reports contain addresses and vulnerabilities)")
	c.Flags().IntVar(&port, "port", server.DefaultPort, "port")
	c.Flags().StringVar(&token, "token", os.Getenv("KANAREIKA_TOKEN"), "access token required for every request (env KANAREIKA_TOKEN)")
	c.Flags().BoolVar(&noScans, "no-scans", false, "read-only dashboard: scans can't be started from it")
	return c
}
