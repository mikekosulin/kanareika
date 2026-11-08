package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/prompt"
	"github.com/mikekosulin/kanareika/internal/scan"
	"github.com/mikekosulin/kanareika/internal/server"
)

// newServer is server.New; tests replace it.
var newServer = server.New

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

// updateDBFunc: `db update` as the interfaces start it (its log to the update's output).
func (a *app) updateDBFunc(ctx context.Context, out io.Writer) error {
	return a.updateDBs(ctx, out, out, false)
}

// envDefault: the value of an environment variable, or def when it is unset or empty.
func envDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// addrInUse: listening failed because something else holds the port (EADDRINUSE; on Windows WSAEADDRINUSE,
// which syscall does not name).
func addrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "address already in use") || strings.Contains(s, "only one usage of each socket address")
}

func (a *app) webCmd() *cobra.Command {
	var host, token, portEnv string
	var port int
	var noScans bool
	c := &cobra.Command{
		Use:     "web",
		Aliases: []string{"dashboard", "serve"},
		Short:   "web interface over reports/; scans can be started from it",
		Long: `The web interface: findings, hosts, trends, ready fix tasks, and scans started from the page (with
the same options and consent rules as "kanareika scan"; their progress shows live).

It listens on 127.0.0.1 and answers only requests addressed to localhost. Any port: --port 9000
(or KANAREIKA_PORT), --port 0 for a free one (the printed URL shows which). To reach it from
elsewhere, bind another --host (or KANAREIKA_HOST) and set --token (or KANAREIKA_TOKEN): the
printed URL carries it once, the browser keeps it in a cookie. Without a token it is read-only there.

The TUI can connect to it too: kanareika tui --url http://host:8088 --token ...`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if portEnv != "" && !cmd.Flags().Changed("port") {
				p, err := strconv.Atoi(portEnv)
				if err != nil || p < 0 || p > 65535 {
					return fmt.Errorf("KANAREIKA_PORT=%q: a port number 0-65535 is required", portEnv)
				}
				port = p
			}
			if port < 0 || port > 65535 {
				return fmt.Errorf("--port %d: a port number 0-65535 is required", port)
			}
			opts := server.Options{Paths: a.paths, Prompt: prompt.Build, Token: token, UpdateDB: a.updateDBFunc}
			if !noScans {
				opts.Scan = a.dashboardScan
			}
			s, err := newServer(opts)
			if err != nil {
				return err
			}
			ctx, stop := interruptible()
			defer stop()
			err = serveFunc(ctx, s, host, port, cmd.ErrOrStderr())
			if err != nil && addrInUse(err) {
				return fmt.Errorf("port %d is busy: pick another with --port (or KANAREIKA_PORT), or --port 0 for any free one (%w)", port, err)
			}
			return err
		},
	}
	portEnv = os.Getenv("KANAREIKA_PORT")
	c.Flags().StringVar(&host, "host", envDefault("KANAREIKA_HOST", server.DefaultHost), "address to listen on (env KANAREIKA_HOST; localhost: reports contain addresses and vulnerabilities)")
	c.Flags().IntVar(&port, "port", server.DefaultPort, "port, 0 for any free one (env KANAREIKA_PORT)")
	c.Flags().StringVar(&token, "token", os.Getenv("KANAREIKA_TOKEN"), "access token required for every request (env KANAREIKA_TOKEN)")
	c.Flags().BoolVar(&noScans, "no-scans", false, "read-only: scans can't be started from it")
	return c
}
