package cli

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/scan"
	"github.com/mikekosulin/kanareika/internal/server"
)

func TestServe(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	oldServe := serveFunc
	t.Cleanup(func() { serveFunc = oldServe })
	var host string
	var port int
	var srv *server.Server
	serveFunc = func(_ context.Context, s *server.Server, h string, p int, out io.Writer) error {
		srv, host, port = s, h, p
		_, _ = io.WriteString(out, "listening\n")
		return nil
	}
	code, _, errs := cli(t, "web")
	if code != 0 || host != "127.0.0.1" || port != 8088 || srv == nil || !strings.Contains(errs, "listening") {
		t.Fatal(code, host, port, errs)
	}
	if code, _, _ := cli(t, "web", "--host", "0.0.0.0", "--port", "9000", "--token", "x", "--no-scans"); code != 0 ||
		host != "0.0.0.0" || port != 9000 {
		t.Fatal(code, host, port)
	}
	if code, _, _ := cli(t, "web", "extra"); code != 1 {
		t.Fatal("arguments are refused")
	}
}

// TestDashboardScan: a dashboard request becomes the same scan the CLI runs.
func TestDashboardScan(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	var got scan.Options
	var gotEnv string
	var gotOut io.Writer
	old := runOrg
	t.Cleanup(func() { runOrg = old })
	runOrg = func(_ context.Context, s *scan.Scanner, _ *config.Org, env string, opt scan.Options) int {
		got, gotEnv, gotOut = opt, env, s.Out
		if s.Err != s.Out {
			t.Fatal("log and plan go to the same job output")
		}
		return 3
	}
	a := &app{version: "v1"}
	var out bytes.Buffer
	rc := a.dashboardScan(context.Background(), &config.Org{ID: "acme"}, server.ScanRequest{Org: "acme", Env: "staging",
		Hosts: []string{"h"}, Groups: []string{"g"}, Modules: []string{"os_packages"}, DryRun: true, IgnoreWindow: true,
		Offline: true}, &out)
	if rc != 3 || gotEnv != "staging" || gotOut != &out || !slices.Equal(got.Hosts, []string{"h"}) ||
		!slices.Equal(got.Groups, []string{"g"}) || !got.DryRun || !got.IgnoreWindow || !got.Offline ||
		got.Parallel != 4 || got.Version != "v1" {
		t.Fatalf("%+v", got)
	}
}
