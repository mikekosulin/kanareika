package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"syscall"
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

// TestServeNoScans: --no-scans is read-only for the vulnerability DB too: no update, no size lookup.
func TestServeNoScans(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	oldServe := serveFunc
	t.Cleanup(func() { serveFunc = oldServe })
	var srv *server.Server
	serveFunc = func(_ context.Context, s *server.Server, _ string, _ int, _ io.Writer) error { srv = s; return nil }
	get := func(method, path string) (int, string) {
		r := httptest.NewRequest(method, path, nil)
		r.Host = "127.0.0.1:8088"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	if code, _, errs := cli(t, "web", "--no-scans"); code != 0 {
		t.Fatal(code, errs)
	}
	if c, _ := get("GET", "/api/db/size"); c != 403 {
		t.Errorf("size lookup: %d, want 403", c)
	}
	if _, body := get("GET", "/api/db"); !strings.Contains(body, `"enabled":false`) {
		t.Errorf("/api/db: %s", body)
	}
	if code, _, errs := cli(t, "web"); code != 0 {
		t.Fatal(code, errs)
	}
	if _, body := get("GET", "/api/db"); !strings.Contains(body, `"enabled":true`) {
		t.Errorf("without --no-scans, updates are on: %s", body)
	}
}

// TestServeEnvAndPort:KANAREIKA_HOST / KANAREIKA_PORT give the defaults, flags win over them, bad ports are
// refused before listening, and a busy port says what to do.
func TestServeEnvAndPort(t *testing.T) {
	sandbox(t)
	fixtureOrg(t)
	oldServe := serveFunc
	t.Cleanup(func() { serveFunc = oldServe })
	var host string
	var port int
	var fail error
	serveFunc = func(_ context.Context, _ *server.Server, h string, p int, _ io.Writer) error {
		host, port = h, p
		return fail
	}
	t.Setenv("KANAREIKA_HOST", "::1")
	t.Setenv("KANAREIKA_PORT", "9123")
	if code, _, errs := cli(t, "web"); code != 0 || host != "::1" || port != 9123 {
		t.Fatal(code, host, port, errs)
	}
	if code, _, _ := cli(t, "web", "--port", "0", "--host", "127.0.0.1"); code != 0 || host != "127.0.0.1" || port != 0 {
		t.Fatal("flags win over the environment:", code, host, port)
	}
	t.Setenv("KANAREIKA_PORT", "http")
	if code, _, errs := cli(t, "web"); code != 1 || !strings.Contains(errs, "KANAREIKA_PORT") {
		t.Fatal(code, errs)
	}
	t.Setenv("KANAREIKA_PORT", "")
	if code, _, errs := cli(t, "web", "--port", "70000"); code != 1 || !strings.Contains(errs, "0-65535") {
		t.Fatal(code, errs)
	}
	fail = &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	if code, _, errs := cli(t, "web", "--port", "8791"); code != 1 || !strings.Contains(errs, "port 8791 is busy") ||
		!strings.Contains(errs, "--port 0") {
		t.Fatal(code, errs)
	}
	fail = errors.New("listen tcp: Only one usage of each socket address (protocol/network address/port) is normally permitted.")
	if code, _, errs := cli(t, "web"); code != 1 || !strings.Contains(errs, "is busy") {
		t.Fatal("the Windows wording too:", code, errs)
	}
	fail = errors.New("listen tcp: permission denied")
	if code, _, errs := cli(t, "web"); code != 1 || strings.Contains(errs, "is busy") {
		t.Fatal("other errors pass through:", code, errs)
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
		got.Parallel != 0 || got.Version != "v1" { // 0: the settings decide
		t.Fatalf("%+v", got)
	}
}
