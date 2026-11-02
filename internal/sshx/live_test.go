package sshx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
)

// TestLive: a manual read-only smoke test against real hosts of a local org file, through the local ssh-agent.
//
//	KANAREIKA_LIVE_ORG=<org id> KANAREIKA_LIVE_HOSTS=host-a,host-b go test -run TestLive -v ./internal/sshx
//
// Only `hostname; uname -r` is sent, and only to the hosts named in KANAREIKA_LIVE_HOSTS (nothing is contacted by
// default); learned keys go to a temp reports dir, never to reports/. Org and host names stay out of the repository.
func TestLive(t *testing.T) {
	orgID, names := os.Getenv("KANAREIKA_LIVE_ORG"), os.Getenv("KANAREIKA_LIVE_HOSTS")
	if orgID == "" || names == "" {
		t.Skip("set KANAREIKA_LIVE_ORG and KANAREIKA_LIVE_HOSTS")
	}
	root, _ := filepath.Abs("../..")
	p := config.PathsAt(root)
	p.Reports = t.TempDir()
	l, err := config.NewLoader(p)
	must(t, err)
	org, errs := l.LoadOrg(filepath.Join(p.Orgs, orgID+".yml"))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	o, err := New(org, p)
	must(t, err)
	defer o.Close()
	for _, name := range strings.Split(names, ",") {
		h := host(org, strings.TrimSpace(name))
		start := time.Now()
		out, err := o.Run(ctx, h, "hostname; uname -r", 60*time.Second, true)
		if err != nil {
			t.Errorf("%s: %v", h.Name, err)
			continue
		}
		t.Logf("%s (legacy_ssh=%v, jump=%q, %s): %s", h.Name, h.LegacySSH, h.Jump,
			time.Since(start).Round(time.Millisecond), strings.Join(strings.Fields(out), " "))
	}
	b, _ := os.ReadFile(filepath.Join(p.Reports, org.ID, "known_hosts"))
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if f := strings.Fields(line); len(f) >= 2 {
			t.Logf("learned: %s %s", f[0], f[1])
		}
	}
}
