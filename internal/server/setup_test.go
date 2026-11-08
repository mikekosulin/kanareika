package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/onboard"
)

type fakeRunner struct{}

func (fakeRunner) Run(_ context.Context, h config.Host, _ string, _ time.Duration, _ bool) (string, error) {
	if h.Name == "web-02" {
		return "", errors.New("ssh: unable to authenticate")
	}
	return "Linux 6.1", nil
}
func (fakeRunner) Close() error { return nil }

// TestSetup: the first-run form creates an org (refusing bad answers with a list, never overwriting), the access
// check logs in to its hosts; both only where scans are allowed, with the CSRF header.
func TestSetup(t *testing.T) {
	p := testHome(t)
	f := &fakeScan{}
	s, h := newTest(t, Options{Paths: p, Scan: f.run})
	oldConn, oldNow := newConn, setupNow
	t.Cleanup(func() { newConn, setupNow = oldConn, oldNow })
	newConn = func(*config.Org, config.Paths) (onboard.Runner, error) { return fakeRunner{}, nil }
	setupNow = func() time.Time { return time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC) }
	form := map[string]any{"id": "neworg", "name": "New Org", "user": "audit", "hosts": "web-01 192.0.2.11\nweb-02 192.0.2.12",
		"consent": "Ticket 7", "confirmed": true}
	if r := do(h, "POST", "/api/setup", form, map[string]string{"Content-Type": "application/json"}); r.code != 403 {
		t.Fatal("no CSRF header:", r.code)
	}
	bad := map[string]any{"id": "Bad Id", "name": "", "user": "audit", "hosts": "", "consent": "", "confirmed": false}
	r := do(h, "POST", "/api/setup", bad, s.postHdr())
	var e struct{ Errors []string }
	if r.code != 400 || json.Unmarshal([]byte(r.body), &e) != nil || len(e.Errors) < 4 {
		t.Fatal(r.code, r.body)
	}
	if r := do(h, "POST", "/api/setup", map[string]any{"nope": 1}, s.postHdr()); r.code != 400 {
		t.Fatal("unknown fields:", r.code)
	}
	r = do(h, "POST", "/api/setup", form, s.postHdr())
	if r.code != 201 || !strings.Contains(r.body, `"org":"neworg"`) {
		t.Fatal(r.code, r.body)
	}
	b, err := os.ReadFile(filepath.Join(p.Orgs, "neworg.yml"))
	if err != nil || !strings.Contains(string(b), "signed: 2026-11-08") {
		t.Fatal(err, string(b))
	}
	if r := do(h, "POST", "/api/setup", form, s.postHdr()); r.code != 409 {
		t.Fatal("exists:", r.code)
	}
	if r := do(h, "GET", "/api/orgs", nil, nil); !strings.Contains(r.body, `"neworg"`) {
		t.Fatal("the new org is listed right away:", r.body)
	}
	r = do(h, "POST", "/api/setup/check", map[string]string{"org": "neworg", "env": "production"}, s.postHdr())
	var c struct{ Results []onboard.Result }
	if r.code != 200 || json.Unmarshal([]byte(r.body), &c) != nil || len(c.Results) != 2 || !c.Results[0].OK || c.Results[1].OK ||
		c.Results[1].Hint == "" {
		t.Fatal(r.code, r.body)
	}
	if r := do(h, "POST", "/api/setup/check", map[string]string{"org": "neworg", "env": "nope"}, s.postHdr()); r.code != 404 {
		t.Fatal(r.code)
	}
	newConn = func(*config.Org, config.Paths) (onboard.Runner, error) { return nil, errors.New("no key") }
	if r := do(h, "POST", "/api/setup/check", map[string]string{"org": "neworg", "env": "production"}, s.postHdr()); r.code != 400 {
		t.Fatal(r.code)
	}
	oldDiscover := discover
	t.Cleanup(func() { discover = oldDiscover })
	discover = func() onboard.Found {
		return onboard.Found{User: "me", Hosts: []onboard.SSHHost{{Alias: "nas", HostName: "192.0.2.40"}}}
	}
	if r := do(h, "GET", "/api/setup/discover", nil, nil); r.code != 200 || !strings.Contains(r.body, `"alias":"nas"`) {
		t.Fatal(r.code, r.body)
	}
	// read-only dashboards neither write org files nor connect
	ro, hro := newTest(t, Options{Paths: p})
	for _, path := range []string{"/api/setup", "/api/setup/check"} {
		if r := do(hro, "POST", path, map[string]any{}, ro.postHdr()); r.code != 403 {
			t.Fatal(path, r.code)
		}
	}
	if r := do(hro, "GET", "/api/setup/discover", nil, nil); r.code != 403 {
		t.Fatal("discover on a read-only dashboard:", r.code)
	}
	_ = io.Discard
}
