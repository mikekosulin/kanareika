package scan

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/priority"
	"github.com/mikekosulin/kanareika/internal/report"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// target: an sshd on 127.0.0.1 that answers the facts query of a Debian host and nothing else (the modules are
// fakes here: what they run over SSH is their own packages' business).
type target struct {
	ln      net.Listener
	port    int
	hostKey ssh.Signer
	mu      sync.Mutex
	cmds    []string
	facts   string // answer to the facts query; "" = a Debian 12 host
}

func newTarget(t *testing.T, user ssh.PublicKey) *target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	tg := &target{ln: ln, port: ln.Addr().(*net.TCPAddr).Port, hostKey: newSigner(t)}
	t.Cleanup(func() { ln.Close() })
	go tg.serve(user)
	return tg
}

func (tg *target) serve(user ssh.PublicKey) {
	for {
		c, err := tg.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
				if bytes.Equal(k.Marshal(), user.Marshal()) {
					return nil, nil
				}
				return nil, errors.New("no")
			}}
			tg.mu.Lock()
			cfg.AddHostKey(tg.hostKey)
			tg.mu.Unlock()
			_, chans, reqs, err := ssh.NewServerConn(c, cfg)
			if err != nil {
				c.Close()
				return
			}
			go ssh.DiscardRequests(reqs)
			for nch := range chans {
				ch, creqs, err := nch.Accept()
				if err != nil {
					continue
				}
				go tg.session(ch, creqs)
			}
		}()
	}
}

func (tg *target) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		if r.Type != "exec" {
			_ = r.Reply(false, nil)
			continue
		}
		_ = r.Reply(true, nil)
		cmd := string(r.Payload[4:])
		tg.mu.Lock()
		tg.cmds = append(tg.cmds, cmd)
		facts := tg.facts
		tg.mu.Unlock()
		if facts == "" {
			facts = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n@@Linux 6.1.0 x86_64\n@@fake-01\n@@"
		}
		if strings.Contains(cmd, "os-release") {
			fmt.Fprint(ch, facts)
		}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
		return
	}
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	s, err := ssh.NewSignerFromKey(k)
	must(t, err)
	return s
}

type env struct {
	t      *testing.T
	paths  config.Paths
	key    ssh.Signer
	target *target
	out    *bytes.Buffer
}

// newEnv: a working directory with one org "t1" (consent valid, any time) and its key; hosts: name -> address.
func newEnv(t *testing.T) *env {
	t.Helper()
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(t.TempDir(), "feeds"))
	old := Heartbeat
	Heartbeat = 10 * time.Millisecond
	t.Cleanup(func() { Heartbeat = old })
	e := &env{t: t, paths: config.PathsAt(t.TempDir()), out: &bytes.Buffer{}}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "")
	must(t, err)
	must(t, os.MkdirAll(filepath.Join(e.paths.Secrets, "t1"), 0o700))
	must(t, os.WriteFile(filepath.Join(e.paths.Secrets, "t1", "key"), pem.EncodeToMemory(block), 0o600))
	e.key, err = ssh.NewSignerFromKey(priv)
	must(t, err)
	e.target = newTarget(t, e.key.PublicKey())
	stub(t, nil, nil)
	return e
}

// stub: fake trivy DB preparation (err: refused).
func stub(t *testing.T, onlineErr, offlineErr error) {
	t.Helper()
	p, po, rs := prepare, prepareOffline, refreshScores
	prepare = func(context.Context, func(string, ...any)) error { return onlineErr }
	prepareOffline = func(func(string, ...any)) error { return offlineErr }
	refreshScores = func(context.Context, *priority.Policy, time.Duration) (bool, error) { return false, nil }
	t.Cleanup(func() { prepare, prepareOffline, refreshScores = p, po, rs })
}

func (e *env) org(consent map[string]any, hosts map[string]any) *config.Org {
	return e.orgWith(consent, hosts, nil)
}

// orgWith: org with more of the file set by edit.
func (e *env) orgWith(consent map[string]any, hosts map[string]any, edit func(doc map[string]any)) *config.Org {
	e.t.Helper()
	if consent == nil {
		consent = map[string]any{"document": "test", "signed": "2026-01-01", "valid_until": "2099-01-01"}
	}
	doc := map[string]any{
		"org":     map[string]any{"id": "t1", "name": "Test", "contacts": []any{map[string]any{"name": "A", "email": "a@example.com"}}},
		"consent": consent,
		"access":  map[string]any{"user": "audit", "key": "t1/key", "privilege": "none", "host_key_checking": "accept-new"},
		"groups":  map[string]any{"app": map[string]any{"role": "app", "exposure": 3, "hosts": hosts}},
	}
	if edit != nil {
		edit(doc)
	}
	b, err := yaml.Marshal(doc)
	must(e.t, err)
	must(e.t, os.MkdirAll(e.paths.Orgs, 0o755))
	must(e.t, os.WriteFile(filepath.Join(e.paths.Orgs, "t1.yml"), b, 0o644))
	l, err := config.NewLoader(e.paths)
	must(e.t, err)
	o, errs := l.LoadOrg(filepath.Join(e.paths.Orgs, "t1.yml"))
	if len(errs) > 0 {
		e.t.Fatal(errs)
	}
	return o
}

func (e *env) here() map[string]any {
	return map[string]any{"web-01": map[string]any{"address": fmt.Sprintf("127.0.0.1:%d", e.target.port)}}
}

// fakeModules: every host module finds one thing; failing modules return an error instead.
func fakeModules(t *testing.T, failing ...string) *sync.Map {
	t.Helper()
	ran := &sync.Map{}
	old := HostModules
	HostModules = map[string]check.Func{}
	for name := range old {
		HostModules[name] = func(ctx *check.Ctx, h config.Host, _ map[string]any, out string, f check.Facts) ([]finding.Finding, error) {
			ran.Store(h.Name+"/"+name, f.OSRelease["ID"])
			for _, x := range failing {
				if x == name {
					return nil, errors.New("boom")
				}
			}
			if _, err := os.Stat(out); err != nil {
				return nil, err
			}
			return []finding.Finding{check.New(h, name, finding.Misconfig, name+"-x", "HIGH", i18n.Plain(name+" finding"), i18n.Plain(""), 0)}, nil
		}
	}
	t.Cleanup(func() { HostModules = old })
	return ran
}

func (e *env) scanner() *Scanner { return &Scanner{Paths: e.paths, Out: e.out, Err: e.out} }

func lastRun(t *testing.T, envDir string) (report.Meta, map[string]any) {
	t.Helper()
	runs, _ := filepath.Glob(filepath.Join(envDir, "20*"))
	if len(runs) == 0 {
		t.Fatal("no run")
	}
	dir := runs[len(runs)-1]
	var m report.Meta
	b, err := os.ReadFile(filepath.Join(dir, "run.json"))
	must(t, err)
	must(t, json.Unmarshal(b, &m))
	var st map[string]any
	b, err = os.ReadFile(filepath.Join(dir, "status.json"))
	must(t, err)
	must(t, json.Unmarshal(b, &st))
	return m, st
}

func TestScan(t *testing.T) {
	e := newEnv(t)
	ran := fakeModules(t, "health")
	o := e.org(nil, e.here())
	rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true, Parallel: 2, Version: "test"})
	if rc != 0 {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
	for _, want := range []string{"== t1 / default: Test", "web-01", "Debian GNU/Linux 12 (bookworm) (fake-01)",
		"health: boom", "hosts done 1/1: web-01 ok (1 module errors)", "done: ", "report:"} {
		if !strings.Contains(e.out.String(), want) {
			t.Fatalf("%q not in\n%s", want, e.out)
		}
	}
	if v, _ := ran.Load("web-01/os_packages"); v != "debian" {
		t.Fatalf("os_packages: facts %v", v)
	}
	envDir := report.EnvDir(e.paths, "t1", config.DefaultEnv)
	m, st := lastRun(t, envDir)
	if m.HostsOK != 1 || m.Kanareika != "test" || m.ModuleErrors.Len() != 1 || st["state"] != "done" {
		t.Fatalf("%+v %v", m, st)
	}
	if _, err := os.Stat(filepath.Join(envDir, report.Current)); err != nil {
		t.Fatal("current state not merged:", err)
	}
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(filepath.Join(envDir, m.RunID, "x")), "run.log"))
	if !strings.Contains(string(b), "hosts done 1/1") {
		t.Fatalf("run.log: %s", b)
	}

	// the host key was learned; a reinstalled host (new key) is refused, with a finding
	e.out.Reset()
	e.target.mu.Lock()
	e.target.hostKey = newSigner(t)
	e.target.mu.Unlock()
	if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 1 {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
	if !strings.Contains(e.out.String(), "HOST KEY CHANGED") {
		t.Fatal(e.out)
	}
	m, _ = lastRun(t, envDir)
	if v, _ := m.HostsFailed.Get("web-01"); !strings.Contains(v, "host key changed") {
		t.Fatalf("%+v", m.HostsFailed)
	}
}

func TestUnreachableAndOffline(t *testing.T) {
	e := newEnv(t)
	fakeModules(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	closed := ln.Addr().String()
	ln.Close()
	hosts := e.here()
	hosts["dead-01"] = map[string]any{"address": closed}
	o := e.org(nil, hosts)
	rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true, Offline: true})
	if rc != 1 || !strings.Contains(e.out.String(), "dead-01: unreachable") || !strings.Contains(e.out.String(), "failed hosts: 1") {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
	m, _ := lastRun(t, report.EnvDir(e.paths, "t1", config.DefaultEnv))
	if m.HostsOK != 1 || m.HostsFailed.Len() != 1 {
		t.Fatalf("%+v", m)
	}
}

func TestRefusals(t *testing.T) {
	e := newEnv(t)
	fakeModules(t)
	o := e.org(nil, e.here())
	run := func(opt Options) (int, string) {
		e.out.Reset()
		return e.scanner().Org(context.Background(), o, config.DefaultEnv, opt), e.out.String()
	}

	// dry run: the plan, no connection
	before := len(e.target.cmds)
	if rc, out := run(Options{DryRun: true, IgnoreWindow: true}); rc != 0 || !strings.Contains(out, "os_packages") || len(e.target.cmds) != before {
		t.Fatalf("dry run %d\n%s", rc, out)
	}
	if rc, out := run(Options{Hosts: []string{"nope"}}); rc != 1 || !strings.Contains(out, "nope") {
		t.Fatalf("unknown host %d\n%s", rc, out)
	}

	stub(t, errors.New("no DB"), errors.New("no cached DB"))
	if rc, out := run(Options{IgnoreWindow: true}); rc != 1 || !strings.Contains(out, "no DB") || !strings.Contains(out, "refusing") {
		t.Fatalf("db %d\n%s", rc, out)
	}
	if rc, out := run(Options{IgnoreWindow: true, Offline: true}); rc != 1 || !strings.Contains(out, "no cached DB") {
		t.Fatalf("offline %d\n%s", rc, out)
	}
	stub(t, nil, nil)

	// another scan holds the environment
	lock, err := report.EnvLock(report.EnvDir(e.paths, "t1", config.DefaultEnv), false)
	must(t, err)
	if rc, out := run(Options{IgnoreWindow: true}); rc != 1 || !strings.Contains(out, "already running") {
		t.Fatalf("busy %d\n%s", rc, out)
	}
	must(t, lock.Unlock())

	// expired consent; outside the window (a window that is never open)
	expired := e.org(map[string]any{"document": "t", "signed": "2020-01-01", "valid_until": "2020-02-01"}, e.here())
	e.out.Reset()
	if rc := e.scanner().Org(context.Background(), expired, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 1 ||
		!strings.Contains(e.out.String(), "refusing to scan") {
		t.Fatalf("expired\n%s", e.out)
	}
	e.out.Reset()
	if rc := e.scanner().Org(context.Background(), expired, config.DefaultEnv, Options{DryRun: true}); rc != 1 {
		t.Fatalf("dry run with problems\n%s", e.out)
	}
	now := time.Now().UTC()
	closedWin := e.org(map[string]any{"document": "t", "signed": "2026-01-01", "valid_until": "2099-01-01",
		"window": map[string]any{"days": []any{strings.ToLower(now.Add(48 * time.Hour).Weekday().String()[:3])}, "from": "00:00", "to": "00:01", "tz": "UTC"}},
		e.here())
	e.out.Reset()
	if rc := e.scanner().Org(context.Background(), closedWin, config.DefaultEnv, Options{}); rc != 1 ||
		!strings.Contains(e.out.String(), "outside scan window") {
		t.Fatalf("window\n%s", e.out)
	}
}

// TestAborted: a run that can't finish (here: the policy disappears mid-run) is marked failed, not left running.
func TestAborted(t *testing.T) {
	e := newEnv(t)
	fakeModules(t)
	for name := range HostModules {
		HostModules[name] = func(*check.Ctx, config.Host, map[string]any, string, check.Facts) ([]finding.Finding, error) {
			must(t, os.MkdirAll(e.paths.Policy, 0o755))
			must(t, os.WriteFile(filepath.Join(e.paths.Policy, "priority.yml"), []byte("rules: ["), 0o644)) // broken
			time.Sleep(30 * time.Millisecond)                                                               // a heartbeat or two
			return nil, nil
		}
	}
	o := e.org(nil, e.here())
	if rc := e.scanner().Org(context.Background(), o, config.DefaultEnv, Options{IgnoreWindow: true}); rc != 1 {
		t.Fatalf("rc 0\n%s", e.out)
	}
	runs, _ := filepath.Glob(filepath.Join(report.EnvDir(e.paths, "t1", config.DefaultEnv), "20*", "status.json"))
	if len(runs) != 1 {
		t.Fatal(runs)
	}
	b, _ := os.ReadFile(runs[0])
	if !strings.Contains(string(b), `"failed"`) {
		t.Fatalf("status: %s", b)
	}
}

// TestOrgModulesAndSelection: org-level modules run with a whole-org scan only; groups, hosts and envs select.
func TestOrgModulesAndSelection(t *testing.T) {
	e := newEnv(t)
	ran := fakeModules(t)
	old := OrgModules
	OrgModules = map[string]OrgFunc{"network_external": func(ctx *check.Ctx, cfg map[string]any, env string) ([]finding.Finding, error) {
		ran.Store("org/network_external", env)
		return nil, errors.New("nmap missing")
	}}
	t.Cleanup(func() { OrgModules = old })
	consent := map[string]any{"document": "t", "signed": "2026-01-01", "valid_until": "2099-01-01", "external_scan": true}
	o := e.orgWith(consent, e.here(), func(doc map[string]any) {
		doc["checks"] = map[string]any{"network_external": true}
		doc["external"] = map[string]any{"production": []any{"203.0.113.10"}}
		doc["groups"].(map[string]any)["app"].(map[string]any)["env"] = "production"
		doc["groups"].(map[string]any)["db"] = map[string]any{"role": "internal", "env": "staging",
			"hosts": map[string]any{"db-01": map[string]any{"address": "192.0.2.5"}}}
	})
	rc := e.scanner().Org(context.Background(), o, "production", Options{IgnoreWindow: true})
	if rc != 0 || !strings.Contains(e.out.String(), "org-level: network_external") || !strings.Contains(e.out.String(), "network_external: nmap missing") {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
	if v, _ := ran.Load("org/network_external"); v != "production" {
		t.Fatal("org module not run")
	}

	sel := func(groups, hosts []string) ([]config.Host, error) {
		return SelectHosts(o, "production", groups, hosts)
	}
	if hs, err := sel([]string{"app"}, nil); err != nil || len(hs) != 1 {
		t.Fatal(hs, err)
	}
	if _, err := sel([]string{"web"}, nil); err == nil || !strings.Contains(err.Error(), "unknown group 'web' (known: app)") {
		t.Fatal(err)
	}
	if _, err := sel(nil, []string{"db-01"}); err == nil || !strings.Contains(err.Error(), "it is in env 'staging'") {
		t.Fatal(err)
	}
	// a partial scan: no org-level modules, and the selection is stored
	ran.Delete("org/network_external")
	e.out.Reset()
	if rc := e.scanner().Org(context.Background(), o, "production", Options{IgnoreWindow: true, Hosts: []string{"web-01"},
		Modules: []string{"health"}}); rc != 0 {
		t.Fatalf("rc %d\n%s", rc, e.out)
	}
	if _, ok := ran.Load("org/network_external"); ok || strings.Contains(e.out.String(), "org-level") {
		t.Fatal("org module in a partial scan")
	}
	m, _ := lastRun(t, report.EnvDir(e.paths, "t1", "production"))
	if len(m.Selection.Hosts) != 1 || len(m.Selection.Modules) != 1 || m.Selection.Groups == nil {
		t.Fatalf("%+v", m.Selection)
	}

	// external scanning without consent is refused
	consent["external_scan"] = false
	o = e.orgWith(consent, e.here(), func(doc map[string]any) {
		doc["checks"] = map[string]any{"network_external": true}
		doc["external"] = []any{"203.0.113.10"}
	})
	e.out.Reset()
	if rc := e.scanner().Org(context.Background(), o, "default", Options{IgnoreWindow: true}); rc != 1 ||
		!strings.Contains(e.out.String(), "consent.external_scan is false") {
		t.Fatalf("%s", e.out)
	}
}
