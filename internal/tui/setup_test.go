package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/dbsize"
	"github.com/mikekosulin/kanareika/internal/priority"
)

// typeText: runes into the field that has the keyboard (a paste: several at once, newlines too).
func (h *harness) typeText(s string) {
	_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s), Paste: true})
	h.run(cmd)
}

// dump: the screen in the test's log when KN_FRAMES is set (to look at the setup's frames).
func (h *harness) dump(name string) {
	if os.Getenv("KN_FRAMES") != "" {
		h.t.Log(name + "\n" + h.screen())
	}
}

// demoSSH: a made-up ~/.ssh/config of this machine (addresses that refuse at once) and made-up download sizes.
func demoSSH(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(home, ".ssh"), 0o700))
	must(t, os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(`# made-up hosts
Host nas
  HostName 127.0.0.1
  User admin
  Port 1
Host vps
  HostName localhost
  User root
  Port 2
Host bastion
  HostName 127.0.0.1
  User jumper
  Port 3
Host app-01
  HostName 10.0.0.5
  User deploy
  ProxyJump bastion
`), 0o600))
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("USER", "demo")
	t.Setenv("LOGNAME", "demo")
	old := dbsize.Lookup
	t.Cleanup(func() { dbsize.Lookup = old; dbsize.Reset() })
	dbsize.Reset()
	dbsize.Lookup = func(context.Context, priority.Policy) map[string]int64 {
		return map[string]int64{"db": 139e6, "java-db": 1e9, "kev": 1e6, "epss": 2e6, "dbip-city": 50e6, "dbip-asn": 15e6}
	}
}

// TestSetup: no organization yet: my servers, pasted and picked from ~/.ssh/config with a live preview, the
// server's problems, the access check of each host, the vulnerability list downloaded when asked, the first scan.
func TestSetup(t *testing.T) {
	demoSSH(t)
	home := t.TempDir()
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(home, "no-feeds"))
	h := newHarnessAt(t, config.PathsAt(home), Options{}, true)
	h.size(120, 40)
	h.has("Welcome to Kanareika", "1 Servers ──── 2 Access ──── 3 First scan", "My servers", "A client's servers", "A fleet",
		"Kanareika needs a list of known vulnerabilities: 68 MB, downloaded once.", "<d> Download now")
	h.hasNot("Add to", "<esc> Cancel") // nothing to add to, nothing to go back to
	h.dump("paths")
	h.key("esc", "down", "up", "enter")
	h.has("Which servers?", "Servers", "an IP, user@host or an ssh command", "ctrl+o choose from ~/.ssh/config (4)", "▸ Login details",
		"These are my servers, or I am allowed to audit them.", "Check access")
	h.hasNot("SSH user") // folded away
	// what is typed is understood as it is typed; lines that make no sense are skipped, with why
	h.typeText("root@127.0.0.1:5\n10.0.0.300\none two three four\n")
	h.has("✓ root@127.0.0.1", "! 2 skipped")
	h.dump("paste")
	h.key("ctrl+u", "ctrl+o")
	h.has("Choose from ~/.ssh/config", "[ ] nas", "admin@127.0.0.1:1", "via bastion")
	h.typeText("a")
	h.key("backspace", "space", "down", "space", "up", "down", "tab")
	h.dump("picker")
	h.key("enter")
	h.has("✓ admin@127.0.0.1:1", "✓ root@localhost:2")
	if v := string(h.m.setup.field("hosts").val); v != "ssh -p 1 admin@127.0.0.1\nssh -p 2 root@localhost" {
		t.Fatalf("%q", v)
	}
	h.key("ctrl+o", "esc", "tab", "enter") // the login details
	h.has("▾ Login details", "SSH user", "(•) the ssh-agent", "The user can sudo without a password")
	h.key("tab", "x", "backspace", "tab", "right", "left")
	h.key("ctrl+s") // not confirmed: the server says so
	h.has("✗ confirm that you are allowed to audit these servers")
	for h.m.setup.fields[h.m.setup.cur].key != "confirmed" {
		h.key("tab")
	}
	h.key("space", "tab", "enter")
	// both fail for the same reason: said once, in plain words, with both hosts on one line; the raw error folded
	h.has("✓ Servers", "2 Access", "Access check(servers/production)",
		"✗ no SSH key to log in with: no ssh-agent is running here. Run ssh-add in a terminal, then check again", "   127.0.0.1  localhost",
		"<r> Check again", "<e> Details", "Addresses and logins are saved in servers.yml.")
	h.hasNot("Scan the", "answered", "SSH_AUTH_SOCK") // none answered; the raw error folded away
	h.dump("check, none answered")
	h.key("e")
	h.has("SSH_AUTH_SOCK")
	h.key("e")
	b, err := os.ReadFile(filepath.Join(home, "orgs", "servers.yml"))
	must(t, err)
	if !strings.Contains(string(b), "My servers") || !strings.Contains(string(b), "127.0.0.1") {
		t.Fatalf("%s", b)
	}
	h.key("r")
	h.has("✗ no SSH key", "127.0.0.1  localhost")
	// one answers (made up: no SSH server here): the scan is of the ones that answered, after the download
	w := h.m.setup
	w.res[w.hosts[0].name] = &checkResult{Host: w.hosts[0].name, OK: true, System: "Linux 6.1.0"}
	h.has("✓ 1 answered", "   127.0.0.1", "<enter> Scan the 1 that answered · downloads 68 MB first", "<r> Check the failed again")
	// one still checking
	w.res["localhost"], w.started = nil, h.m.now().Add(-4e9)
	h.has("⠋ Checking 1… 4 s", "   localhost", "✓ 1 answered")
	h.hasNot("<enter>", "<r>")
	h.dump("check, mid-run")
	w.res["localhost"] = &checkResult{Host: "localhost", Error: "dial tcp: connection refused", Hint: "nothing listens on that port"}
	h.dump("check")
	h.key("d") // the download, asked for
	h.has("Downloading the vulnerability list")
	h.m.db.Updating, h.m.dbSize = false, &dbSizeResp{}
	h.has("✓ Vulnerability list ready")
	h.hasNot("downloads")
	h.key("enter")
	h.has("3 First scan", "✓ Access", "running")
	if r := h.scan.reqs; len(r) != 1 || len(r[0].Hosts) != 1 || r[0].Hosts[0] != w.hosts[0].name {
		t.Fatalf("%+v", r)
	}
	close(h.scan.release)
	h.waitJob("done")
	h.has("See the results")
	h.key("enter")
	if h.m.setup != nil || h.m.view != vActions || h.m.org != "servers" {
		t.Fatal("ToDo after the first scan", h.m.org)
	}
	// more servers: My servers exists now, so it is added to
	h.key("N")
	h.has("Add servers", "Add to My servers")
	h.key("enter")
	h.typeText("box 127.0.0.1:6")
	for h.m.setup.fields[h.m.setup.cur].key != "confirmed" {
		h.key("tab")
	}
	h.key("space", "ctrl+s")
	h.has("Access check(servers/production)", "box · 127.0.0.1")
	if len(h.m.setup.hosts) != 1 {
		t.Fatal("only the added host is checked", h.m.setup.hosts)
	}
}

// TestSetupClientFleet: a client's servers (an org named after the client) and a fleet (its own id, env, jump
// host, internet-facing groups); the downloads line in its states.
func TestSetupClientFleet(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	h.key("N")
	h.has("Add servers", "Add to ACME", "My servers", "<esc> Cancel")
	h.key("down", "down", "enter") // a client's servers
	h.has("A client's servers", "Client", "The client's permission", "The client allowed me to audit these servers.")
	h.typeText("Globex Corp")
	h.key("tab")
	h.typeText("127.0.0.1:7")
	for _, k := range []string{"consent", "confirmed"} {
		for h.m.setup.fields[h.m.setup.cur].key != k {
			h.key("tab")
		}
		if k == "consent" {
			h.typeText("Contract 42")
		} else {
			h.key("x")
		}
	}
	h.key("ctrl+s")
	h.has("Access check(globex-corp/production)")
	h.key("esc", "N", "esc")
	if h.m.setup != nil {
		t.Fatal("esc on the paths: cancel")
	}
	// a fleet: a table of what was understood
	h.key("N", "up", "up", "up", "down", "down", "down", "down", "enter")
	h.has("Your fleet", "Short id", "Jump host for all", "Groups facing the internet")
	h.typeText("Initech")
	h.key("tab")
	h.typeText("initech")
	h.key("tab")
	h.typeText("web-1,127.0.0.1:8,web\nweb-2,127.0.0.1:9,web\ndb-1,127.0.0.1:10,db\ndb-2,127.0.0.1:11,db\n")
	h.has("NAME", "ADDRESS", "VIA", "web-1", "127.0.0.1:11")
	h.dump("fleet")
	h.key("esc") // back to the paths
	h.has("A fleet")
	// the downloads line: downloading, failed
	h.m.db.Updating, h.m.dlStart = true, h.m.now().Add(-37e9)
	h.has("Downloading the vulnerability list… 37 s")
	h.dump("downloading")
	h.m.db.Updating, h.m.db.Error, h.m.setup.dlAsked = false, "no repository worked", true
	h.has("✗ The download failed: no repository worked", "<d> Try again")
}

// TestFirstScanOfEnv: an env with no runs: enter checks the SSH access to its hosts, then its first scan.
func TestFirstScanOfEnv(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "staging"}, true)
	h.has("No runs yet", "<enter> checks SSH access to every host", "enter check access, first scan")
	h.key("enter")
	h.has("Access check(acme/staging)", "2 Access")
	h.key("esc") // later
	if h.m.setup != nil || h.m.view != vActions {
		t.Fatal("esc: back to ToDo")
	}
}
