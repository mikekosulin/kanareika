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
	"github.com/mikekosulin/kanareika/internal/onboard"
	"github.com/mikekosulin/kanareika/internal/priority"
)

// TestMain: nothing of the machine running the tests shows: pasted names never resolve against its
// ~/.ssh/config, the setup finds no keys or hosts of its own (an empty HOME, no agent, user demo), and download
// sizes are made up (no network).
func TestMain(m *testing.M) {
	onboard.LocalSSHConfig = func() []onboard.SSHHost { return nil }
	home, err := os.MkdirTemp("", "kn-tui-home")
	if err != nil {
		panic(err)
	}
	for k, v := range map[string]string{"HOME": home, "SSH_AUTH_SOCK": "", "USER": "demo", "LOGNAME": "demo"} {
		_ = os.Setenv(k, v)
	}
	dbsize.Lookup = func(context.Context, priority.Policy) map[string]int64 {
		return map[string]int64{"db": 139e6, "java-db": 1e9, "kev": 1e6, "epss": 2e6, "dbip-city": 50e6, "dbip-asn": 15e6}
	}
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}

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

// demoConfig: a made-up ~/.ssh/config (documentation addresses).
const demoConfig = `# made-up hosts
Host nas
  HostName 192.0.2.40
  User admin
Host vps
  HostName vps.example.com
  User root
  Port 2222
Host bastion
  HostName 203.0.113.10
  User jumper
Host app-01
  HostName 10.0.0.5
  User deploy
  ProxyJump bastion
Host db-01
  HostName 10.0.0.6
  User deploy
  ProxyJump bastion
`

// demoSSH: this machine's SSH setup made up: the config above, no key, no agent (so no check connects anywhere),
// the user demo; and made-up download sizes.
func demoSSH(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(home, ".ssh"), 0o700))
	must(t, os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(demoConfig), 0o600))
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("USER", "demo")
	t.Setenv("LOGNAME", "demo")
	oldL, oldC := dbsize.Lookup, onboard.LocalSSHConfig
	t.Cleanup(func() { dbsize.Lookup, onboard.LocalSSHConfig = oldL, oldC; dbsize.Reset() })
	onboard.LocalSSHConfig = func() []onboard.SSHHost { return onboard.ParseSSHConfig(demoConfig) }
	dbsize.Reset()
	dbsize.Lookup = func(context.Context, priority.Policy) map[string]int64 {
		return map[string]int64{"db": 139e6, "java-db": 1e9, "kev": 1e6, "epss": 2e6, "dbip-city": 50e6, "dbip-asn": 15e6}
	}
}

func (h *harness) focus(key string) {
	h.t.Helper()
	for i := 0; i < 15 && h.m.setup.cur > 0; i++ {
		h.key("shift+tab")
	}
	for i := 0; i < 30 && h.m.setup.fields[h.m.setup.cur].key != key; i++ {
		h.key("tab")
	}
	if h.m.setup.fields[h.m.setup.cur].key != key {
		h.t.Fatal("no field", key)
	}
}

// TestSetup: no organization yet: personal servers, pasted in several forms and picked from ~/.ssh/config, each
// line beside what it becomes; what is missing; the access check grouped by cause; the vulnerability list
// downloaded when asked; the first scan.
func TestSetup(t *testing.T) {
	demoSSH(t)
	home := t.TempDir()
	t.Setenv("KANAREIKA_FEEDS_DIR", filepath.Join(home, "no-feeds"))
	h := newHarnessAt(t, config.PathsAt(home), Options{}, true)
	h.size(120, 40)
	h.has("~ kanareika setup", " Servers  › Access › First scan", "vulnerability list 68 MB  ↓ d download",
		"Whose servers?   (•) Personal  ( ) Client  ( ) Company", "One per line: user@host, an ssh command, ssh config, CSV",
		"admin@192.0.2.10", "ssh -p 2222 deploy@203.0.113.7", "ctrl+o + ~/.ssh/config (5)", "Login  no SSH key found · user demo   c change",
		"[ ] I’m allowed to audit these servers", "⏎ Check access", "setup │ ssh-agent none", "tab next")
	h.hasNot("Add to", "esc close") // nothing to add to, nothing to go back to
	h.key("i")                      // what the list is made of
	h.has("Linux packages", "139 MB", "IP locations", "65 MB", "Java libraries", "~1.0 GB", "only if a scan finds .jar files")
	h.key("i")
	h.hasNot("Linux packages")
	// nothing pasted, not confirmed: said before anything is sent
	h.key("ctrl+s")
	h.has("✗ Paste at least one server.")
	h.focus("hosts")
	h.typeText("admin@192.0.2.10\nssh -p 2222 deploy@203.0.113.7\nnas\n10.0.0.300")
	h.key("ctrl+o")
	h.has("~/.ssh/config", "[ ] nas", "admin@192.0.2.40", "deploy@10.0.0.5 via bastion")
	h.typeText("app")
	h.key("backspace", "backspace", "backspace", "down", "down", "down", "space", "up", "down")
	h.dump("picker")
	h.key("enter")
	h.has("1 admin@192.0.2.10", "→ admin@192.0.2.10", "→ deploy@203.0.113.7:2222", "3 nas", "→ admin@192.0.2.40 from ssh config",
		"5 app-01", "→ deploy@10.0.0.5 via jumper@203.0.113.10 from ssh config", "4 10.0.0.300", "→ not an IP address · skipped")
	h.dump("paste")
	h.key("ctrl+s")
	h.has("✗ Confirm that you are allowed to audit these servers.")
	h.focus("login")
	h.key("enter")
	h.has("User", "Key", "(•) ssh-agent", "passwordless sudo")
	h.hasNot("Environment") // a company's only
	h.key("c")
	h.hasNot("passwordless sudo")
	h.focus("confirmed")
	h.key("space", "tab", "enter")
	h.has("✓ Servers", "Access", "Checking access", "One login per server, uname -sr, log out. Nothing is changed.",
		"✗ no SSH key to log in with", "admin@192.0.2.10", "deploy@203.0.113.7:2222", "deploy@10.0.0.5", "! 1 skipped",
		"Saved in servers.yml", "r Check again", "esc Back", "Personal · production")
	h.hasNot("Scan the", "answered")
	h.dump("check, none answered")
	b, err := os.ReadFile(filepath.Join(home, "orgs", "servers.yml"))
	must(t, err)
	for _, want := range []string{"Personal", "192.0.2.40", "address: 203.0.113.10", "user: jumper"} { // aliases written out
		if !strings.Contains(string(b), want) {
			t.Fatalf("%q not in\n%s", want, b)
		}
	}
	// some answer, one connects, one is refused (made up: nothing connects here)
	w := h.m.setup
	w.res[w.hosts[0].name] = &checkResult{OK: true, System: "Linux 6.8.0-49-generic"}
	w.res[w.hosts[1].name] = &checkResult{Error: w.hosts[1].name + ": ssh: unable to authenticate", Hint: "the server refused the login"}
	w.res[w.hosts[2].name] = &checkResult{Error: w.hosts[2].name + ": ssh: unable to authenticate", Hint: "the server refused the login"}
	delete(w.res, w.hosts[3].name)
	w.started = h.m.now().Add(-6e9)
	h.has("1 connecting · 6 s", "via 203-0-113-10", "✗ the server refused the login", "fix: ssh-copy-id -p 2222 deploy@203.0.113.7",
		"✓ 1 answered", "Linux 6.8.0-49-generic")
	h.hasNot("⏎ Scan") // still checking
	h.dump("check, mid-run")
	w.res[w.hosts[3].name] = &checkResult{Error: w.hosts[3].name + ": dial tcp: i/o timeout", Hint: "no answer: a firewall"}
	h.has("⏎ Scan the 1 that answered · downloads the vuln list first (68 MB)", "r Check again")
	h.dump("check")
	h.key("d") // the download, asked for
	h.has("vulnerability list ")
	h.m.db.Updating, h.m.dbSize = false, &dbSizeResp{}
	h.has("vulnerability list ✓ ready")
	h.hasNot("downloads the vuln list")
	h.key("enter")
	h.has("✓ Servers › ✓ Access ›", "First scan", "A few minutes.")
	r := h.scan.requests() // the scan waits for the download, then starts
	if len(r) != 1 || len(r[0].Hosts) != 1 || r[0].Hosts[0] != w.hosts[0].name {
		t.Fatalf("%+v", r)
	}
	close(h.scan.release)
	h.waitJob("done")
	h.has("⏎ See the results", "plan line")
	h.dump("first scan")
	h.key("enter")
	if h.m.setup != nil || h.m.view != vServers || h.m.org != "servers" {
		t.Fatal("ToDo after the first scan", h.m.org)
	}
	// more personal servers: added to Personal
	h.key("N")
	h.has("(•) Personal", "esc close")
	h.focus("hosts")
	h.typeText("box 192.0.2.77")
	h.focus("confirmed")
	h.key("space", "ctrl+s")
	h.has("Checking access", "192.0.2.77")
	if len(h.m.setup.hosts) != 1 {
		t.Fatal("only the added host is checked", h.m.setup.hosts)
	}
	h.key("esc", "esc") // back to the form, then closed
	if h.m.setup != nil {
		t.Fatal("esc closes")
	}
}

// TestSetupClientCompany: a client's servers (an org named after the client) and a company's (its environment and
// jump host under the login line); the vulnerability list's line in its states.
func TestSetupClientCompany(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 40)
	h.key("N")
	h.has("( ) Add to ACME", "(•) Personal", "( ) Client", "( ) Company", "esc close")
	h.key("right") // client
	h.has("Client  ", "Their permission")
	h.key("ctrl+s")
	h.has("✗ Paste at least one server.")
	h.focus("hosts")
	h.typeText("192.0.2.30")
	h.key("ctrl+s")
	h.has("✗ Name the client.")
	h.focus("name")
	h.typeText("Globex Corp")
	h.key("ctrl+s")
	h.has("✗ Say where the permission is documented.")
	h.focus("consent")
	h.typeText("Contract 42")
	h.focus("confirmed")
	h.key("x", "ctrl+s")
	h.has("Checking access", "Globex Corp · production")
	h.key("esc", "esc")
	// a company: its environment and jump host
	h.key("N", "left", "left") // company
	h.has("Company  ", "Permission")
	h.focus("login")
	h.key("enter")
	h.has("Environment", "Jump host")
	h.focus("hosts")
	h.typeText("web-1,192.0.2.21,web\nweb-2,192.0.2.22,web\n")
	h.has("→ demo@192.0.2.21", "→ demo@192.0.2.22")
	h.focus("user")
	h.typeText("audit")
	h.has("→ audit@192.0.2.21", "user audit")
	h.dump("company")
	// the list's line: downloading, failed
	h.m.db.Updating, h.m.dlStart = true, h.m.now().Add(-37e9)
	h.has("vulnerability list", "37 s")
	h.m.db.Updating, h.m.db.Error, h.m.setup.dlAsked = false, "no repository worked", true
	h.has("vulnerability list failed  d retry")
	h.focus("confirmed")
	h.key("i")
	h.has("no repository worked")
}

// TestFirstScanOfEnv: an env with no runs: enter checks the SSH access to its hosts, then its first scan.
func TestFirstScanOfEnv(t *testing.T) {
	demoSSH(t)
	h := newHarness(t, Options{Org: "acme", Env: "staging"}, true)
	h.has("No runs yet", "<enter> checks SSH access to every host", "enter check access, first scan")
	h.key("enter")
	h.has("Checking access", " · staging")
	h.key("esc") // no form to go back to: closed
	if h.m.setup != nil || h.m.view != vServers {
		t.Fatal("esc: back to ToDo")
	}
}
