package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

// TestHostCard: Enter on a host opens all a run knows about it; it scrolls, and Esc goes back to the list.
func TestHostCard(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(110, 70)
	h.key("3", "enter")
	h.has("Host(web-01)", "CentOS Stream 9", "5.14.0-575.el9.x86_64", "19 CVE",
		"ToDo", "Update OS packages (2)", "Packages", "openssl", "KEV", "+8 more",
		"SSH and logins", "port", "logged in", "10.77.0.24", "failed logins", "password guessing", "198.51.100.0",
		"Network", "public IPs", "192.0.2.1", "listening", "tcp *:22",
		"Health", "disks", "50% /", "load", "Other findings", "SSH password guessing")
	h.size(110, 20) // scrolls
	h.has("CentOS Stream 9")
	h.key("G")
	h.hasNot("CentOS Stream 9")
	h.has("Other findings")
	h.key("g", "down", "up", "pgdown", "pgup")
	h.has("CentOS Stream 9")
	h.key("esc")
	h.has("Hosts(acme/production)[5]")
	h.key("enter", "2") // another view closes the card
	h.key("3")
	h.has("Hosts(acme/production)")
}

// TestHostCardSections: the fields the modules write on real hosts (as the module goldens have them).
func TestHostCardSections(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 90)
	rd := h.m.rund
	rd.Access["web-01"] = map[string]any{
		"sshd": map[string]any{"port": "22", "permitrootlogin": "without-password"}, "password_auth": true,
		"password_auth_match_users": []any{"deploy"}, "users_with_password": []any{"root", "admin"},
		"keys": []any{map[string]any{"user": "root"}, map[string]any{"user": "deploy"}},
		"logins": map[string]any{"accepted": []any{map[string]any{"user": "root", "ip": "100.21.0.11", "method": "publickey", "count": 10.0, "last": "2026-11-01T23:54:24"}},
			"failed_total": 4981.0, "failed_ips": 551.0,
			"attackers": []any{map[string]any{"ip": "100.21.0.14", "n": 353.0, "users": []any{[]any{"admin", 10.0}}}}},
		"denied": []any{"shadow"}}
	rd.Exposure["web-01"] = map[string]any{"public": []any{"192.0.2.1", "192.0.2.9"}, "unlisted_public": []any{"192.0.2.9"},
		"listen": []any{map[string]any{"proto": "tcp", "addr": "*", "port": 80.0, "process": "nginx", "public": true},
			map[string]any{"proto": "tcp", "port": 22.0, "process": "sshd"}},
		"firewall": map[string]any{"readable": true, "has_input_filtering": false, "iptables_input_policy": "ACCEPT", "docker_rules": true}}
	rd.Health["web-01"] = map[string]any{
		"disks":  []any{map[string]any{"mount": "/", "use": 95.0}, map[string]any{"mount": "/var", "use": 85.0}},
		"inodes": []any{map[string]any{"mount": "/", "use": 60.0}, map[string]any{"mount": "/boot", "use": 3.0}},
		"mem":    map[string]any{"available_mb": 241.0, "total_mb": 490.0}, "load": map[string]any{"load1": 0.5, "load15": 0.2, "cpus": 2.0},
		"failed_units": []any{"nginx.service"}, "readonly_mounts": []any{"/data"}, "journal": map[string]any{"errors_7d": 12.0},
		"time": map[string]any{"service": "chronyd", "synced": "yes", "offset_s": 0.0008, "skew_s": 0.07}}
	h.key("3", "enter")
	h.has("password login       on (Match: deploy)", "root login           without-password", "users with password  root, admin",
		"authorized keys      2 (root: 1)", "root @ 100.21.0.11 ×10 publickey 2026-11-01 23:54:24", "failed logins        4981 551 IPs",
		"100.21.0.14 ×353 admin", "no access to", "192.0.2.9 (not in the config)", "tcp *:80", "nginx public", "no inbound filtering",
		"iptables_input_policy=ACCEPT", "docker", "95% /", "85% /var", "60% /", "241 / 490 MB", "0.5 / 0.2", "nginx.service", "/data",
		"journal errors       12", "chronyd, synchronized: yes, offset 0.001 s, clock skew 0.07 s")
	h.hasNot("/boot")
	// a firewall it could not read, and an empty network
	rd.Exposure["web-01"] = map[string]any{"firewall": map[string]any{"readable": false, "has_input_filtering": true}}
	h.has("not readable without root", "public IPs           none")
	if str(nil) != "" || str(false) != "no" || str(3) != "3" || num("x") != 0 {
		t.Fatal("helpers")
	}
}

// TestOtherLayout: hotkeys work on a Cyrillic layout (the same physical keys); the filter keeps the letters typed.
func TestOtherLayout(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("3") // Hosts
	runes := func(s string) {
		for _, r := range s {
			_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
			h.run(cmd)
		}
	}
	runes("о") // j: down
	if h.m.cur[vHosts] != 1 {
		t.Fatal("о is not j")
	}
	runes(".") // / on the Russian layout: the filter
	if !h.m.typing {
		t.Fatal(". is not /")
	}
	runes("веб")
	if h.m.filter != "веб" {
		t.Fatalf("filter %q", h.m.filter)
	}
	h.key("esc")
	runes("Щ") // O: nothing; щ is o: the panel settings
	runes("щ")
	h.has("Panels(Hosts)")
	h.key("esc")
	_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("й")}) // q
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("й is not q")
	}
}

// TestSelectedRowKeepsChart: the cursor row is a bar, but its chart keeps its colors.
func TestSelectedRowKeepsChart(t *testing.T) {
	old := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor) // tests have no terminal: colors on
	t.Cleanup(func() { lipgloss.SetColorProfile(old) })
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 30)
	h.key("3")
	for _, l := range strings.Split(h.m.View(), "\n") {
		if strings.Contains(ansi.Strip(l), "web-01") {
			chart := strings.Index(l, "▇")
			// the chart's cells: a priority color in front of them, not the cursor bar's black on cyan
			if chart < 0 || !strings.Contains(l[:chart], "38;2;229;72;77") {
				t.Fatalf("selected row without its colored chart: %q", l)
			}
			if !strings.Contains(l, "48;2;34;211;238") {
				t.Fatalf("not selected: %q", l)
			}
			return
		}
	}
	t.Fatal("no web-01 row")
}

// TestDBStatus: checked at start (none yet: a hint), shown in the header, U updates it.
func TestDBStatus(t *testing.T) {
	t.Setenv("KN_TEST_NO_DB", "1")
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.has("DB:", "no DB <U>", "No vulnerability DB yet: press U to download it", "<U> update DBs")
	h.key("U")
	h.has("Updating vulnerability DBs")
	for i := 0; i < 200 && (h.m.db == nil || h.m.db.Updating || h.m.dbAttention() != ""); i++ {
		time.Sleep(5 * time.Millisecond)
		h.run(h.m.fetchDB())
	}
	h.has("DB:       1h")
	h.hasNot("no DB")

	// one running: U does nothing; a newer build out: said so; a failed update: the error
	h.m.db.Updating = true
	if h.m.updateDB() != nil {
		t.Fatal("second update started")
	}
	h.has("updating")
	h.m.db.DBs[1].Outdated = true
	h.m.db.Updating = false
	h.has("newer DB out <U>")
	h.m.db.Updating = true
	h.run(func() tea.Msg { return dbMsg(dbResp{Error: "no repository worked", Enabled: true}) })
	h.has("DB update failed: no repository worked")

	// read-only: no updates from here
	h2 := newHarness(t, Options{Org: "acme", Env: "production"}, false)
	h2.key("U")
	h2.has("DB updates are off here (read-only)")
	if agoShort(5*time.Minute) != "5m" || agoShort(3*time.Hour) != "3h" || agoShort(72*time.Hour) != "3d" {
		t.Fatal("agoShort")
	}
}
