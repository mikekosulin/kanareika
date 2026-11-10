package tui

import (
	"encoding/json"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// TestHostCardOtherInLanguage: the other findings of a host card are in the interface's language, as in ToDo.
func TestHostCardOtherInLanguage(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production", Lang: "ru"}, true)
	h.size(110, 70)
	card(h)
	h.has("Подбор паролей SSH:")
	h.hasNot("SSH password guessing")
}

// TestHostCard: Enter on a host opens all a run knows about it; it scrolls, and Esc goes back to the list.
func TestHostCard(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(110, 70)
	card(h)
	h.has("Host(web-01)", "CentOS Stream 9", "5.14.0-575.el9.x86_64", "19 CVE",
		"ToDo", "Update OS packages (2)", "Packages", "openssl", "KEV", "+8 more",
		"SSH and logins", "port", "logged in", "10.77.0.24", "failed logins", "password guessing", "198.51.100.0",
		"Network", "public IPs", "192.0.2.1", "listening", "tcp *:22",
		"Health", "disks", "50% /", "load", "Other findings", "SSH password guessing")
	h.size(110, 20) // scrolls
	h.has("CentOS Stream 9")
	h.key("G") // the end: the whole lists after the summaries
	h.hasNot("CentOS Stream 9")
	h.has("198.51.100.99")
	h.key("g", "down", "up", "pgdown", "pgup")
	h.has("CentOS Stream 9")
	h.key("esc")
	h.has("Servers(acme/production)")
	card(h)
	h.key("2") // another view closes the card
	h.key("1")
	h.has("Servers(acme/production)")
	h.hasNot("Host(web-01)")
}

// TestHostCardSections: the fields the modules write on real hosts (as the module goldens have them).
func TestHostCardSections(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(140, 120)
	rd := h.m.rund
	rd.Access["web-01"] = map[string]any{
		"sshd": map[string]any{"port": "22", "permitrootlogin": "without-password"}, "password_auth": true,
		"password_auth_match_users": []any{"deploy"}, "users_with_password": []any{"root", "admin"},
		"keys": []any{map[string]any{"user": "root", "type": "ssh-ed25519", "fp": "SHA256:JDsJkvoMQRMG211AX9dOCtH40Q6", "comment": "user1@example.com"},
			map[string]any{"user": "deploy"}},
		"login_users": []any{"deploy", "root"}, "uid0": []any{"root", "toor"},
		"last": []any{"deploy   pts/0        100.21.0.11  Sun Nov  1 22:43:30 2026 - Sun Nov  1 23:11:26 2026  (00:27)"},
		"logins": map[string]any{"accepted": []any{map[string]any{"user": "root", "ip": "100.21.0.11", "method": "publickey", "count": 10.0, "last": "2026-11-01T23:54:24"}},
			"failed_total": 4981.0, "failed_ips": 551.0, "failed_last": "2026-11-01T22:28:00", "invalid_users": 1624.0,
			"failed_top_users": []any{[]any{"root", 1545.0}, []any{"ubuntu", 147.0}}, "period": []any{"2026-11-01T09:02:28", "2026-11-01T22:28:00"},
			"attackers": []any{map[string]any{"ip": "100.21.0.14", "n": 353.0, "last": "2026-11-01T16:33:30", "users": []any{[]any{"admin", 10.0}}}}},
		"denied": []any{"shadow"}}
	rd.Exposure["web-01"] = map[string]any{"public": []any{"192.0.2.1", "192.0.2.9"}, "unlisted_public": []any{"192.0.2.9"},
		"listen": []any{map[string]any{"proto": "tcp", "addr": "*", "port": 80.0, "process": "nginx", "public": true},
			map[string]any{"proto": "tcp", "port": 22.0, "process": "sshd"}},
		"firewall": map[string]any{"readable": true, "has_input_filtering": false, "iptables_input_policy": "ACCEPT", "docker_rules": true}}
	rd.Health["web-01"] = map[string]any{
		"disks":  []any{map[string]any{"mount": "/", "use": 95.0}, map[string]any{"mount": "/var", "use": 85.0}},
		"inodes": []any{map[string]any{"mount": "/", "use": 60.0}, map[string]any{"mount": "/boot", "use": 3.0}},
		"mem":    map[string]any{"available_mb": 241.0, "total_mb": 490.0}, "load": map[string]any{"load1": 0.5, "load15": 0.2, "cpus": 2.0},
		"failed_units": []any{"nginx.service"}, "readonly_mounts": []any{"/data"},
		"journal": map[string]any{"errors_7d": 12.0, "top": []any{[]any{"kernel", 9.0}}},
		"dmesg":   map[string]any{"classes": map[string]any{"oom": map[string]any{"count": 3.0, "last": "Out of memory: Killed process 812", "key": "dmesg.oom"}}, "tail": []any{"[1.0] eth0: link up"}},
		"time":    map[string]any{"service": "chronyd", "synced": "yes", "offset_s": 0.0008, "skew_s": 0.07, "timezone": "Etc/UTC"}}
	card(h)
	h.has("password login       on (Match: deploy)", "root login           without-password", "users with password  root, admin",
		"authorized keys      2 (root: 1)", "root @ 100.21.0.11 ×10 publickey 2026-11-01 23:54:24", "failed logins        4981 551 IPs, last attack 2026-11-01 22:28:00",
		"password guessing    100.21.0.14      ×353 2026-11-01 16:33:30 admin", "ssh-ed25519", "JDsJkvoMQRMG…", "user1@example.com", "login users          deploy, root",
		"root accounts        root, toor", "login period         2026-11-01 09:02:28 — 2026-11-01 22:28:00", "unknown user names   1624",
		"root ×1545, ubuntu ×147", "Sessions", "deploy pts/0 100.21.0.11 Sun Nov 1 22:43:30 2026", "×3  Out of memory: Killed process 812",
		"Kernel log", "eth0: link up", "kernel ×9", "time zone Etc/UTC", "no access to", "192.0.2.9 (not in the config)", "tcp *:80", "nginx public", "no inbound filtering",
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

// TestOtherLayout: hotkeys work on Russian, Korean and French layouts (the same physical keys); the filter keeps
// the letters typed.
func TestOtherLayout(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("1") // Servers
	runes := func(s string) {
		for _, r := range s {
			_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
			h.run(cmd)
		}
	}
	runes("о") // j: down
	if h.m.cur[vServers] != 1 {
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
	runes("Щ") // O: the organizations; щ is o: the panel settings
	h.has("Organizations")
	h.key("esc")
	runes("щ")
	h.has("Panels(Servers)")
	h.key("esc")
	// Korean 2-set: ㅓ is j, ㅃ (shift+q) is Q; French AZERTY: é is 2 (ToDo), à is 0 (Scans)
	h.key("1")
	before := h.m.cur[vServers]
	runes("ㅓ")
	if h.m.cur[vServers] != before+1 {
		t.Fatal("ㅓ is not j")
	}
	if latin['ㅃ'] != 'Q' || latin['ㅖ'] != 'P' {
		t.Fatal("shifted jamo")
	}
	h.key("2")
	runes("é")
	if h.m.view != vActions {
		t.Fatalf("é is not 2: view %d", h.m.view)
	}
	runes("\"") // 3 on AZERTY: History
	if h.m.view != vRuns {
		t.Fatalf("\" is not 3: view %d", h.m.view)
	}
	_, cmd := h.m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("й")}) // q
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("й is not q")
	}
}

// card: the card of web-01, as Enter in Access opens it.
func card(h *harness) {
	host := "web-01"
	h.t.Helper()
	h.show(vAccess)
	h.key("/")
	h.typeText(host)
	h.key("enter", "enter")
}

// TestHostCardFirewallRules: the rules a run read are fetched once for the card on screen and shown at its end.
func TestHostCardFirewallRules(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(120, 200)
	card(h)
	h.m.rund.Exposure["web-01"] = map[string]any{"firewall": map[string]any{"readable": true, "has_input_filtering": true}}
	delete(h.m.fwRules, h.m.fwKey("web-01"))
	delete(h.m.pending, "fw")
	if h.m.fetchFirewall() == nil {
		t.Fatal("no request for the rules of the card on screen")
	}
	if h.m.fetchFirewall() != nil {
		t.Fatal("a second request while the first is on the way")
	}
	h.m.Update(fwMsg{h.m.fwKey("web-01"), "## nft\ntable inet filter {\n  chain input { policy drop; }\n}\n"})
	h.has("inbound filtered ↓")
	h.key("G") // the whole lists are at the end
	h.has("Firewall rules", "## nft", "chain input { policy drop; }")
	if h.m.fetchFirewall() != nil {
		t.Fatal("the rules again")
	}
}

// TestDBStatus: checked at start (none yet: a hint), shown in the header, U updates it.
func TestDBStatus(t *testing.T) {
	t.Setenv("KN_TEST_NO_DB", "1")
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.has("no DB U", "No vulnerability DB yet: press U to download it")
	h.key("U")
	h.has("Updating vulnerability DBs")
	for i := 0; i < 200 && (h.m.db == nil || h.m.db.Updating || h.m.dbAttention() != ""); i++ {
		time.Sleep(5 * time.Millisecond)
		h.run(h.m.fetchDB())
	}
	h.has("DB ok")
	h.hasNot("no DB")

	// one running: U does nothing; a newer build out: said so; a failed update: the error
	h.m.db.Updating = true
	if h.m.updateDB() != nil {
		t.Fatal("second update started")
	}
	h.has("updating")
	h.m.db.DBs[1].Outdated = true
	h.m.db.Updating = false
	h.has("newer DB out U")
	h.m.db.Updating = true
	h.run(func() tea.Msg { return dbMsg(dbResp{Error: "no repository worked", Enabled: true}) })
	h.has("DB update failed: no repository worked")

	// read-only: no updates from here
	h2 := newHarness(t, Options{Org: "acme", Env: "production"}, false)
	h2.key("U")
	h2.has("DB updates are off here (read-only)")
	// the help names the server's built-in trivy
	var d dbResp
	if err := json.Unmarshal([]byte(`{"trivy": "0.76.2", "enabled": true, "dbs": [{"name": "db", "updated": "2026-11-07T11:00:00Z"}]}`), &d); err != nil {
		t.Fatal(err)
	}
	h.m.db = &d
	h.key("?")
	h.has("Trivy 0.76.2 · built in")
	h.key("x")

	if agoShort(5*time.Minute) != "5m" || agoShort(3*time.Hour) != "3h" || agoShort(72*time.Hour) != "3d" {
		t.Fatal("agoShort")
	}
}
