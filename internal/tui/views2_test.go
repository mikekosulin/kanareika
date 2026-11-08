package tui

import (
	"strings"
	"testing"
)

// TestAnalysisViews: the web page's tabs, in the TUI: Changes, Access, Network, Health, Exceptions, a run's errors.
func TestAnalysisViews(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(130, 44)

	h.key("4")
	h.has("Changes(acme/production)[1]", "Compared with the full run 2026-11-02 10:00", "+0 (0 CVE)", "−1 (1 CVE)", "custom-check")
	h.key("/", "z", "z", "enter")
	h.has("Changes(acme/production)[0]", "nothing here")
	h.key("esc")

	h.key("5")
	h.has("Access(acme/production)[3]", "PASSWORD", "12.3T", "Successful logins", "10.77.0.24", "Password guessing", "198.51.100.0")
	h.key("enter") // the host's card
	h.has("Host(db-01)")
	h.key("esc")
	h.has("Hosts(acme/production)")

	h.key("6")
	h.has("Network(acme/production)[3]", "192.0.2.1", "Listening ports 3", "internal")
	h.key("f")
	h.has("Listening ports 0", "●")
	h.key("f", "down", "enter")
	h.has("Host(db-01)")

	h.key("7")
	h.has("Health(acme/production)[3]", "50% /", "1")

	h.key("8")
	h.has("Exceptions(acme/production)[4]", "CVE-2026-0040", "no internet", "Already fixed in the installed build 2 CVE", "sqlite-libs")

	h.key("9", "i")
	h.has("Run(2026-11-02 11:00)", "Errors", "dead-01", "host unreachable: timeout", "Log", "No log.")
	h.key("down", "j", "k", "up", "pgdown", "pgup", "G", "g", "esc")
	h.has("Runs(acme/production)[5]")
}

// TestAnalysisViewsRich: the fields real hosts have (as in the module goldens).
func TestAnalysisViewsRich(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.size(160, 50)
	rd := h.m.rund
	rd.Access = map[string]map[string]any{
		"web-01": {"sshd": map[string]any{"permitrootlogin": "yes"}, "password_auth": true, "users_with_password": []any{"root"},
			"keys": []any{map[string]any{"user": "root"}}, "logins": map[string]any{
				"accepted":     []any{map[string]any{"user": "root", "ip": "100.21.0.11", "method": "password", "count": 3.0, "last": "2026-11-01T23:54:24"}},
				"failed_total": 4981.0, "failed_ips": 551.0,
				"attackers": []any{map[string]any{"ip": "100.21.0.14", "n": 353.0, "last": "2026-11-01T05:27:36", "users": []any{[]any{"admin", 10.0}, []any{"oracle", 20.0}}}}}},
		"db-01": {"password_auth": false, "sshd": map[string]any{"permitrootlogin": "without-password"}, "keys": []any{},
			"logins": map[string]any{"accepted": []any{}, "attackers": []any{map[string]any{"ip": "100.21.0.14", "n": 7.0, "users": []any{}}}}},
		"app-01": {"password_auth": true, "sshd": map[string]any{"permitrootlogin": "forced-commands-only"}, "logins": map[string]any{}},
		"x-01":   {"sshd": map[string]any{"permitrootlogin": "weird"}, "logins": map[string]any{}},
	}
	rd.Exposure = map[string]map[string]any{"web-01": {"public": []any{"192.0.2.1", "192.0.2.9"}, "unlisted_public": []any{"192.0.2.9"},
		"listen": []any{map[string]any{"proto": "tcp", "port": 443.0, "public": true, "process": "nginx", "addr": "*"},
			map[string]any{"proto": "tcp", "port": 80.0, "public": true}, map[string]any{"proto": "udp", "port": 323.0, "local_only": true}},
		"firewall": map[string]any{"readable": true, "has_input_filtering": true, "firewalld": "running", "ufw_active": true,
			"iptables_input_policy": "DROP", "docker_rules": true}},
		"db-01":  {"firewall": map[string]any{"readable": false}},
		"app-01": {"firewall": map[string]any{"readable": true, "has_input_filtering": false}},
		"x-01":   {}}
	rd.Health = map[string]map[string]any{
		"web-01": {"disks": []any{map[string]any{"mount": "/", "use": 96.0}, map[string]any{"mount": "/var", "use": 40.0}},
			"inodes": []any{map[string]any{"use": 88.0}}, "mem": map[string]any{"available_mb": 250.0, "total_mb": 1000.0},
			"load": map[string]any{"load15": 0.4, "cpus": 2.0}, "failed_units": []any{"a", "b"},
			"dmesg":   map[string]any{"classes": map[string]any{"dmesg.oom": map[string]any{"count": 3.0}}},
			"journal": map[string]any{"errors_7d": 12.0}, "time": map[string]any{"timezone": "UTC", "synced": "yes", "offset_s": 0.002}},
		"db-01":  {"disks": []any{map[string]any{"mount": "/", "use": 87.0}}, "time": map[string]any{"timezone": "UTC", "synced": "no"}},
		"app-01": {"time": map[string]any{"timezone": "Europe/Moscow", "synced": "yes", "offset_s": 1.5}},
		"x-01":   {"ntp_synced": "unknown"}}
	h.key("5")
	h.has("on", "off", "yes", "key only", "commands", "weird", "4981", "Successful logins", "password", "100.21.0.11",
		"100.21.0.14", "360", "oracle,admin", "db-01,web-01")
	h.key("6")
	h.has("192.0.2.9!", "80 443", "✓ firewalld · ufw · INPUT DROP · docker", "no access", "no filtering", "Listening ports 3",
		"outside", "local", "nginx")
	h.key("7")
	h.has("96% /", "88%", "25% free", "0.4/2", "2", "OOM", "12", "Europe/Moscow!", "✓ 2 ms", "✗", "! 1.5 s", "unknown", "87% /")

	rd.New, rd.Resolved = nil, nil // no previous full run
	h.key("4")
	h.has("No previous full run.")
	rd.Exceptions, rd.Backported = nil, nil
	h.key("8")
	h.has("No exceptions.")
	rd.Access, rd.Exposure, rd.Health = nil, nil, nil
	for _, k := range []string{"5", "6", "7"} {
		h.key(k)
		h.has("has not run yet.")
	}
	h.m.rund = nil
	for _, k := range []string{"4", "5", "8"} {
		h.key(k)
		h.screen()
	}
	for n, want := range map[float64]string{12: "12", 9999: "9999", 12345: "12.3k", 1e6: "1M", 2.5e9: "2.5G", 3e12: "3T"} {
		if compact(n) != want {
			t.Errorf("%v: %s", n, compact(n))
		}
	}
	if abs(-2) != 2 || strings.TrimSpace(m0().fwCell(nil)) != "?" {
		t.Fatal("helpers")
	}
}

func m0() *Model { return New(Options{}) }

// TestOnlySelected: v lists only the selected nodes (P4 among them too), the title counts them.
func TestOnlySelected(t *testing.T) {
	h := newHarness(t, Options{Org: "acme", Env: "production"}, true)
	h.key("v")
	h.has("Nothing selected yet", "ToDo(acme/production)[0]", "<v> selected only")
	h.key("v", "space", "down", "space") // two selected
	h.has("2 selected")
	h.key("v")
	h.has("ToDo(acme/production)[2]", "<v> selected only")
	h.key("v")
	h.has("ToDo(acme/production)[30]", "2 selected")
}
