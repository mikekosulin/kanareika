package lens

import (
	"encoding/json"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/tree"
)

// TestDefinitions: unique lenses and columns, known kinds, and every title a message in every language.
func TestDefinitions(t *testing.T) {
	kinds := map[string]bool{Text: true, Number: true, Percent: true, Duration: true, Bytes: true, Bool: true, Mark: true}
	cat := i18n.Catalog()
	ids := map[string]bool{}
	for _, l := range All {
		if ids[l.ID] || l.cells == nil || len(l.Columns) == 0 {
			t.Errorf("lens %q: duplicate or empty", l.ID)
		}
		ids[l.ID] = true
		check := func(key string) {
			if len(cat[key]) != len(i18n.Langs()) {
				t.Errorf("%s: in %d of %d languages", key, len(cat[key]), len(i18n.Langs()))
			}
		}
		check("lens." + l.ID)
		keys := map[string]bool{}
		for _, c := range l.Columns {
			if keys[c.Key] || !kinds[c.Kind] || c.Align == "" || c.WidthHint == 0 {
				t.Errorf("%s/%s: %+v", l.ID, c.Key, c)
			}
			keys[c.Key] = true
			check(c.TitleKey)
		}
	}
	if Get("") != &All[0] || Get("logins").ID != "logins" || Get("nope") != nil {
		t.Error("Get")
	}
}

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func p(s string) *string { return &s }

// rows: one lens over hosts a, b, c with the given per-host data.
func rows(t *testing.T, id string, health, access, exposure map[string]string, fs []finding.Finding) map[string]map[string]Cell {
	t.Helper()
	v := &report.View{Health: map[string]any{}, Access: map[string]any{}, Exposure: map[string]any{}, Facts: map[string]report.Fact{}}
	var inv []tree.HostInfo
	for _, h := range []string{"a", "b", "c"} {
		inv = append(inv, tree.HostInfo{Name: h, Group: "g"})
		if s, ok := health[h]; ok {
			v.Health[h] = decode(t, s)
		}
		if s, ok := access[h]; ok {
			v.Access[h] = decode(t, s)
		}
		if s, ok := exposure[h]; ok {
			v.Exposure[h] = decode(t, s)
		}
	}
	tr := tree.Build(fs, tree.Hosts(v.Facts), tree.Opts{By: tree.ByHost, All: true, Inventory: inv})
	res := Build(Get(id), Input{Servers: tr, View: v, Findings: fs})
	out := map[string]map[string]Cell{}
	for _, r := range res.Rows {
		out[r.Host] = r.Cells
	}
	return out
}

func level(t *testing.T, got map[string]map[string]Cell, host, key, want string) {
	t.Helper()
	if c := got[host][key]; c.Level != want {
		t.Errorf("%s %s: level %q (%+v), want %q", host, key, c.Level, c, want)
	}
}

func TestHealthLevels(t *testing.T) {
	got := rows(t, "health", map[string]string{
		"a": `{"disks":[{"mount":"/","use":40},{"mount":"/var","use":86}],"inodes":[{"mount":"/","use":96}],
			"mem":{"total_mb":1000,"available_mb":40},"load":{"load15":9,"cpus":4},"failed_units":["x.service"],
			"journal":{"errors_7d":3},"time":{"offset_s":1.5,"synced":"yes","service_active":true,"timezone":"Europe/Berlin"}}`,
		"b": `{"disks":[{"mount":"/","use":84}],"inodes":[{"mount":"/","use":85}],"mem":{"total_mb":1000,"available_mb":100},
			"load":{"load15":1,"cpus":4},"failed_units":[],"journal":{"errors_7d":0},
			"time":{"offset_s":0.002,"synced":"yes","service_active":true,"skew_s":40,"timezone":"Etc/UTC"}}`,
		"c": `{"disks":[{"mount":"/","use":95}],"mem":{"total_mb":1000,"available_mb":500},"denied":["denied.journal"],
			"time":{"offset_s":0.002,"synced":"yes","service_active":true,"timezone":"Etc/UTC"}}`,
	}, nil, nil, []finding.Finding{{Host: "c", Module: "hardening", Kind: finding.Misconfig, ID: "reboot-required", Priority: p("P3")}})
	level(t, got, "a", "disk", Warn)
	if s := got["a"]["disk"].S; s != "86% /var" {
		t.Errorf("disk shows %q", s)
	}
	level(t, got, "b", "disk", OK)
	level(t, got, "c", "disk", Bad)
	level(t, got, "a", "inodes", Bad)
	level(t, got, "b", "inodes", Warn)
	level(t, got, "a", "mem_free", Bad)  // 4% free
	level(t, got, "b", "mem_free", Warn) // 10%
	level(t, got, "c", "mem_free", OK)
	level(t, got, "a", "load", Warn) // 9 > 4 CPUs × 2
	level(t, got, "b", "load", OK)
	level(t, got, "a", "failed_units", Warn)
	level(t, got, "a", "clock", Warn) // offset 1.5 s
	level(t, got, "b", "clock", Bad)  // 40 s off the scanner's clock
	level(t, got, "c", "clock", OK)
	level(t, got, "a", "timezone", Warn) // two of three hosts are on Etc/UTC
	level(t, got, "b", "timezone", OK)
	level(t, got, "c", "reboot", Warn)
	if c := got["c"]["journal"]; c.S != ResultUnknown || c.Note == "" {
		t.Errorf("journal without root: %+v", c)
	}
}

func TestLoginsAndNetwork(t *testing.T) {
	got := rows(t, "logins", nil, map[string]string{
		"a": `{"password_auth":true,"users_with_password":["admin"],"sshd":{"permitrootlogin":"yes"},"keys":[{"user":"root"},{"user":"bob"}],
			"logins":{"failed_daily":{"2026-11-06":5,"2026-11-07":1200},"failed_total":1205,"failed_ips":7,"attackers":[{"last":"2026-11-07T04:14:00"}]},"denied":[]}`,
		"b": `{"password_auth":false,"users_with_password":[],"sshd":{"permitrootlogin":"without-password"},"keys":[],
			"logins":{"failed_daily":{}},"denied":[]}`,
		"c": `{"password_auth":true,"users_with_password":null,"sshd":{"permitrootlogin":"no"},"keys":[],"denied":["denied.shadow","denied.authlog"]}`,
	}, nil, nil)
	level(t, got, "a", "password", Bad)
	level(t, got, "b", "password", OK)
	level(t, got, "c", "password", Warn)
	level(t, got, "a", "root", Bad)
	level(t, got, "b", "root", OK)
	level(t, got, "a", "failed_24h", Bad)
	level(t, got, "b", "failed_24h", OK)
	if c := got["a"]["failed_24h"]; c.V != 1200 {
		t.Errorf("failed in the last day: %+v", c)
	}
	if c := got["a"]["last_attack"]; c.S != "2026-11-07 04:14" {
		t.Errorf("last attack %+v", c)
	}
	for _, k := range []string{"pw_users", "failed_24h", "last_attack"} {
		if c := got["c"][k]; c.S != ResultUnknown || c.Note != "not checked (needs root)" {
			t.Errorf("c %s: %+v", k, c)
		}
	}
	if c := got["a"]["keys"]; c.V != 2 || c.Note != "root: 1" {
		t.Errorf("keys %+v", c)
	}

	got = rows(t, "network", nil, nil, map[string]string{
		"a": `{"public":["203.0.113.5"],"unlisted_public":["203.0.113.5"],"listen":[{"port":22,"public":true},{"port":6379,"public":true},
			{"port":323,"local_only":true}],"firewall":{"readable":true,"has_input_filtering":false,"iptables_input_policy":"ACCEPT"}}`,
		"b": `{"public":[],"unlisted_public":[],"listen":[{"port":5432}],"firewall":{"readable":true,"has_input_filtering":true,"ufw_active":true}}`,
		"c": `{"public":[],"unlisted_public":[],"listen":[],"firewall":{"readable":false},"denied":["denied.firewall"]}`,
	}, nil)
	level(t, got, "a", "public_ips", Bad)
	level(t, got, "a", "open_ports", Warn)
	if c := got["a"]["open_ports"]; c.S != "22 6379" {
		t.Errorf("ports %+v", c)
	}
	level(t, got, "a", "firewall", Bad)
	level(t, got, "b", "firewall", OK)
	level(t, got, "b", "open_ports", OK)
	if c := got["c"]["firewall"]; c.S != ResultUnknown {
		t.Errorf("firewall without root: %+v", c)
	}
	if got["a"]["listening"].V != 2 || got["b"]["listening"].V != 1 {
		t.Errorf("listening %+v %+v", got["a"]["listening"], got["b"]["listening"])
	}
}

func TestLocalized(t *testing.T) {
	res := Build(Get("network"), Input{Lang: "ru"})
	if res.Lens.Title != "Сеть" || res.Lens.Columns[2].Title != "Firewall" || res.Lenses[0].Title != "Приоритеты" ||
		res.Lens.Columns[0].TitleKey != "lens.col.public_ips" {
		t.Errorf("%+v", res)
	}
}
