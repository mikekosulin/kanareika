package tree

import (
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
)

// TestSameNameOtherOS: libc6 of Ubuntu 22.04 and of Debian 12 are two top rows; they name their OS. Two versions
// on the same OS do not (the versions tell them apart).
func TestSameNameOtherOS(t *testing.T) {
	hosts := Hosts{"u1": {OS: osName("Ubuntu 22.04.5 LTS")}, "d1": {OS: osName("Debian GNU/Linux 12 (bookworm)")},
		"d2": {OS: osName("Debian GNU/Linux 12 (bookworm)")}}
	f := func(host, pkg, inst string) finding.Finding {
		return finding.Finding{Host: host, Group: "g", Module: "os_packages", Kind: finding.Vuln, ID: "CVE-1", Pkg: pkg,
			Installed: inst, Fixed: inst + "1", Target: "os", FixState: finding.FixAvailable, Priority: p("P2")}
	}
	fs := []finding.Finding{f("u1", "libc6", "2.35-0ubuntu3.8"), f("d1", "libc6", "2.36-9+deb12u7"),
		f("d1", "curl", "7.88.1-10+deb12u5"), f("d2", "curl", "7.88.1-10+deb12u8")}
	got := map[string]string{}
	for _, n := range Build(fs, hosts, Opts{}).Nodes {
		got[n.Label+" "+n.Installed] = n.OS
	}
	for k, want := range map[string]string{"libc6 (Ubuntu 22.04) 2.35-0ubuntu3.8": "Ubuntu 22.04",
		"libc6 (Debian 12) 2.36-9+deb12u7": "Debian 12", "curl 7.88.1-10+deb12u5": "", "curl 7.88.1-10+deb12u8": ""} {
		if os, ok := got[k]; !ok || os != want {
			t.Errorf("%s: %q (%v)", k, os, got)
		}
	}
	for in, want := range map[string]string{"Rocky Linux 9.4 (Blue Onyx)": "Rocky Linux 9.4", "Amazon Linux 2023": "Amazon Linux 2023",
		"Ubuntu 18.04.6 LTS": "Ubuntu 18.04", "": ""} {
		if got := ShortOS(in); got != want {
			t.Errorf("ShortOS(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestServers: every host of the env, flat, most urgent first, clean ones last; filters narrow what is under the
// rows, not the rows.
func TestServers(t *testing.T) {
	fs, hosts := fleet()
	inv := []HostInfo{{Name: "web-01", Group: "web", Exposure: 1}, {Name: "api-01", Group: "api"},
		{Name: "quiet-01", Group: "misc", LastScan: "2026-11-08T03:00:00Z"},
		{Name: "down-01", Group: "misc", State: StateFailed, Problem: i18n.Text{Text: "x"}}}
	tr := Build(fs, hosts, Opts{By: ByHost, All: true, Inventory: inv, Filters: []string{FKEV}, Today: "2026-11-09"})
	var order []string
	byName := map[string]*Node{}
	for _, n := range tr.Nodes {
		order = append(order, n.Label+":"+n.State)
		byName[n.Label] = n
	}
	if order[0] != "api-01:todo" || order[len(order)-1] != "quiet-01:clean" {
		t.Errorf("order %v", order)
	}
	w := byName["web-01"]
	if w == nil || len(w.Kids) != 0 || w.Fixes != 2 || w.Counts["P2"] != 2 || w.Priority != "P2" {
		t.Errorf("web-01 (nothing KEV under it, still a row with its counts): %+v", w)
	}
	if a := byName["api-01"]; a == nil || len(a.Kids) != 1 || !a.Overdue {
		t.Errorf("api-01: %+v", a)
	}
	if d := byName["down-01"]; d == nil || d.State != StateFailed || d.Problem != "x" || d.Hosts != 1 {
		t.Errorf("down-01: %+v", d)
	}
	if q := byName["quiet-01"]; q.LastScan != "2026-11-08T03:00:00Z" || q.Fixes != 0 {
		t.Errorf("quiet-01: %+v", q)
	}
	if tr.Servers[StateClean] != 1 || tr.Servers[StateFailed] != 1 || byName["web-09"] == nil || byName["k8s:prod"] == nil {
		t.Errorf("servers %v, rows %v", tr.Servers, order)
	}
	if tr.Find("h:api-01") == nil {
		t.Error("host rows are found by id")
	}
}
