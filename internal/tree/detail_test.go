package tree

import (
	"slices"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/report"
)

// TestDescribeOtherFamilies: Alpine and SUSE hosts get their package manager's command, one step each in the order
// the hosts come; a pre-auth flaw that is no RCE says so; the groups are listed with the most hosts first, then by
// name; without a date for today the due date counts no days (never a made-up overdue).
func TestDescribeOtherFamilies(t *testing.T) {
	hosts := Hosts{"edge-01": {OS: osName("Alpine Linux v3.20")}}
	vuln := func(host, group string) finding.Finding {
		return finding.Finding{Org: "acme", Host: host, Group: group, Exposure: 3, Module: "os_packages", Kind: finding.Vuln,
			ID: "CVE-0000-0001", Pkg: "openssl", Installed: "1", Fixed: "2", Severity: "HIGH", Target: "os",
			FixState: finding.FixAvailable, Priority: p("P2"), Due: p("2026-12-01"), Preauth: true}
	}
	fs := []finding.Finding{vuln("edge-01", "edge")}
	for _, h := range []struct{ name, group string }{{"db-01", "db"}, {"web-01", "web"}, {"web-02", "web"}, {"app-01", "app"}} {
		hosts[h.name] = report.Fact{OS: osName("openSUSE Leap 15.6")}
		fs = append(fs, vuln(h.name, h.group))
	}
	tr := Build(fs, hosts, Opts{})
	if len(tr.Nodes) != 1 {
		t.Fatalf("nodes %s", labels(tr.Nodes))
	}
	d := Describe(tr.Nodes[0], hosts, nil, "")
	var steps []string
	for _, s := range d.Apply {
		steps = append(steps, s.Command+" @ "+strings.Join(s.Hosts, ","))
	}
	if want := []string{"apk upgrade openssl @ edge-01", "zypper update openssl @ app-01,db-01,web-01,web-02"}; !slices.Equal(steps, want) {
		t.Errorf("apply %q", steps)
	}
	var where []string
	for _, w := range d.Where {
		where = append(where, w.Group+":"+strings.Join(w.Hosts, ","))
	}
	if strings.Join(where, " ") != "web:web-01,web-02 app:app-01 db:db-01 edge:edge-01" {
		t.Errorf("where %v", where)
	}
	if len(d.Why) != 1 || d.Why[0].Code != "preauth" {
		t.Errorf("why %+v", d.Why)
	}
	if due := d.Due; due.Date != "2026-12-01" || due.In != 0 || due.Overdue != 0 {
		t.Errorf("due without today: %+v", due)
	}
}

// TestServersStates: a host the last scan did not reach says why (with what to do when the error is a known one);
// what a module could not read makes a host partial, whether the keys came decoded or made in code; keys that are
// no list are ignored; hosts of other environments are left out.
func TestServersStates(t *testing.T) {
	org := &config.Org{Hosts: []config.Host{{Name: "web-01", Env: "production", Group: "web"},
		{Name: "web-02", Env: "production", Group: "web"}, {Name: "web-03", Env: "production", Group: "web"},
		{Name: "web-04", Env: "production", Group: "web"}, {Name: "stage-01", Env: "staging", Group: "web"}}}
	meta := &report.Meta{RunID: "2026-11-08_030000", HostsScanned: []string{"web-01", "web-02", "web-03", "web-04"}}
	refused := "dial tcp 192.0.2.12:22: connect: connection refused"
	meta.HostsFailed.Set("web-01", "exit status 255")
	meta.HostsFailed.Set("web-02", refused)
	limited := []finding.Finding{
		{Host: "web-03", Kind: finding.Inventory, ID: "access-limited", Args: map[string]any{"what_keys": []string{"denied.shadow"}}},
		{Host: "web-04", Kind: finding.Inventory, ID: "health-limited", Args: map[string]any{"what_keys": "denied.journal"}},
	}
	got := map[string]HostInfo{}
	for _, hi := range Servers(org, "production", &report.View{Meta: meta}, slices.Values(ptrs(limited))) {
		got[hi.Name] = hi
	}
	if len(got) != 4 {
		t.Fatalf("hosts %v", got)
	}
	if hi := got["web-01"]; hi.State != StateFailed || hi.Problem.Text != i18n.Msg("host.failed", map[string]any{"why": "exit status 255"}).Text {
		t.Errorf("web-01: %+v", hi)
	}
	if hi := got["web-02"]; hi.State != StateFailed || !strings.HasSuffix(hi.Problem.Text, "("+refused+")") ||
		!strings.Contains(hi.Problem.Text, "nothing listens on that port") {
		t.Errorf("web-02: %+v", hi)
	}
	want := i18n.Msg("denied.title", map[string]any{"what_keys": []string{"denied.shadow"}})
	if hi := got["web-03"]; hi.State != StatePartial || hi.Problem.Text != want.Text {
		t.Errorf("web-03: %+v", hi)
	}
	if hi := got["web-04"]; hi.State != "" || hi.Problem.Text != "" || hi.LastScan != "2026-11-08T03:00:00Z" {
		t.Errorf("web-04: %+v", hi)
	}
}

func ptrs(fs []finding.Finding) []*finding.Finding {
	out := make([]*finding.Finding, len(fs))
	for i := range fs {
		out[i] = &fs[i]
	}
	return out
}

// TestKeyStable: a finding's selection key stays the same between runs (priority, due date and texts change) and
// differs between hosts.
func TestKeyStable(t *testing.T) {
	fs, _ := fleet()
	a := fs[0]
	b := a
	b.Priority, b.Due, b.EPSS, b.Title = p("P1"), p("2026-11-10"), e(0.9), "openssl: flaw, rated again"
	c := a
	c.Host = "web-02"
	if Key(&a) == "" || Key(&a) != Key(&b) || Key(&a) == Key(&c) {
		t.Fatalf("%q %q %q", Key(&a), Key(&b), Key(&c))
	}
}

// TestSelectStops: Select yields the findings keep picks and stops when the caller does.
func TestSelectStops(t *testing.T) {
	fs, _ := fleet()
	s := NewSet(fs)
	misconfig := func(kind, _ string) bool { return kind == finding.Misconfig }
	var all []string
	for f := range s.Select(misconfig) {
		all = append(all, f.Host+"/"+f.ID)
	}
	if !slices.Equal(all, []string{"web-01/ssh-password-auth", "web-02/ssh-password-auth"}) {
		t.Fatalf("selected %v", all)
	}
	n := 0
	for range s.Select(misconfig) {
		n++
		break
	}
	if n != 1 {
		t.Fatalf("%d after break", n)
	}
}
