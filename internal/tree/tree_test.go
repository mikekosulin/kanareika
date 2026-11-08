package tree

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/report"
)

func p(s string) *string      { return &s }
func e(v float64) *float64    { return &v }
func osName(s string) *string { return &s }

// fleet: openssl on 9 web hosts (one waiting for a reboot of nothing: a vendor one too), the same CVE in a docker
// image on 2 api hosts and in a k8s workload, a misconfiguration on 2 hosts, an inventory note, an accepted risk,
// a backported one.
func fleet() ([]finding.Finding, Hosts) {
	var fs []finding.Finding
	hosts := Hosts{}
	vuln := func(host, group, pkg, id string, mod func(*finding.Finding)) {
		f := finding.Finding{Org: "acme", Host: host, Group: group, Exposure: 1, Module: "os_packages", Kind: finding.Vuln,
			ID: id, Pkg: pkg, Installed: "1.0", Fixed: "1.1", Severity: "HIGH", Target: "os", FixState: finding.FixAvailable,
			Priority: p("P2"), Due: p("2026-12-01"), DueWhy: finding.DueFirstSeen, FirstSeen: "2026-11-01", ClockStart: "2026-11-01",
			EPSS: e(0.2), Title: pkg + ": flaw", CVSSScore: e(7.5), Description: "made up"}
		if mod != nil {
			mod(&f)
		}
		fs = append(fs, f)
	}
	for i := 1; i <= 9; i++ {
		h := fmt.Sprintf("web-%02d", i)
		hosts[h] = report.Fact{OS: osName("Debian GNU/Linux 12 (bookworm)")}
		vuln(h, "web", "openssl", "CVE-1", nil)
		vuln(h, "web", "openssl", "CVE-2", func(f *finding.Finding) { f.Priority, f.Due, f.EPSS = p("P3"), p("2027-02-01"), e(0.01) })
	}
	vuln("web-09", "web", "libxml2", "CVE-3", func(f *finding.Finding) { f.Fixed, f.FixState, f.EPSS = "", finding.FixVendor, e(0.01) })
	for _, h := range []string{"api-01", "api-02"} {
		hosts[h] = report.Fact{OS: osName("Rocky Linux 9.4 (Blue Onyx)")}
		vuln(h, "api", "openssl", "CVE-1", func(f *finding.Finding) { f.Module, f.Target, f.Exposure = "docker", "image:reg/api:1", 2 })
		vuln(h, "api", "log4j-core", "CVE-9", func(f *finding.Finding) {
			f.Module, f.Target, f.PkgPath, f.KEV, f.Preauth, f.RCE, f.Priority, f.Due, f.EPSS, f.Exposure =
				"docker", "image:reg/api:1", "/app/log4j.jar", true, true, true, p("P1"), p("2026-11-05"), e(0.97), 2
		})
		vuln(h, "api", "sudo", "CVE-4", func(f *finding.Finding) { f.Backported, f.FixState = true, "" })
	}
	vuln("k8s:prod", "k8s:prod", "openssl", "CVE-1", func(f *finding.Finding) {
		f.Module, f.Target, f.Image, f.Exposure = "k8s", "jobs/Deployment/worker", "reg/worker:5", 2
	})
	for _, h := range []string{"web-01", "web-02"} {
		fs = append(fs, finding.Finding{Org: "acme", Host: h, Group: "web", Exposure: 1, Module: "access", Kind: finding.Misconfig,
			ID: "ssh-password-auth", Title: "SSH password login enabled", Severity: "HIGH", Priority: p("P2"), Due: p("2026-11-20")})
	}
	fs = append(fs, finding.Finding{Host: "web-01", Group: "web", Module: "access", Kind: finding.Inventory, ID: "ssh-bruteforce"},
		finding.Finding{Host: "web-02", Group: "web", Module: "os_packages", Kind: finding.Vuln, ID: "CVE-8", Pkg: "zlib",
			Priority: p("P1"), Accepted: true, Target: "os"})
	return fs, hosts
}

func labels(ns []*Node) string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Kind+":"+n.Label)
	}
	return strings.Join(out, " ")
}

func TestByFix(t *testing.T) {
	fs, hosts := fleet()
	tr := Build(fs, hosts, Opts{})
	if tr.By != ByFix || labels(tr.Nodes) != "image:reg/api:1 pkg:openssl image:reg/worker:5 pkg:libxml2 other:SSH password login enabled" {
		t.Fatalf("order: %s", labels(tr.Nodes))
	}
	if tr.Hidden != 2 || tr.Fixes != 5 || tr.CVEs != 4 || tr.Hosts != 12 || tr.Counts["P1"] != 1 || tr.Counts["P2"] != 4 {
		t.Fatalf("totals: %+v", tr)
	}
	ssl := tr.Nodes[1]
	if ssl.Hosts != 9 || ssl.CVEs != 2 || ssl.Priority != "P2" || ssl.Due != "2026-12-01" || len(ssl.Kids) != 1 ||
		ssl.Kids[0].Kind != KindGroup || len(ssl.Kids[0].Kids) != 9 || ssl.HostList != nil || ssl.States[finding.FixAvailable] != 9 {
		t.Fatalf("a package on 9 hosts: grouped, aggregated: %+v", ssl)
	}
	api := tr.Nodes[0]
	if api.Runtime != "docker" || !api.KEV || !api.RCE || api.Priority != "P1" || api.Hosts != 2 {
		t.Fatalf("image: %+v", api)
	}
	if labels(api.Kids) != "section:parts part:log4j-core part:openssl section:where where:image:reg/api:1" ||
		api.Kids[1].Path != "/app/log4j.jar" || len(api.Kids[4].Kids) != 2 {
		t.Fatalf("image kids: %s", labels(api.Kids))
	}
	k8s := tr.Nodes[2]
	if k8s.Runtime != "k8s" || labels(k8s.Kids) != "section:parts part:openssl section:where where:prod · jobs/Deployment/worker" {
		t.Fatalf("k8s: %s", labels(k8s.Kids))
	}
	if tr.Find(ssl.Kids[0].Kids[3].ID) == nil || tr.Find("nope") != nil {
		t.Fatal("Find")
	}
	if len(tr.Nodes[3].HostList) != 1 || tr.Nodes[3].States[finding.FixVendor] != 1 {
		t.Fatalf("few hosts are listed: %+v", tr.Nodes[2])
	}
}

func TestByCVEAndHost(t *testing.T) {
	fs, hosts := fleet()
	tr := Build(fs, hosts, Opts{By: ByCVE})
	c1 := tr.Find("cve:CVE-1")
	if c1 == nil || c1.Hosts != 12 || labels(c1.Kids) != "pkg:openssl image:reg/api:1 image:reg/worker:5" {
		t.Fatalf("one CVE, three fixes: %+v", c1)
	}
	if tr.Find("other:access:ssh-password-auth:SSH password login enabled") == nil {
		t.Fatal("not a CVE: listed as itself")
	}
	tr = Build(fs, hosts, Opts{By: ByHost})
	if labels(tr.Nodes) != "group:api group:web group:k8s:prod" {
		t.Fatalf("%s", labels(tr.Nodes))
	}
	w9 := tr.Find("g:web/h:web-09")
	if w9 == nil || labels(w9.Kids) != "pkg:openssl pkg:libxml2" && labels(w9.Kids) != "pkg:libxml2 pkg:openssl" || w9.Kids[0].Kids != nil || w9.OS == "" {
		t.Fatalf("a host's fixes, not repeating the host: %+v", w9)
	}
}

func TestFilters(t *testing.T) {
	fs, hosts := fleet()
	for _, c := range []struct {
		o    Opts
		want string
	}{
		{Opts{Filters: []string{FKEV}}, "image:reg/api:1"},
		{Opts{Filters: []string{FRCE}}, "image:reg/api:1"},
		{Opts{Filters: []string{FEPSS}}, "image:reg/api:1 pkg:openssl image:reg/worker:5"},
		{Opts{Filters: []string{FFront, FNoFix}}, "pkg:libxml2"},
		{Opts{Filters: []string{FReady}, Query: "web-09"}, "pkg:openssl other:SSH password login enabled"[:11]},
		{Opts{Filters: []string{FOverdue}, Today: "2026-11-10"}, "image:reg/api:1"},
		{Opts{Filters: []string{FOverdue}}, ""},
		{Opts{Query: "LOG4J"}, "image:reg/api:1"},
		{Opts{Query: "worker"}, "image:reg/worker:5"},
		{Opts{Backported: true, Query: "sudo"}, "pkg:sudo"},
	} {
		if got := labels(Build(fs, hosts, c.o).Nodes); got != c.want {
			t.Errorf("%+v: %q, want %q", c.o, got, c.want)
		}
	}
}

func TestDescribe(t *testing.T) {
	fs, hosts := fleet()
	view := &report.View{Actions: []report.Action{
		{ID: "a1", Hosts: []string{"web-01"}, Packages: []report.Package{{Pkg: "openssl"}}},
		{ID: "a2", Hosts: []string{"api-01"}, Image: p("reg/api:1")},
		{ID: "a3", Hosts: []string{"web-02"}, Title: "SSH password login enabled"},
		{ID: "a4", Hosts: []string{"db-01"}, Packages: []report.Package{{Pkg: "openssl"}}},
	}}
	tr := Build(fs, hosts, Opts{})
	d := Describe(tr.Nodes[1], hosts, view, "2026-11-08")
	if d.Due.Date != "2026-12-01" || d.Due.In != 23 || d.Due.Overdue != 0 || d.Due.FirstSeen != "2026-11-01" || d.Due.Why != "first_seen" {
		t.Fatalf("due: %+v", d.Due)
	}
	if len(d.CVEs) != 2 || d.CVEs[0].ID != "CVE-1" || d.CVEs[0].Hosts != 9 || d.CVEs[0].CVSS == nil || d.CVEs[0].Description == "" {
		t.Fatalf("cves: %+v", d.CVEs)
	}
	if len(d.Where) != 1 || len(d.Where[0].Hosts) != 9 || d.Where[0].OS == "" {
		t.Fatalf("where: %+v", d.Where)
	}
	if len(d.Apply) != 1 || d.Apply[0].Command != "apt-get update && apt-get install --only-upgrade openssl" || len(d.Apply[0].Hosts) != 9 {
		t.Fatalf("apply: %+v", d.Apply)
	}
	if strings.Join(d.Actions, ",") != "a1" || len(d.Why) == 0 {
		t.Fatalf("actions %v why %v", d.Actions, d.Why)
	}
	img := Describe(tr.Nodes[0], hosts, view, "2026-11-08")
	codes := []string{}
	for _, r := range img.Why {
		codes = append(codes, r.Code)
	}
	if img.Due.Overdue != 3 || strings.Join(codes, ",") != "kev,rce,epss" || strings.Join(img.Actions, ",") != "a2" || img.Apply != nil {
		t.Fatalf("image: due %+v why %v actions %v apply %v", img.Due, codes, img.Actions, img.Apply)
	}
	other := Describe(tr.Nodes[4], hosts, view, "2026-11-08")
	if strings.Join(other.Actions, ",") != "a3" || len(other.CVEs) != 0 {
		t.Fatalf("other: %+v", other)
	}
	vendor := Describe(tr.Nodes[3], hosts, nil, "2026-11-08")
	if vendor.Apply != nil || vendor.Why[len(vendor.Why)-1].Code != "nofix" {
		t.Fatalf("no fix: %+v", vendor)
	}
}

func TestFamily(t *testing.T) {
	for os, want := range map[string]string{"Debian GNU/Linux 12": "apt", "Ubuntu 22.04.5 LTS": "apt", "Rocky Linux 9.4": "dnf",
		"Alpine Linux v3.20": "apk", "openSUSE Leap 15.6": "zypper", "": ""} {
		if got := family(os); got != want {
			t.Errorf("%q: %q, want %q", os, got, want)
		}
	}
	if command("", "x") != "" || !strings.HasPrefix(command("dnf", "x"), "dnf") {
		t.Error("command")
	}
}
