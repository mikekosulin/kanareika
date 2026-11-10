package tree

import (
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/report"
)

// TestSorted: each column orders the rows its natural way (most CVEs, earliest due with none last, A to Z), "-"
// the other way, ties keep the tree's order; the tree itself is not changed; an unknown column is an error.
func TestSorted(t *testing.T) {
	tr := &Tree{Nodes: []*Node{
		{Label: "b", CVEs: 2, Due: "", Priority: "P2", EPSS: 0.1, Hosts: 1, Fixes: 3, LastScan: "2026-11-02"},
		{Label: "a", CVEs: 9, Due: "2026-12-01", Priority: "P1", EPSS: 0.9, Hosts: 3, Fixes: 1, LastScan: "2026-11-09"},
		{Label: "C", CVEs: 2, Due: "2026-11-20", Priority: "", EPSS: 0.5, Hosts: 2, Fixes: 2, LastScan: ""},
	}}
	for by, want := range map[string]string{
		"": "baC", "cve": "abC", "-cve": "bCa", "due": "Cab", "-due": "baC", "name": "abC", "-name": "Cba",
		"pri": "abC", "epss": "aCb", "hosts": "aCb", "fixes": "bCa", "scanned": "abC",
	} {
		f, err := Sorter(by)
		if err != nil {
			t.Fatal(by, err)
		}
		var got strings.Builder
		for _, n := range tr.Sorted(f).Nodes {
			got.WriteString(n.Label)
		}
		if got.String() != want {
			t.Errorf("%q: %s, want %s", by, got.String(), want)
		}
	}
	if tr.Nodes[0].Label != "b" {
		t.Fatal("the tree itself was sorted")
	}
	if _, err := Sorter("size"); err == nil {
		t.Fatal("an unknown column")
	}
	// kids in the same order; a level with headings stays as it is
	f, _ := Sorter("name")
	ns := []*Node{{Label: "x", Kids: []*Node{{Label: "z"}, {Label: "y"}}}, {Label: "w", Kids: []*Node{{Label: "q", Kind: KindSection}, {Label: "p"}}}}
	SortAll(ns, f)
	if ns[0].Label != "w" || ns[1].Kids[0].Label != "y" || ns[0].Kids[0].Label != "q" {
		t.Fatalf("%s %s %s", ns[0].Label, ns[1].Kids[0].Label, ns[0].Kids[0].Label)
	}
}

// TestDescribeHighestSeverity: a CVE rated differently on two hosts lists the highest rating, in either order.
func TestDescribeHighestSeverity(t *testing.T) {
	hosts := Hosts{}
	mk := func(host, sev string) finding.Finding {
		return finding.Finding{Org: "acme", Host: host, Group: "g", Module: "os_packages", Kind: finding.Vuln, ID: "CVE-0000-0001",
			Pkg: "openssl", Installed: "1", Fixed: "2", Severity: sev, Target: "os", FixState: finding.FixAvailable, Priority: p("P2")}
	}
	for _, fs := range [][]finding.Finding{{mk("a", "MEDIUM"), mk("b", "HIGH")}, {mk("b", "HIGH"), mk("a", "MEDIUM")}} {
		tr := Build(fs, hosts, Opts{})
		d := Describe(tr.Nodes[0], hosts, &report.View{}, "2026-11-10")
		if len(d.CVEs) != 1 || d.CVEs[0].Severity != "HIGH" {
			t.Fatalf("%+v", d.CVEs)
		}
	}
}
