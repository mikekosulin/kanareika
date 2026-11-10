package report

import (
	"fmt"
	"iter"
	"strings"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// What one fix is (FixKey's kind).
const (
	FixPkg   = "pkg"   // an OS package update (or a library on the host): one source package at one version
	FixImage = "image" // an image to rebuild (docker, or a k8s workload's)
	FixOther = "other" // a misconfiguration, an exposure, a health problem: the check on its hosts
)

// Actionable: a finding that is something to do; inventory, accepted risks and findings without a priority are not.
// Backported ones are actionable but left out of the totals (the installed build has the fix).
func Actionable(f *finding.Finding) bool {
	return f.Kind != finding.Inventory && !f.Accepted && f.Priority != nil
}

// Installable: there is something to install for the finding (or, for other findings, something to change).
func Installable(f *finding.Finding) bool {
	switch f.FixState {
	case finding.FixAvailable, finding.FixReboot:
		return true
	case finding.FixVendor:
		return false
	}
	return f.Kind != finding.Vuln || f.NoFix() == ""
}

// FixKey: the fix a finding belongs to, the unit every count of fixes counts. OS packages: the source package at
// its installed version (libssl3 and openssl of one openssl build are one update; the highest fixed version of its
// CVEs is the target), split into what can be installed now and what has nothing to install yet; a library on the
// host: the package at its path; docker: the image; k8s: the workload's image (the workload when the image is
// unknown); everything else: the check on its hosts.
func FixKey(f *finding.Finding) (key, kind string) {
	switch FixKind(f) {
	case FixOther:
		return "other:" + f.Module + ":" + f.ID + ":" + f.Title, FixOther
	case FixImage:
		if f.Module == "k8s" {
			img := f.Image
			if img == "" {
				img = f.Target
			}
			return "image:k8s:" + img, FixImage
		}
		return "image:docker:" + strings.TrimPrefix(f.Target, "image:"), FixImage
	}
	where, name := "os", f.Source()
	if f.Target != "" && f.Target != "os" {
		where, name = f.Target, f.Pkg // a library on the host
	}
	key = "pkg:" + where + ":" + name + ":" + f.Installed
	if !Installable(f) {
		key += ":nofix"
	}
	return key, FixPkg
}

// FixKind: the kind of FixKey's fix, without making the key.
func FixKind(f *finding.Finding) string {
	switch {
	case f.Kind != finding.Vuln:
		return FixOther
	case f.Module == "k8s", strings.HasPrefix(f.Target, "image:"):
		return FixImage
	}
	return FixPkg
}

// Totals: what there is to do, counted the same way wherever it is shown (the scan's last line, summary.md,
// run.json and view.json, the web page and the TUI, MCP). The headline numbers are Fixes (FixKey: one package
// update on any number of hosts, one image to rebuild, one setting to change — the rows of the to-do tree) and
// CVEs (unique ids). Findings (package × CVE × host rows) is an internal count.
type Totals struct {
	Fixes      int `json:"fixes"`      // fixes to apply
	P1         int `json:"P1"`         // fixes per priority (a fix takes the most urgent of its findings')
	P2         int `json:"P2"`         //
	P3         int `json:"P3"`         //
	P4         int `json:"P4"`         //
	NoFix      int `json:"no_fix"`     // fixes with nothing to install yet (counted in Fixes)
	CVEs       int `json:"cves"`       // unique CVE ids
	Hosts      int `json:"hosts"`      // hosts with something to do
	Findings   int `json:"findings"`   // finding rows (package × CVE × host, plus one per other finding)
	Accepted   int `json:"accepted"`   // findings accepted as risks, not counted above
	Backported int `json:"backported"` // findings the installed build already fixes (package changelog), not counted above
}

// Tally adds findings up into Totals; the tree counts what it shows with it too.
type Tally struct {
	prio     map[string]string // fix -> its most urgent priority
	fixable  map[string]bool   // fix -> something in it can be installed
	cves     map[string]bool
	hosts    map[string]bool
	findings int
}

func NewTally() *Tally {
	return &Tally{prio: map[string]string{}, fixable: map[string]bool{}, cves: map[string]bool{}, hosts: map[string]bool{}}
}

// Add counts an actionable finding.
func (t *Tally) Add(f *finding.Finding) {
	k, _ := FixKey(f)
	t.AddKey(f, k)
}

// AddKey: Add with the finding's FixKey already known.
func (t *Tally) AddKey(f *finding.Finding, k string) {
	t.AddParts(k, f.PriorityOr(), Installable(f), f.Kind == finding.Vuln, f.ID, f.Host)
}

// AddParts: AddKey with what it takes of the finding (fix k, its priority, whether it is installable, whether it
// is a vulnerability, its id and host) given apart, for findings not held as finding.Finding (package fset).
func (t *Tally) AddParts(k, prio string, installable, vuln bool, id, host string) {
	if p, ok := t.prio[k]; !ok || prioRank(prio) < prioRank(p) {
		t.prio[k] = prio
	}
	t.fixable[k] = t.fixable[k] || installable
	if vuln {
		t.cves[id] = true
	}
	t.hosts[host] = true
	t.findings++
}

func (t *Tally) Totals() Totals {
	c := Totals{Fixes: len(t.prio), CVEs: len(t.cves), Hosts: len(t.hosts), Findings: t.findings}
	for k, p := range t.prio {
		switch p {
		case "P1":
			c.P1++
		case "P2":
			c.P2++
		case "P3":
			c.P3++
		case "P4":
			c.P4++
		}
		if !t.fixable[k] {
			c.NoFix++
		}
	}
	return c
}

// ByPriority: fixes per priority, as the tree's priority chips show them.
func (c Totals) ByPriority() map[string]int {
	return map[string]int{"P1": c.P1, "P2": c.P2, "P3": c.P3, "P4": c.P4}
}

// TotalsOf: the totals of a run's (or the current state's) findings.
func TotalsOf(findings []finding.Finding) Totals {
	t, _ := TotalsSeq(func(yield func(*finding.Finding) bool) {
		for i := range findings {
			if !yield(&findings[i]) {
				return
			}
		}
	}, false)
	return t
}

// TotalsByHost: the totals of each host's own findings.
func TotalsByHost(findings []finding.Finding) map[string]Totals {
	_, by := TotalsSeq(func(yield func(*finding.Finding) bool) {
		for i := range findings {
			if !yield(&findings[i]) {
				return
			}
		}
	}, true)
	return by
}

// TotalsSeq: TotalsOf of the findings seq gives one at a time (each may be reused), and with byHost TotalsByHost.
func TotalsSeq(seq iter.Seq[*finding.Finding], byHost bool) (Totals, map[string]Totals) {
	type counter struct {
		t       *Tally
		acc, bp int
	}
	add := func(c *counter, f *finding.Finding) {
		switch {
		case f.Backported:
			if Actionable(f) {
				c.bp++
			}
		case f.Accepted:
			c.acc++
		case Actionable(f):
			c.t.Add(f)
		}
	}
	totals := func(c *counter) Totals {
		t := c.t.Totals()
		t.Accepted, t.Backported = c.acc, c.bp
		return t
	}
	all := &counter{t: NewTally()}
	hosts := map[string]*counter{}
	for f := range seq {
		add(all, f)
		if byHost {
			c := hosts[f.Host]
			if c == nil {
				c = &counter{t: NewTally()}
				hosts[f.Host] = c
			}
			add(c, f)
		}
	}
	var by map[string]Totals
	if byHost {
		by = map[string]Totals{}
		for h, c := range hosts {
			by[h] = totals(c)
		}
	}
	return totals(all), by
}

// HighestFix: the highest fixed version (natural version order), "" when none.
func HighestFix(versions []string) string {
	set := map[string]bool{}
	for _, v := range versions {
		if v != "" {
			set[v] = true
		}
	}
	vs := sortedVersions(set)
	if len(vs) == 0 {
		return ""
	}
	return vs[len(vs)-1]
}

// Line: the totals in one line, as the scan's last line and summary.md say them.
func (c Totals) Line() string {
	s := fmt.Sprintf("%d fixes to apply (P1 %d, P2 %d, P3 %d, P4 %d)", c.Fixes, c.P1, c.P2, c.P3, c.P4)
	if c.NoFix > 0 {
		s += fmt.Sprintf(", %d of them with nothing to install yet", c.NoFix)
	}
	return s + fmt.Sprintf("; %d unique %s; %d %s with something to do", c.CVEs, plural(c.CVEs, "CVE", "CVEs"),
		c.Hosts, plural(c.Hosts, "host", "hosts"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
