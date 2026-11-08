package report

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

var (
	Prios      = []string{"P1", "P2", "P3", "P4"}
	fixStates  = []string{finding.FixAvailable, finding.FixReboot, finding.FixVendor} // a package takes the most actionable one
	kernelPkgs = []string{"kernel", "kernel-core", "kernel-uek"}
)

// Key is the identity of a finding across runs. For vulnerabilities the target (os / image / path) is part of
// it; for configuration / exposure / health findings the target is human text, so it is not.
type Key [5]string

func KeyOf(f *finding.Finding) Key {
	if f.Kind == finding.Vuln {
		return Key{f.Host, f.Module, f.Target, f.Pkg, f.ID}
	}
	return Key{f.Host, f.Module, f.ID, f.Pkg, pyPort(f)}
}

// pyPort is str(args.get("port", "")) as Python wrote it into keys.
func pyPort(f *finding.Finding) string {
	v, ok := f.Args["port"]
	if !ok {
		return ""
	}
	return pyfmt.Str(v)
}

// Counts: findings per priority; accepted and backported ones are counted apart (and not per priority).
type Counts struct {
	P1         int `json:"P1"`
	P2         int `json:"P2"`
	P3         int `json:"P3"`
	P4         int `json:"P4"`
	Accepted   int `json:"accepted"`
	Backported int `json:"backported"`
}

// Map: the counts as meta.counts stores them.
func (c Counts) Map() map[string]int {
	return map[string]int{"P1": c.P1, "P2": c.P2, "P3": c.P3, "P4": c.P4, "accepted": c.Accepted, "backported": c.Backported}
}

func CountsOf(findings []finding.Finding) Counts {
	var c Counts
	for i := range findings {
		f := &findings[i]
		switch {
		case f.Backported: // the installed build already has the fix (package changelog)
			c.Backported++
		case f.Accepted:
			c.Accepted++
		default:
			switch f.PriorityOr() { // Python: priority in c (whose keys include accepted/backported)
			case "P1":
				c.P1++
			case "P2":
				c.P2++
			case "P3":
				c.P3++
			case "P4":
				c.P4++
			case "accepted":
				c.Accepted++
			case "backported":
				c.Backported++
			}
		}
	}
	return c
}

func prioRank(p string) int {
	if i := slices.Index(Prios, p); i >= 0 {
		return i
	}
	return len(Prios)
}

func rankPtr(p *string) int {
	if p == nil {
		return len(Prios)
	}
	return prioRank(*p)
}

// Group is one package update on one host: every CVE of (host, target, pkg).
type Group struct {
	Host, Target, Pkg, Installed string
	Fixed                        map[string]bool // versions that fix one of the CVEs
	CVEs                         map[string]bool
	Priority, Due                *string
	KEV                          bool
	Unfixed                      int // CVEs without a fixed version
	PreauthRCE, Preauth          int
	Inactive, Kernel, Pending    bool
	Module                       string
	FixState, RepoVersion        *string
}

// HostPlan: one host's package updates, most urgent first.
type HostPlan struct {
	Host   string
	Groups []*Group
}

// Plan keeps the hosts in the order their first package appeared (Python's dict order): the view's plan rows and
// the summary's tie-breaks depend on it.
type Plan []HostPlan

func (p Plan) Get(host string) []*Group {
	for _, h := range p {
		if h.Host == host {
			return h.Groups
		}
	}
	return nil
}

// PatchPlan: host -> list of package updates, most urgent first.
func PatchPlan(findings []finding.Finding) Plan {
	type gk struct{ host, target, pkg string }
	idx := map[gk]*Group{}
	var order []*Group
	for i := range findings {
		f := &findings[i]
		if f.Kind != finding.Vuln || f.Accepted || f.Backported {
			continue
		}
		k := gk{f.Host, f.Target, f.Pkg}
		g := idx[k]
		if g == nil {
			g = &Group{Host: f.Host, Target: f.Target, Pkg: f.Pkg, Installed: f.Installed, Fixed: map[string]bool{},
				CVEs: map[string]bool{}}
			idx[k] = g
			order = append(order, g)
		}
		g.CVEs[f.ID] = true
		if f.Fixed != "" {
			g.Fixed[f.Fixed] = true
		} else {
			g.Unfixed++
		}
		g.KEV = g.KEV || f.KEV
		if f.Preauth && f.RCE {
			g.PreauthRCE++
		}
		if f.Preauth {
			g.Preauth++
		}
		g.Inactive = f.Inactive
		g.Kernel = g.Kernel || f.Kernel
		g.Module = f.Module
		g.Pending = g.Pending || f.Pending
		if st := slices.Index(fixStates, f.FixState); st >= 0 && (g.FixState == nil || st < slices.Index(fixStates, *g.FixState)) {
			g.FixState = ptr(f.FixState)
		}
		if f.RepoVersion != "" {
			g.RepoVersion = ptr(f.RepoVersion)
		}
		if prioRank(f.PriorityOr()) < rankPtr(g.Priority) {
			g.Priority = f.Priority
		}
		if f.DueOr() != "" && (g.Due == nil || f.DueOr() < *g.Due) {
			g.Due = f.Due
		}
	}
	var plan Plan
	at := map[string]int{}
	for _, g := range order {
		i, ok := at[g.Host]
		if !ok {
			i = len(plan)
			at[g.Host] = i
			plan = append(plan, HostPlan{Host: g.Host})
		}
		plan[i].Groups = append(plan[i].Groups, g)
	}
	for _, h := range plan {
		slices.SortStableFunc(h.Groups, func(a, b *Group) int {
			return cmp.Or(cmp.Compare(rankPtr(a.Priority), rankPtr(b.Priority)), cmp.Compare(len(b.CVEs), len(a.CVEs)),
				cmp.Compare(a.Pkg, b.Pkg))
		})
	}
	return plan
}

// PlanCounts: packages to update per priority (the unit of work), plus CVE totals.
type PlanCounts struct {
	P1   int `json:"P1"`
	P2   int `json:"P2"`
	P3   int `json:"P3"`
	P4   int `json:"P4"`
	CVEs int `json:"cves"`
}

func PlanCountsOf(plan Plan) PlanCounts {
	var c PlanCounts
	for _, h := range plan {
		for _, g := range h.Groups {
			switch deref(g.Priority) {
			case "P1":
				c.P1++
			case "P2":
				c.P2++
			case "P3":
				c.P3++
			case "P4":
				c.P4++
			case "cves": // Python: priority in c
				c.CVEs++
			}
			c.CVEs += len(g.CVEs)
		}
	}
	return c
}

var vkeyRe = regexp.MustCompile(`(\d+)`)

// vkeyCompare is Python's natural sort key for versions (1.10 > 1.9): digit runs compare as numbers and before
// text runs, text runs by code point.
func vkeyCompare(a, b string) int {
	ka, kb := vkey(a), vkey(b)
	for i := 0; i < len(ka) && i < len(kb); i++ {
		x, y := ka[i], kb[i]
		if x.num != y.num {
			if x.num {
				return -1
			}
			return 1
		}
		var c int
		if x.num {
			c = cmpDigits(x.s, y.s)
		} else {
			c = strings.Compare(x.s, y.s)
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(ka), len(kb))
}

type vtok struct {
	num bool
	s   string
}

func vkey(v string) []vtok {
	var out []vtok
	last := 0
	for _, m := range vkeyRe.FindAllStringIndex(v, -1) {
		if m[0] > last {
			out = append(out, vtok{false, v[last:m[0]]})
		}
		out = append(out, vtok{true, v[m[0]:m[1]]})
		last = m[1]
	}
	if last < len(v) {
		out = append(out, vtok{false, v[last:]})
	}
	return out
}

// cmpDigits compares digit strings as integers of any length (int("0012") == 12).
func cmpDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	return cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(a, b))
}

func sortedVersions(set map[string]bool) []string {
	out := keys(set)
	slices.Sort(out) // fixes the order of _vkey ties ("01" vs "1"), which Python leaves to set order
	slices.SortStableFunc(out, vkeyCompare)
	return out
}

var repoState = map[string]string{"available": "update to", "reboot": "installed, reboot into", "vendor": "no fix yet"}

// WriteSummary writes summary.md: the run in a form to read in a terminal or paste into a ticket.
func WriteSummary(runDir string, meta *Meta, findings []finding.Finding) error {
	return os.WriteFile(filepath.Join(runDir, "summary.md"), []byte(Summary(meta, findings)), 0o644)
}

func Summary(meta *Meta, findings []finding.Finding) string {
	tot := TotalsOf(findings)
	plan := PatchPlan(findings)
	trivy := "?"
	if meta.TrivyVersion != nil {
		trivy = *meta.TrivyVersion
	}
	feeds := deref(meta.FeedsUpdated)
	if feeds == "" {
		feeds = "none (kanareika db update)"
	}
	lines := []string{
		fmt.Sprintf("# %s / %s — scan %s", meta.Org, meta.Env, meta.RunID),
		"",
		fmt.Sprintf("- Hosts: %d ok, %d failed", meta.HostsOK, meta.HostsFailed.Len()),
		fmt.Sprintf("- Modules: %s", strings.Join(meta.Modules, ", ")),
		fmt.Sprintf("- Trivy %s, KEV/EPSS as of %s", trivy, feeds),
		"",
		"| | P1 | P2 | P3 | P4 | total |",
		"|---|---:|---:|---:|---:|---:|",
		fmt.Sprintf("| fixes to apply | %d | %d | %d | %d | %d |", tot.P1, tot.P2, tot.P3, tot.P4, tot.Fixes),
		"",
		"- " + tot.Line(),
		"- A fix is one change: one package update on every host that needs it, one image to rebuild, one setting to change.",
		fmt.Sprintf("- Not counted: %d accepted risks; %d already fixed in the installed build (CVE in the package changelog).",
			tot.Accepted, tot.Backported),
		"",
	}
	if meta.HostsFailed.Len() > 0 {
		lines = append(lines, "## Errors", "")
		for _, h := range meta.HostsFailed.Keys {
			lines = append(lines, fmt.Sprintf("- **%s**: %s", h, meta.HostsFailed.M[h]))
		}
		lines = append(lines, "")
	}
	for _, h := range meta.ModuleErrors.Keys {
		for _, e := range meta.ModuleErrors.M[h] {
			lines = append(lines, fmt.Sprintf("- %s: %s", h, e))
		}
	}
	if meta.ModuleErrors.Len() > 0 {
		lines = append(lines, "")
	}

	lines = append(lines, "## Update plan", "")
	if len(plan) == 0 {
		lines = append(lines, "No vulnerable packages found.", "")
	}
	hosts := slices.Clone(plan)
	minRank := func(h HostPlan) int {
		m := len(Prios)
		for _, g := range h.Groups {
			m = min(m, rankPtr(g.Priority))
		}
		return m
	}
	slices.SortStableFunc(hosts, func(a, b HostPlan) int { return cmp.Compare(minRank(a), minRank(b)) })
	for _, h := range hosts {
		lines = append(lines, "### "+h.Host, "", "| prio | due | package | where | installed | fixed in | repositories | CVE | KEV |",
			"|---|---|---|---|---|---|---|---:|---|")
		for _, g := range h.Groups {
			fixed := "no fix"
			if fv := sortedVersions(g.Fixed); len(fv) > 0 {
				fixed = fv[len(fv)-1]
			}
			repo := repoState[deref(g.FixState)]
			if deref(g.FixState) == finding.FixVendor && finding.IsESM(fixed) {
				repo = "only in Ubuntu Pro (ESM)"
			}
			if deref(g.RepoVersion) != "" {
				repo += " " + *g.RepoVersion
			}
			lines = append(lines, fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %d | %s |", orDash(g.Priority),
				orDash(g.Due), g.Pkg, g.Target, g.Installed, fixed, repo, len(g.CVEs), yes(g.KEV)))
		}
		lines = append(lines, "")
	}

	other := otherFindings(findings)
	if len(other) > 0 {
		lines = append(lines, "## Configuration, exposure, health", "", "| prio | host | id | what | details |", "|---|---|---|---|---|")
		sorted := slices.Clone(other)
		slices.SortStableFunc(sorted, func(a, b *finding.Finding) int {
			return cmp.Or(cmp.Compare(prioRank(a.PriorityOr()), prioRank(b.PriorityOr())), cmp.Compare(a.Host, b.Host))
		})
		for _, f := range sorted {
			lines = append(lines, fmt.Sprintf("| %s | %s | %s | %s | %s |", orDash(f.Priority), f.Host, f.ID, f.Title, f.Target))
		}
		lines = append(lines, "")
	}

	var accepted []*finding.Finding
	for i := range findings {
		if findings[i].Exception != nil {
			accepted = append(accepted, &findings[i])
		}
	}
	if len(accepted) > 0 {
		lines = append(lines, "## Exceptions", "", "| host | id | package | until | status | reason |", "|---|---|---|---|---|---|")
		for _, f := range accepted {
			ex := f.Exception
			status := "accepted"
			if ex.FixAvailable {
				status = "fix arrived in the repositories — back in the plan"
			} else if ex.Expired {
				status = "EXPIRED — back in the plan"
			}
			lines = append(lines, fmt.Sprintf("| %s | %s | %s | %s | %s | %s |", f.Host, f.ID, f.Pkg, ex.ReviewBy, status, ex.Reason))
		}
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

// otherFindings: configuration / exposure / health findings that still need doing.
func otherFindings(findings []finding.Finding) []*finding.Finding {
	var out []*finding.Finding
	for i := range findings {
		f := &findings[i]
		if (f.Kind == finding.Misconfig || f.Kind == finding.Exposure || f.Kind == finding.Health) && !f.Accepted {
			out = append(out, f)
		}
	}
	return out
}

// --- small helpers -----------------------------------------------------------------------------------------------

func ptr[T any](v T) *T { return &v }

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func orDash(p *string) string {
	if deref(p) == "" {
		return "-"
	}
	return *p
}

// pyOpt is str() of an optional value as Python formats it into texts.
func pyOpt(p *string) string {
	if p == nil {
		return "None"
	}
	return *p
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return ""
}

func keys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func sortedKeys(set map[string]bool) []string {
	out := keys(set)
	slices.Sort(out)
	return out
}

func itoa(i int) string { return strconv.Itoa(i) }
