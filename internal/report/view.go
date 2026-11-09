package report

import (
	"bytes"
	"cmp"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// ViewVersion: bump when BuildView / BuildActions change; stored views older than this get rebuilt, newer ones
// (written by newer code) are left alone.
const ViewVersion = 11

// View is everything the dashboard shows for one run, pre-aggregated (KBs instead of the raw findings). It is
// written to view.json; the per-host files (health, access, exposure) are passed through as decoded JSON.
type View struct {
	Version    int                    `json:"version"`
	Meta       *Meta                  `json:"meta"`
	Counts     Counts                 `json:"counts"`      // finding rows per priority (internal; Totals is what to show)
	PlanCounts PlanCounts             `json:"plan_counts"` // package updates per host and priority (the classic plan table)
	Totals     Totals                 `json:"totals"`      // fixes to apply and unique CVEs: the numbers every interface shows
	Hosts      map[string]*HostCounts `json:"hosts"`
	Facts      map[string]Fact        `json:"facts"`
	Actions    []Action               `json:"actions"`
	Health     map[string]any         `json:"health"`
	Access     map[string]any         `json:"access"`
	Exposure   map[string]any         `json:"exposure"`
	Plan       []PlanRow              `json:"plan"`
	Other      []map[string]any       `json:"other"`
	Exceptions []map[string]any       `json:"exceptions"`
	Inventory  []map[string]any       `json:"inventory"`
	Backported []BackportedRow        `json:"backported"`
	Prev       *string                `json:"prev"` // the run "new" / "resolved" compare with
	New        *DiffSet               `json:"new,omitempty"`
	Resolved   *DiffSet               `json:"resolved,omitempty"`
}

// HostCounts: things to do on a host per priority (packages + other findings) and its CVE total.
type HostCounts struct {
	P1   int `json:"P1"`
	P2   int `json:"P2"`
	P3   int `json:"P3"`
	P4   int `json:"P4"`
	CVEs int `json:"cves"`
}

func (h *HostCounts) add(p string) {
	switch p {
	case "P1":
		h.P1++
	case "P2":
		h.P2++
	case "P3":
		h.P3++
	case "P4":
		h.P4++
	}
}

type DiffSet struct {
	Total int       `json:"total"`
	Rows  []DiffRow `json:"rows"`
}

// DiffRow: a diff aggregated by package, so a kernel with 15k CVEs is one row, not 15k.
type DiffRow struct {
	Host     string   `json:"host"`
	Target   string   `json:"target"`
	Pkg      string   `json:"pkg"` // the finding id when there is no package
	Kind     string   `json:"kind"`
	IDs      []string `json:"ids"` // the first 8, newest first
	Priority *string  `json:"priority"`
	KEV      bool     `json:"kev"`
	Title    string   `json:"title"`
	RCE      int      `json:"rce"`
	Count    int      `json:"count"`
}

// BackportedRow: CVEs the scanner matched by version that the installed build already fixes (package changelog).
type BackportedRow struct {
	Host      string   `json:"host"`
	Pkg       string   `json:"pkg"`
	Installed string   `json:"installed"`
	IDs       []string `json:"ids"`
	CVEs      int      `json:"cves"`
}

// Prev is the run a view is compared with.
type Prev struct {
	ID       string
	Meta     *Meta
	Findings []finding.Finding
}

// slim: the fields of a finding the view lists, without empty ones (Python drops None, "", False and 0).
func slim(f *finding.Finding) map[string]any {
	m := map[string]any{}
	str := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	str("host", f.Host)
	str("group", f.Group)
	if f.Exposure != 0 {
		m["exposure"] = f.Exposure
	}
	str("module", f.Module)
	str("kind", f.Kind)
	str("id", f.ID)
	str("pkg", f.Pkg)
	str("installed", f.Installed)
	str("fixed", f.Fixed)
	str("severity", f.Severity)
	str("title", f.Title)
	str("msg", f.Msg) // the title's message key and arguments: the interfaces render it in their language
	if len(f.Args) > 0 {
		m["args"] = f.Args
	}
	str("url", f.URL)
	str("target", f.Target)
	str("priority", f.PriorityOr())
	str("due", f.DueOr())
	if f.KEV {
		m["kev"] = true
	}
	if f.EPSS != nil && *f.EPSS != 0 {
		m["epss"] = *f.EPSS
	}
	if f.Accepted {
		m["accepted"] = true
	}
	if f.Exception != nil {
		m["exception"] = f.Exception
	}
	return m
}

// hostJSON reads hosts/<h>/<name> of every host; missing or broken files are left out.
func hostJSON(runDir string, hosts []string, name string) map[string]any {
	out := map[string]any{}
	for _, h := range hosts {
		if v, err := readAny(filepath.Join(runDir, "hosts", h, name)); err == nil {
			out[h] = v
		}
	}
	return out
}

// readAny decodes JSON keeping numbers as written (json.Number), so passed-through files keep big integers.
func readAny(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func diffRows(items []finding.Finding) []DiffRow {
	type gk struct{ host, target, pkg string }
	idx := map[gk]int{}
	rows := []DiffRow{}
	for i := range items {
		f := &items[i]
		pkg := f.Pkg
		if pkg == "" {
			pkg = f.ID
		}
		k := gk{f.Host, f.Target, pkg}
		j, ok := idx[k]
		if !ok {
			j = len(rows)
			idx[k] = j
			rows = append(rows, DiffRow{Host: f.Host, Target: f.Target, Pkg: pkg, Kind: f.Kind, Title: f.Title})
		}
		g := &rows[j]
		g.IDs = append(g.IDs, f.ID)
		g.KEV = g.KEV || f.KEV
		if f.Preauth && f.RCE {
			g.RCE++
		}
		if prioRank(f.PriorityOr()) < rankPtr(g.Priority) {
			g.Priority = f.Priority
		}
	}
	slices.SortStableFunc(rows, func(a, b DiffRow) int {
		return cmp.Or(cmp.Compare(rankPtr(a.Priority), rankPtr(b.Priority)), cmp.Compare(len(b.IDs), len(a.IDs)),
			cmp.Compare(a.Host, b.Host), cmp.Compare(a.Pkg, b.Pkg))
	})
	for i := range rows {
		g := &rows[i]
		g.Count = len(g.IDs)
		slices.Sort(g.IDs)
		slices.Reverse(g.IDs)
		g.IDs = g.IDs[:min(8, len(g.IDs))]
	}
	return rows
}

func backported(findings []finding.Finding) []BackportedRow {
	type gk struct{ host, pkg string }
	idx := map[gk]int{}
	var rows []BackportedRow
	var ids []map[string]bool
	for i := range findings {
		f := &findings[i]
		if !f.Backported {
			continue
		}
		k := gk{f.Host, f.Pkg}
		j, ok := idx[k]
		if !ok {
			j = len(rows)
			idx[k] = j
			rows = append(rows, BackportedRow{Host: f.Host, Pkg: f.Pkg, Installed: f.Installed})
			ids = append(ids, map[string]bool{})
		}
		ids[j][f.ID] = true
	}
	for j := range rows {
		s := sortedKeys(ids[j])
		slices.Reverse(s)
		rows[j].CVEs = len(s)
		rows[j].IDs = s[:min(8, len(s))]
	}
	slices.SortStableFunc(rows, func(a, b BackportedRow) int {
		return cmp.Or(cmp.Compare(a.Host, b.Host), cmp.Compare(b.CVEs, a.CVEs), cmp.Compare(a.Pkg, b.Pkg))
	})
	if rows == nil {
		rows = []BackportedRow{}
	}
	return rows
}

func facts(runDir string, hosts []string) map[string]Fact {
	out := map[string]Fact{}
	for _, h := range hosts {
		v, err := readAny(filepath.Join(runDir, "hosts", h, "facts.json"))
		fj, _ := v.(map[string]any)
		if err != nil || fj == nil {
			continue
		}
		osr, ok := fj["os_release"].(map[string]any)
		if !ok {
			continue
		}
		f := Fact{Kernel: []string{}}
		if s, ok := osr["PRETTY_NAME"].(string); ok {
			f.OS = &s
		}
		if u, _ := fj["uname"].(string); len(strings.Fields(u)) > 1 {
			f.Kernel = []string{strings.Fields(u)[1]}
		}
		out[h] = f
	}
	return out
}

func limit[T any](s []T, n int) []T {
	if s == nil {
		return []T{}
	}
	return s[:min(n, len(s))]
}

// BuildView aggregates one run for the dashboard. runDir holds hosts/<h>/*.json; prev (may be nil) is the run
// "new" / "resolved" are computed against.
func BuildView(runDir string, meta *Meta, findings []finding.Finding, prev *Prev) *View {
	plan := PatchPlan(findings)
	hosts := map[string]*HostCounts{}
	hc := func(h string) *HostCounts {
		if hosts[h] == nil {
			hosts[h] = &HostCounts{}
		}
		return hosts[h]
	}
	for _, h := range plan {
		for _, g := range h.Groups {
			c := hc(h.Host)
			c.add(deref(g.Priority))
			c.CVEs += len(g.CVEs)
		}
	}
	other := otherFindings(findings)
	for _, f := range other {
		if slices.Contains(Prios, f.PriorityOr()) {
			hc(f.Host).add(f.PriorityOr())
		}
	}
	fc := facts(runDir, meta.HostsScanned)
	rows := PlanRows(plan)
	access := hostJSON(runDir, meta.HostsScanned, "access.json")
	for _, v := range access { // keep the view small: long tails stay in hosts/<h>/access.json
		a, _ := v.(map[string]any)
		if a == nil {
			continue
		}
		if l, _ := a["logins"].(map[string]any); l != nil {
			if acc, ok := l["accepted"].([]any); ok {
				l["accepted"] = acc[:min(200, len(acc))]
			}
			att, ok := l["attackers"].([]any)
			if _, present := l["attackers"]; !present {
				att, ok = []any{}, true
			}
			if ok {
				l["attackers"] = att[:min(100, len(att))]
			}
		}
		delete(a, "last")
	}
	exposure := hostJSON(runDir, meta.HostsScanned, "exposure.json")
	for _, v := range exposure {
		if e, _ := v.(map[string]any); e != nil {
			delete(e, "firewall_raw")
		}
	}
	slims := func(keep func(*finding.Finding) bool) []map[string]any {
		out := []map[string]any{}
		for i := range findings {
			if keep(&findings[i]) {
				out = append(out, slim(&findings[i]))
			}
		}
		return out
	}
	otherSlim := []map[string]any{}
	for _, f := range other {
		otherSlim = append(otherSlim, slim(f))
	}
	v := &View{
		Version: ViewVersion, Meta: meta, Counts: CountsOf(findings), PlanCounts: PlanCountsOf(plan), Totals: TotalsOf(findings),
		Hosts: hosts, Facts: fc, Actions: BuildActions(rows, other, fc),
		Health: hostJSON(runDir, meta.HostsScanned, "health.json"), Access: access, Exposure: exposure,
		Plan:       rows,
		Other:      limit(otherSlim, 5000),
		Exceptions: limit(slims(func(f *finding.Finding) bool { return f.Exception != nil }), 5000),
		Inventory:  limit(slims(func(f *finding.Finding) bool { return f.Kind == finding.Inventory }), 5000),
		Backported: limit(backported(findings), 3000),
	}
	if prev != nil {
		ok := func(m *Meta) map[string]bool {
			s := map[string]bool{}
			for _, h := range m.HostsScanned {
				if !m.HostsFailed.Has(h) {
					s[h] = true
				}
			}
			return s
		}
		a, b := ok(meta), ok(prev.Meta)
		both := map[string]bool{}
		for h := range a {
			if b[h] {
				both[h] = true
			}
		}
		for _, fs := range [][]finding.Finding{findings, prev.Findings} { // org-level checks: always comparable
			for i := range fs {
				if strings.Contains(fs[i].Host, ":") {
					both[fs[i].Host] = true
				}
			}
		}
		newF, gone := Diff(prev.Findings, findings, both)
		v.Prev = &prev.ID
		v.New = &DiffSet{Total: len(newF), Rows: limit(diffRows(newF), 3000)}
		v.Resolved = &DiffSet{Total: len(gone), Rows: limit(diffRows(gone), 3000)}
	}
	return v
}

// Diff: findings new in b and resolved since a, restricted to hosts (nil: all) scanned successfully in both.
// Accepted, backported and inventory findings are not "to do", so they count as absent.
func Diff(a, b []finding.Finding, hosts map[string]bool) (newF, gone []finding.Finding) {
	active := func(fs []finding.Finding) map[Key]*finding.Finding {
		m := map[Key]*finding.Finding{}
		for i := range fs {
			f := &fs[i]
			if f.Kind != finding.Inventory && !f.Accepted && !f.Backported && (hosts == nil || hosts[f.Host]) {
				m[KeyOf(f)] = f // the last one wins, as in a dict comprehension
			}
		}
		return m
	}
	ka, kb := active(a), active(b)
	newF, gone = []finding.Finding{}, []finding.Finding{}
	for k, f := range kb {
		if ka[k] == nil {
			newF = append(newF, *f)
		}
	}
	for k, f := range ka {
		if kb[k] == nil {
			gone = append(gone, *f)
		}
	}
	// Python orders ties of (priority, host, pkg, id) by set order (random); the full key makes it deterministic
	order := func(x, y finding.Finding) int {
		kx, ky := KeyOf(&x), KeyOf(&y)
		return cmp.Or(cmp.Compare(prioRank(x.PriorityOr()), prioRank(y.PriorityOr())), cmp.Compare(x.Host, y.Host),
			cmp.Compare(x.Pkg, y.Pkg), cmp.Compare(x.ID, y.ID), slices.Compare(kx[:], ky[:]))
	}
	slices.SortFunc(newF, order)
	slices.SortFunc(gone, order)
	return newF, gone
}
