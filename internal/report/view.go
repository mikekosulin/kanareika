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

// BuildView aggregates one run for the dashboard from findings in memory. runDir holds hosts/<h>/*.json; prev
// (may be nil) is the run "new" / "resolved" are computed against. A run on disk: BuildViewDir, which never holds
// its findings.
func BuildView(runDir string, meta *Meta, findings []finding.Finding, prev *Prev) *View {
	a := newViewAcc()
	for i := range findings {
		a.add(&findings[i])
	}
	a.flushHost()
	var d *diffAcc
	if prev != nil {
		both := hostsInBoth(meta, prev.Meta)
		for _, fs := range [][]finding.Finding{findings, prev.Findings} { // org-level checks: always comparable
			for i := range fs {
				if strings.Contains(fs[i].Host, ":") {
					both[fs[i].Host] = true
				}
			}
		}
		newF, gone := Diff(prev.Findings, findings, both)
		d = &diffAcc{prevID: prev.ID, newN: len(newF), goneN: len(gone), newRows: diffRows(newF), goneRows: diffRows(gone)}
	}
	return a.view(runDir, meta, d)
}

// accessView: hosts/<h>/access.json of every host, long tails cut (they stay in the files).
func accessView(runDir string, hosts []string) map[string]any {
	access := hostJSON(runDir, hosts, "access.json")
	for _, v := range access {
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
	return access
}

// exposureView: hosts/<h>/exposure.json of every host without the raw firewall dump.
func exposureView(runDir string, hosts []string) map[string]any {
	exposure := hostJSON(runDir, hosts, "exposure.json")
	for _, v := range exposure {
		if e, _ := v.(map[string]any); e != nil {
			delete(e, "firewall_raw")
		}
	}
	return exposure
}

// Diff: findings new in b and resolved since a, restricted to hosts (nil: all) scanned successfully in both.
// Accepted, backported and inventory findings are not "to do", so they count as absent.
func Diff(a, b []finding.Finding, hosts map[string]bool) (newF, gone []finding.Finding) {
	active := func(fs []finding.Finding) map[Key]*finding.Finding {
		m := map[Key]*finding.Finding{}
		for i := range fs {
			if f := &fs[i]; diffable(f, hosts) {
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
	sortDiff(newF)
	sortDiff(gone)
	return newF, gone
}

// diffable: a finding Diff compares (hosts nil: on any host).
func diffable(f *finding.Finding, hosts map[string]bool) bool {
	return f.Kind != finding.Inventory && !f.Accepted && !f.Backported && (hosts == nil || hosts[f.Host])
}

// sortDiff orders Diff's lists. Python orders ties of (priority, host, pkg, id) by set order (random); the full key
// makes it deterministic.
func sortDiff(fs []finding.Finding) {
	slices.SortFunc(fs, func(x, y finding.Finding) int {
		kx, ky := KeyOf(&x), KeyOf(&y)
		return cmp.Or(cmp.Compare(prioRank(x.PriorityOr()), prioRank(y.PriorityOr())), cmp.Compare(x.Host, y.Host),
			cmp.Compare(x.Pkg, y.Pkg), cmp.Compare(x.ID, y.ID), slices.Compare(kx[:], ky[:]))
	})
}

// hostsInBoth: the hosts scanned successfully in both runs.
func hostsInBoth(a, b *Meta) map[string]bool {
	ok := func(m *Meta) map[string]bool {
		s := map[string]bool{}
		for _, h := range m.HostsScanned {
			if !m.HostsFailed.Has(h) {
				s[h] = true
			}
		}
		return s
	}
	sa, sb := ok(a), ok(b)
	both := map[string]bool{}
	for h := range sa {
		if sb[h] {
			both[h] = true
		}
	}
	return both
}

// BuildViewDir: the view of dir (a run or current/) described by meta, compared with the run in prevDir ("":
// none), read one host at a time: what is held is one host's findings' groups and keys, never the run's.
func BuildViewDir(dir string, meta *Meta, prevDir string) (*View, error) {
	v, _, err := buildViewDir(dir, meta, prevDir)
	return v, err
}

func buildViewDir(dir string, meta *Meta, prevDir string) (*View, *viewAcc, error) {
	hosts, err := fileHosts(dir)
	if err != nil {
		return nil, nil, err
	}
	var d *diffAcc
	var both map[string]bool
	if prevDir != "" {
		pm, err := LoadMeta(prevDir)
		if err != nil {
			return nil, nil, err
		}
		both = hostsInBoth(meta, pm)
		both[OrgHost] = true // org-level checks: always comparable
		d = &diffAcc{prevID: filepath.Base(prevDir)}
		ph, err := fileHosts(prevDir)
		if err != nil {
			return nil, nil, err
		}
		for _, h := range ph { // hosts with nothing left: all of it is resolved
			if both[h] && !slices.Contains(hosts, h) {
				hosts = append(hosts, h)
			}
		}
		slices.Sort(hosts)
	}
	a := newViewAcc()
	if legacy := legacyFile(dir); legacy != "" {
		// a run written before 0.6: added in the file's order (a merged action takes its first finding's words, as
		// it always did), the comparison a host at a time
		if err := EachFindingIn(legacy, a.add); err != nil {
			return nil, nil, err
		}
		a.flushHost()
		if d != nil {
			for _, h := range hosts {
				if !both[h] {
					continue
				}
				if err := d.startHost(prevDir, h); err != nil {
					return nil, nil, err
				}
				if err := eachHostFinding(dir, h, d.cur); err != nil {
					return nil, nil, err
				}
				if err := d.endHost(); err != nil {
					return nil, nil, err
				}
			}
		}
		return a.view(dir, meta, d), a, nil
	}
	for _, h := range hosts {
		compare := d != nil && both[h]
		if compare {
			if err := d.startHost(prevDir, h); err != nil {
				return nil, nil, err
			}
		}
		err := eachHostFinding(dir, h, func(f *finding.Finding) {
			a.add(f)
			if compare {
				d.cur(f)
			}
		})
		if err != nil {
			return nil, nil, err
		}
		if compare {
			if err := d.endHost(); err != nil {
				return nil, nil, err
			}
		}
		a.flushHost()
	}
	return a.view(dir, meta, d), a, nil
}

// fileHosts: the hosts dir has findings of, sorted (a run written before 0.6: read to find them).
func fileHosts(dir string) ([]string, error) {
	hfs, err := HostFiles(dir)
	if err != nil {
		return nil, err
	}
	if len(hfs) == 1 && hfs[0].Host == "" {
		set := map[string]bool{}
		if err := EachFindingIn(hfs[0].Path, func(f *finding.Finding) { set[FileHost(f)] = true }); err != nil {
			return nil, err
		}
		return sortedKeys(set), nil
	}
	out := make([]string, len(hfs))
	for i, hf := range hfs {
		out[i] = hf.Host
	}
	return out, nil
}
