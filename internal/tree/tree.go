// Package tree groups an environment's findings into what to do: by fix (one package update on many hosts, one
// image to rebuild), by CVE, or by host. The web page, the TUI and MCP draw the same nodes, so they can't drift
// apart. Nodes carry aggregates (priority, earliest due date, hosts, CVEs, EPSS, flags, fix states); Detail adds
// what a details pane shows.
package tree

import (
	"cmp"
	"iter"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/fset"
	"github.com/mikekosulin/kanareika/internal/report"
)

// Groupings.
const (
	ByFix  = "fix"
	ByCVE  = "cve"
	ByHost = "host"
)

// Node kinds.
const (
	KindPkg      = report.FixPkg   // an OS package update: pkg installed -> fixed, on hosts
	KindImage    = report.FixImage // an image to rebuild (docker, or a k8s workload's)
	KindPart     = "part"          // a component inside an image (a library, a package of the base image)
	KindWhere    = "where"         // where an image runs: a container name on hosts, a k8s workload
	KindCVE      = "cve"           // one vulnerability
	KindGroup    = "group"         // a host group
	KindHost     = "host"          // one host
	KindOther    = report.FixOther // a misconfiguration, an exposure, a health problem
	KindSection  = "section"       // a heading inside a node: "components", "runs on", "OS packages"
	minGroupSize = 7               // fewer hosts than this are listed, more are grouped by host group
)

// Filters (Opts.Filters).
const (
	FKEV     = "kev"     // in CISA KEV
	FRCE     = "rce"     // remote code execution without logging in
	FEPSS    = "epss"    // EPSS >= 10%
	FFront   = "front"   // on internet-facing hosts (exposure 1)
	FReady   = "ready"   // an installable fix exists
	FNoFix   = "nofix"   // no fix in the repositories yet
	FOverdue = "overdue" // due before today
)

type Opts struct {
	By         string   // fix (default), cve, host
	Filters    []string // all must match
	Query      string   // substring of host, group, package, CVE id, title
	Backported bool     // include findings the package changelog says are fixed
	Today      string   // YYYY-MM-DD, for "overdue"
	// All: with By host, every host of the env (Inventory, from Servers) as a flat list of host rows, also the
	// clean, failed and not scanned ones; the filters and the query then narrow what is under the rows.
	All       bool
	Inventory []HostInfo
}

// Count: how many hosts of a group.
type Count struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

type Node struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"` // package, image, CVE id, group, host, title, or section heading

	// what it is
	Installed string   `json:"installed,omitempty"`
	Fixed     string   `json:"fixed,omitempty"`   // a package update: the highest fixed version of its CVEs
	Pkgs      []string `json:"pkgs,omitempty"`    // a source package update: its binary packages (libssl3, openssl)
	Parts     []string `json:"parts,omitempty"`   // an image: the names of the components to update in it, most urgent first
	Path      string   `json:"path,omitempty"`    // a library's file in the image
	Runtime   string   `json:"runtime,omitempty"` // image / where: docker, k8s
	Title     string   `json:"title,omitempty"`   // CVE: the advisory's title; other: what it is
	Severity  string   `json:"severity,omitempty"`
	OS        string   `json:"os,omitempty"` // host, group: the OS; a package update: the OS releases, when two top rows share the package name
	Exposure  int      `json:"exposure,omitempty"`

	// aggregates over everything under the node
	Priority string         `json:"priority"`
	Due      string         `json:"due,omitempty"`
	DueWhy   string         `json:"due_why,omitempty"`
	Hosts    int            `json:"hosts"`
	Groups   []Count        `json:"groups,omitempty"` // host groups, largest first
	HostList []string       `json:"host_list,omitempty"`
	CVEs     int            `json:"cves"`
	EPSS     float64        `json:"epss"`
	KEV      bool           `json:"kev,omitempty"`
	RCE      bool           `json:"rce,omitempty"`
	Preauth  bool           `json:"preauth,omitempty"`
	States   map[string]int `json:"states,omitempty"` // hosts per fix state: available, reboot, vendor, backported, other
	NoFix    map[string]int `json:"no_fix,omitempty"` // of the vendor hosts, why there is nothing to install (finding.NoFix*)

	// host rows of the server view (Opts.All)
	State       string         `json:"state,omitempty"`        // todo, clean, partial, failed, not_scanned
	Problem     string         `json:"problem,omitempty"`      // failed / not scanned / partial: why, in plain words (English)
	ProblemMsg  string         `json:"problem_msg,omitempty"`  // ... its message key and args, to render in other languages
	ProblemArgs map[string]any `json:"problem_args,omitempty"` //
	LastScan    string         `json:"last_scan,omitempty"`    // when its data was collected (RFC 3339, UTC)
	OSShort     string         `json:"os_short,omitempty"`     // the OS as short as tells releases apart (Ubuntu 22.04)
	Fixes       int            `json:"fixes,omitempty"`        // fixes to apply on the host (all its findings, unfiltered)
	Counts      map[string]int `json:"counts,omitempty"`       // ... per priority
	Overdue     bool           `json:"overdue,omitempty"`      // its earliest due date has passed

	Kids []*Node `json:"kids,omitempty"`
	More int     `json:"more,omitempty"` // kids left out of this answer (Shallow): ask for them with the node's id
	fs   []*item
	lz   *lazy        // kids made on first use (BuildSet); Kids is then empty and never written
	full func() *Node // a top row (BuildSet): itself made again with its findings and kids, once
}

// lazy: a node's kids, made when first asked for. A built tree is cached and read by many requests at once, so the
// kids are made once (once) and kept here, never written into the shared node.
type lazy struct {
	once sync.Once
	n    int // how many there will be
	make func() []*Node
	kids []*Node
}

func later(n int, make func() []*Node) *lazy { return &lazy{n: n, make: make} }

// Children: the node's kids, made on first use.
func (n *Node) Children() []*Node {
	if n.lz == nil {
		return n.Kids
	}
	n.lz.once.Do(func() { n.lz.kids, n.lz.make = n.lz.make(), nil })
	return n.lz.kids
}

// count: how many kids the node has, without making them.
func (n *Node) count() int {
	if n.lz != nil {
		return n.lz.n
	}
	return len(n.Kids)
}

// Tree: the env's nodes for a grouping, most urgent first.
type Tree struct {
	By     string         `json:"by"`
	Nodes  []*Node        `json:"nodes"`
	Counts map[string]int `json:"counts"`            // fixes per priority (what the priority filter chips show)
	Fixes  int            `json:"fixes"`             // fixes to apply: the top rows of the fix grouping (report.FixKey)
	NoFix  int            `json:"no_fix"`            // of them, with nothing to install yet
	CVEs   int            `json:"cves"`              // unique CVE ids
	Hosts  int            `json:"hosts"`             // hosts with something to do
	Hidden int            `json:"hidden_backported"` // findings left out because a backport fixed them
	// Servers: with Opts.All, host rows per state (todo, clean, partial, failed, not_scanned)
	Servers map[string]int `json:"servers,omitempty"`
	// Rows: the top rows there are, when Nodes is one page of them (Page)
	Rows int `json:"rows,omitempty"`
}

// Key: a finding's selection key, stable between runs (the report key).
func Key(f *finding.Finding) string {
	k := report.KeyOf(f)
	return strings.Join(k[:], "|")
}

// item: a finding (its vulnerability's fields under C) with the fix it belongs to (U: report.FixKey).
type item = fset.Item

// Set: findings to build trees from, with the words the query filter searches. A server keeps one per run and
// builds many trees from it.
type Set struct {
	fs *fset.Set
}

// NewSet: a set over findings.
func NewSet(findings []finding.Finding) *Set { return &Set{fs: fset.Of(findings)} }

// FromSet: a set over findings already held compactly (package store's).
func FromSet(s *fset.Set) *Set { return &Set{fs: s} }

// All: the set's findings one at a time (fset.Set.All: the finding is reused).
func (s *Set) All() iter.Seq[*finding.Finding] { return s.fs.All() }

// Select: the set's findings of the kinds and ids keep says (keep sees each distinct pair once), one at a time,
// reused: a few of many, without making the rest into findings.
func (s *Set) Select(keep func(kind, id string) bool) iter.Seq[*finding.Finding] {
	return func(yield func(*finding.Finding) bool) {
		type pair struct {
			kind string
			c    int32
		}
		seen := map[pair]bool{}
		var f finding.Finding
		for _, it := range s.fs.Items {
			p := pair{it.Kind, it.C.Idx}
			k, ok := seen[p]
			if !ok {
				k = keep(it.Kind, it.C.ID)
				seen[p] = k
			}
			if !k {
				continue
			}
			it.Finding(&f)
			if !yield(&f) {
				return
			}
		}
	}
}

// Inventory: the set's inventory findings (Servers reads them).
func (s *Set) Inventory() iter.Seq[*finding.Finding] {
	return s.Select(func(kind, _ string) bool { return kind == finding.Inventory })
}

// searched: the fields the query filter looks in, joined (a query with spaces is matched against them).
func searched(f *item) string {
	return strings.Join([]string{f.Host, f.Group, f.Pkg, f.C.ID, f.C.Title, f.Target, f.Image, f.PkgPath}, " ")
}

// matcher: whether an item matches query q (lower case, trimmed). A query without spaces is in the joined fields
// only if it is in one of them, so each part (fset: shared by many findings) is checked once; one with spaces is
// matched against the joined fields, as before.
func (s *Set) matcher(q string) func(f *item) bool {
	if q == "" {
		return func(*item) bool { return true }
	}
	if strings.Contains(q, " ") {
		return func(f *item) bool { return strings.Contains(strings.ToLower(searched(f)), q) }
	}
	in := func(fields ...string) bool {
		for _, w := range fields {
			if strings.Contains(strings.ToLower(w), q) {
				return true
			}
		}
		return false
	}
	rest := make([]bool, len(s.fs.Rests))
	for i, r := range s.fs.Rests {
		rest[i] = in(r.Host, r.Group, r.Pkg, r.Target, r.Image, r.PkgPath)
	}
	cve := make([]bool, len(s.fs.CVEs))
	for i, c := range s.fs.CVEs {
		cve[i] = in(c.ID, c.Title)
	}
	return func(f *item) bool { return rest[f.Idx] || cve[f.C.Idx] }
}

// actionable: what the tree shows; inventory and accepted risks are not to-dos.
func actionable(f *item) bool { return f.Actionable() }

func installable(f *item) bool { return f.Installable() }

func state(f *item) string {
	switch {
	case f.Backported:
		return "backported"
	case f.Kind != finding.Vuln:
		return "other"
	case f.FixState == finding.FixReboot || f.Pending:
		return finding.FixReboot
	case !installable(f):
		return finding.FixVendor
	}
	return finding.FixAvailable
}

// keep: whether the filters (the query apart: Set.matcher) keep the item.
func (o Opts) keep(f *item) bool {
	if !actionable(f) || (f.Backported && !o.Backported) {
		return false
	}
	for _, x := range o.Filters {
		switch x {
		case FKEV:
			if !f.C.KEV {
				return false
			}
		case FRCE:
			if !(f.C.Preauth && f.C.RCE) {
				return false
			}
		case FEPSS:
			if f.C.EPSS == nil || *f.C.EPSS < 0.1 {
				return false
			}
		case FFront:
			if f.Exposure != 1 {
				return false
			}
		case FReady:
			if !installable(f) {
				return false
			}
		case FNoFix:
			if installable(f) {
				return false
			}
		case FOverdue:
			if f.DueOr() == "" || o.Today == "" || f.DueOr() >= o.Today {
				return false
			}
		}
	}
	return true
}

// unit: what one change fixes (report.FixKey, which every count of fixes uses).
func unit(f *item) (key, kind string) { return f.U.Key, f.U.Kind }

// Hosts: what the tree needs to know about hosts (from the view's facts).
type Hosts map[string]report.Fact

func (h Hosts) os(name string) string {
	if f, ok := h[name]; ok && f.OS != nil {
		return *f.OS
	}
	return ""
}

// hostNames: the hosts of a filled node's findings.
func (n *Node) hostNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range n.fs {
		if !seen[f.Host] {
			seen[f.Host] = true
			out = append(out, f.Host)
		}
	}
	return out
}

// common: the OS most of names run (of equal counts, the first by name), "" when none is known; a group's, which
// does not depend on the order of the findings.
func (h Hosts) common(names []string) string {
	n := map[string]int{}
	for _, name := range names {
		if os := h.os(name); os != "" {
			n[os]++
		}
	}
	best := ""
	for os, c := range n {
		if best == "" || c > n[best] || c == n[best] && os < best {
			best = os
		}
	}
	return best
}

func prioRank(p string) int {
	switch p {
	case "P1":
		return 1
	case "P2":
		return 2
	case "P3":
		return 3
	case "P4":
		return 4
	}
	return 9
}

func sevRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

// noFixOrder: why there is nothing to install, from the closest to a fix to the farthest.
var noFixOrder = []string{finding.NoFixRepos, finding.NoFixESM, finding.NoFixPending, finding.NoFixDeferred, finding.NoFixWontFix}

// fill sets a node's aggregates from its findings.
func fill(n *Node, fs []*item) *Node {
	n.fs = fs
	hosts := map[string]string{} // host -> its state (the most urgent of its findings')
	why := map[string]string{}   // host -> why it has nothing to install (the reason closest to a fix)
	groups := map[string]map[string]bool{}
	cves := map[string]bool{}
	n.Priority = "P4"
	for _, f := range fs {
		if p := f.PriorityOr(); prioRank(p) < prioRank(n.Priority) {
			n.Priority = p
		}
		if d := f.DueOr(); d != "" && (n.Due == "" || d < n.Due) {
			n.Due, n.DueWhy = d, f.DueWhy
		}
		if f.Kind == finding.Vuln {
			cves[f.C.ID] = true
		}
		if f.C.EPSS != nil && *f.C.EPSS > n.EPSS {
			n.EPSS = *f.C.EPSS
		}
		n.KEV = n.KEV || f.C.KEV
		n.RCE = n.RCE || f.C.Preauth && f.C.RCE
		n.Preauth = n.Preauth || f.C.Preauth
		if sevRank(f.C.Severity) > sevRank(n.Severity) {
			n.Severity = f.C.Severity
		}
		st := state(f)
		if old, ok := hosts[f.Host]; !ok || old == finding.FixAvailable {
			hosts[f.Host] = st
		}
		if r := f.NoFix(); r != "" && f.FixState != finding.FixReboot && !f.Backported {
			if old, ok := why[f.Host]; !ok || slices.Index(noFixOrder, r) < slices.Index(noFixOrder, old) {
				why[f.Host] = r
			}
		}
		if groups[f.Group] == nil {
			groups[f.Group] = map[string]bool{}
		}
		groups[f.Group][f.Host] = true
	}
	n.Hosts, n.CVEs = len(hosts), len(cves)
	n.States = map[string]int{}
	for h, st := range hosts {
		n.States[st]++
		if st == finding.FixVendor && why[h] != "" {
			if n.NoFix == nil {
				n.NoFix = map[string]int{}
			}
			n.NoFix[why[h]]++
		}
	}
	for g, hs := range groups {
		n.Groups = append(n.Groups, Count{g, len(hs)})
	}
	slices.SortFunc(n.Groups, func(a, b Count) int { return cmp.Or(b.N-a.N, strings.Compare(a.Name, b.Name)) })
	if len(hosts) < minGroupSize {
		for h := range hosts {
			n.HostList = append(n.HostList, h)
		}
		slices.Sort(n.HostList)
	}
	return n
}

// urgency: most urgent first (priority, KEV, RCE, EPSS, more hosts), then by label for a stable order.
func urgency(a, b *Node) int {
	return cmp.Or(cmp.Compare(prioRank(a.Priority), prioRank(b.Priority)), boolFirst(a.KEV, b.KEV), boolFirst(a.RCE, b.RCE),
		cmp.Compare(b.EPSS, a.EPSS), cmp.Compare(b.Hosts, a.Hosts), strings.Compare(a.Label, b.Label), strings.Compare(a.ID, b.ID))
}

func boolFirst(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	}
	return 1
}

func byKey(fs []*item, key func(*item) string) ([]string, map[string][]*item) {
	m := map[string][]*item{}
	var order []string
	for _, f := range fs {
		k := key(f)
		if m[k] == nil {
			order = append(order, k)
		}
		m[k] = append(m[k], f)
	}
	return order, m
}

// hostKids: the hosts under a node, grouped by host group when there are many. Made when first asked for; n is
// the node over the same findings (filled), whose host and group counts say how many kids there will be.
func hostKids(n *Node, id string, fs []*item, hosts Hosts) *lazy {
	count := n.Hosts
	if count >= minGroupSize {
		count = len(n.Groups)
	}
	return later(count, func() []*Node {
		leaf := func(h string, hf []*item) *Node {
			return fill(&Node{ID: id + "/h:" + h, Kind: KindHost, Label: h, OS: hosts.os(h), Exposure: hf[0].Exposure}, hf)
		}
		order, byHost := byKey(fs, func(f *item) string { return f.Host })
		if len(order) < minGroupSize {
			var out []*Node
			for _, h := range order {
				out = append(out, leaf(h, byHost[h]))
			}
			slices.SortFunc(out, func(a, b *Node) int { return strings.Compare(a.Label, b.Label) })
			return out
		}
		gorder, byGroup := byKey(fs, func(f *item) string { return f.Group })
		var out []*Node
		for _, g := range gorder {
			gf := byGroup[g]
			ho, bh := byKey(gf, func(f *item) string { return f.Host })
			n := fill(&Node{ID: id + "/g:" + g, Kind: KindGroup, Label: g, OS: hosts.common(ho), Exposure: gf[0].Exposure}, gf)
			for _, h := range ho {
				n.Kids = append(n.Kids, leaf(h, bh[h]))
			}
			slices.SortFunc(n.Kids, func(a, b *Node) int { return strings.Compare(a.Label, b.Label) })
			out = append(out, n)
		}
		slices.SortFunc(out, func(a, b *Node) int { return cmp.Or(b.Hosts-a.Hosts, strings.Compare(a.Label, b.Label)) })
		return out
	})
}

func where(f *item) string {
	if f.Module == "k8s" {
		return strings.TrimPrefix(f.Host, "k8s:") + " · " + f.Target
	}
	return f.Target
}

// unitNode: one unit and what is under it. deep: include where it is (hosts, or for images their components and
// where they run); the host grouping lists units under a host without repeating the host.
func unitNode(id string, fs []*item, hosts Hosts, deep bool) *Node {
	f0 := fs[0]
	_, kind := unit(f0)
	switch kind {
	case KindOther:
		n := fill(&Node{ID: id, Kind: KindOther, Label: f0.C.Title, Title: f0.Module}, fs)
		if deep {
			n.lz = hostKids(n, id, fs, hosts)
		}
		return n
	case KindPkg:
		var fixed, bins []string
		for _, f := range fs {
			fixed = append(fixed, f.Fixed)
			if !slices.Contains(bins, f.Pkg) {
				bins = append(bins, f.Pkg)
			}
		}
		slices.Sort(bins)
		label := f0.Pkg
		if len(bins) > 1 {
			label = f0.Source()
		}
		n := fill(&Node{ID: id, Kind: KindPkg, Label: label, Installed: f0.Installed, Fixed: report.HighestFix(fixed)}, fs)
		if len(bins) > 1 || bins[0] != label {
			n.Pkgs = bins
		}
		if f0.Target != "os" {
			n.Path = f0.Target
		}
		if deep {
			n.lz = hostKids(n, id, fs, hosts)
		}
		return n
	}
	runtime := "docker"
	img := strings.TrimPrefix(f0.Target, "image:")
	if f0.Module == "k8s" {
		runtime, img = "k8s", cmp.Or(f0.Image, f0.Target)
	}
	n := fill(&Node{ID: id, Kind: KindImage, Label: img, Runtime: runtime}, fs)
	porder, parts := byKey(fs, func(f *item) string { return f.Pkg + "|" + f.PkgPath + "|" + f.Installed + "|" + f.Fixed })
	var comps []*Node
	for _, k := range porder {
		pf := parts[k]
		comps = append(comps, fill(&Node{ID: id + "/p:" + k, Kind: KindPart, Label: pf[0].Pkg, Installed: pf[0].Installed,
			Fixed: pf[0].Fixed, Path: pf[0].PkgPath}, pf))
	}
	slices.SortFunc(comps, urgency)
	for _, c := range comps {
		if !slices.Contains(n.Parts, c.Label) {
			n.Parts = append(n.Parts, c.Label)
		}
	}
	n.Kids = append([]*Node{{ID: id + "/s:parts", Kind: KindSection, Label: "parts"}}, comps...)
	if deep {
		worder, ws := byKey(fs, where)
		n.Kids = append(n.Kids, &Node{ID: id + "/s:where", Kind: KindSection, Label: "where"})
		for _, w := range worder {
			wf := ws[w]
			wn := fill(&Node{ID: id + "/w:" + w, Kind: KindWhere, Label: w, Runtime: runtime}, wf)
			if runtime == "docker" {
				wn.lz = hostKids(wn, wn.ID, wf, hosts)
			}
			n.Kids = append(n.Kids, wn)
		}
	}
	return n
}

// units: the units of fs as nodes (not deep), most urgent first, made when first asked for.
func units(id string, fs []*item, hosts Hosts) *lazy {
	seen := map[string]bool{}
	for _, f := range fs {
		seen[f.U.Key] = true
	}
	return later(len(seen), func() []*Node {
		uo, us := byKey(fs, func(f *item) string { return f.U.Key })
		var out []*Node
		for _, u := range uo {
			out = append(out, unitNode(id+"/"+u, us[u], hosts, false))
		}
		slices.SortFunc(out, urgency)
		return out
	})
}

// Build: the tree of an environment's findings, every level made.
func Build(findings []finding.Finding, hosts Hosts, o Opts) *Tree {
	return BuildSet(NewSet(findings), hosts, o).Full()
}

// BuildSet: the tree of a set's findings with its top rows made; the levels under them are made when first
// asked for (Node.Children, Find, Shallow, Under, Full), once. The top rows don't keep their findings: a large
// environment's would be a million pointers per cached tree. A row's findings are picked from the set again
// when its kids or details are first asked for (a pass over the set: milliseconds).
func BuildSet(s *Set, hosts Hosts, o Opts) *Tree {
	t := &Tree{By: cmp.Or(o.By, ByFix), Counts: map[string]int{}}
	var fs, all []*item
	tally := report.NewTally()
	match := s.matcher(strings.ToLower(strings.TrimSpace(o.Query)))
	kept := func(f *item) bool { return o.keep(f) && match(f) }
	for i := range s.fs.Items {
		f := &s.fs.Items[i]
		if actionable(f) && f.Backported && !o.Backported {
			t.Hidden++
		}
		if actionable(f) && (!f.Backported || o.Backported) {
			all = append(all, f)
		}
		if !kept(f) {
			continue
		}
		fs = append(fs, f)
		tally.AddParts(f.U.Key, f.PriorityOr(), f.Installable(), f.Kind == finding.Vuln, f.C.ID, f.Host)
	}
	tot := tally.Totals()
	t.Counts, t.Fixes, t.NoFix, t.CVEs, t.Hosts = tot.ByPriority(), tot.Fixes, tot.NoFix, tot.CVEs, tot.Hosts
	recipes := map[*Node]recipe{}
	add := func(n *Node, r recipe) {
		recipes[n] = r
		t.Nodes = append(t.Nodes, n)
	}
	switch t.By {
	case ByCVE:
		order, m := byKey(fs, func(f *item) string {
			if f.Kind == finding.Vuln {
				return "cve:" + f.C.ID
			}
			return f.U.Key
		})
		for _, k := range order {
			if !strings.HasPrefix(k, "cve:") {
				u := m[k][0].U
				mk := func(fs []*item) *Node { return unitNode(k, fs, hosts, true) }
				add(mk(m[k]), recipe{func(f *item) bool { return f.Kind != finding.Vuln && f.U == u && kept(f) }, mk})
				continue
			}
			id := strings.TrimPrefix(k, "cve:")
			mk := func(fs []*item) *Node { return cveNode(k, fs, hosts) }
			add(mk(m[k]), recipe{func(f *item) bool { return f.Kind == finding.Vuln && f.C.ID == id && kept(f) }, mk})
		}
	case ByHost:
		if o.All {
			servers(t, all, fs, hosts, o)
			for _, n := range t.Nodes {
				if n.fs == nil {
					continue // no findings (clean, not scanned)
				}
				h := n.Label
				mk := func(hf []*item) *Node {
					var kf []*item
					for _, f := range hf {
						if kept(f) {
							kf = append(kf, f)
						}
					}
					k := &Node{fs: hf}
					if len(kf) > 0 {
						k.lz = units(n.ID, kf, hosts)
					}
					return k
				}
				recipes[n] = recipe{func(f *item) bool { return f.Host == h && actionable(f) && (!f.Backported || o.Backported) }, mk}
			}
			t.detach(s, recipes)
			return t
		}
		order, m := byKey(fs, func(f *item) string { return f.Group })
		for _, g := range order {
			mk := func(gf []*item) *Node { return groupNode(g, gf, hosts) }
			add(mk(m[g]), recipe{func(f *item) bool { return f.Group == g && kept(f) }, mk})
		}
	default:
		t.By = ByFix
		order, m := byKey(fs, func(f *item) string { return f.U.Key })
		for _, k := range order {
			u := m[k][0].U
			mk := func(fs []*item) *Node { return unitNode(k, fs, hosts, true) }
			add(mk(m[k]), recipe{func(f *item) bool { return f.U == u && kept(f) }, mk})
		}
	}
	disambiguate(t.Nodes, hosts)
	slices.SortFunc(t.Nodes, urgency)
	t.detach(s, recipes)
	return t
}

// recipe: how to make a top row again from the set: which findings are its, and the row from them.
type recipe struct {
	pick func(*item) bool
	make func([]*item) *Node
}

// detach lets the top rows go of their findings (and of kids made with them); each picks them from the set
// again, once, when they are needed.
func (t *Tree) detach(s *Set, recipes map[*Node]recipe) {
	for _, n := range t.Nodes {
		r, ok := recipes[n]
		if !ok {
			continue
		}
		count := n.count()
		full := sync.OnceValue(func() *Node {
			var fs []*item
			for i := range s.fs.Items {
				if f := &s.fs.Items[i]; r.pick(f) {
					fs = append(fs, f)
				}
			}
			return r.make(fs)
		})
		n.fs, n.Kids, n.full = nil, nil, full
		n.lz = later(count, func() []*Node { return full().Children() })
	}
}

// items: the node's findings.
func (n *Node) items() []*item {
	if n.full != nil {
		return n.full().fs
	}
	return n.fs
}

// cveNode: a CVE and the fixes under it.
func cveNode(k string, g []*item, hosts Hosts) *Node {
	n := fill(&Node{ID: k, Kind: KindCVE, Label: g[0].C.ID, Title: g[0].C.Title}, g)
	seen := map[*fset.Unit]bool{}
	for _, f := range g {
		seen[f.U] = true
	}
	n.lz = later(len(seen), func() []*Node {
		uo, us := byKey(g, func(f *item) string { return f.U.Key })
		var kids []*Node
		for _, u := range uo {
			kids = append(kids, unitNode(k+"/"+u, us[u], hosts, true))
		}
		disambiguate(kids, hosts)
		slices.SortFunc(kids, urgency)
		return kids
	})
	return n
}

// groupNode: a host group and its hosts, each with its fixes.
func groupNode(g string, gf []*item, hosts Hosts) *Node {
	gn := fill(&Node{ID: "g:" + g, Kind: KindGroup, Label: g, Exposure: gf[0].Exposure}, gf)
	gn.OS = hosts.common(gn.hostNames())
	gn.lz = later(gn.Hosts, func() []*Node {
		ho, hm := byKey(gf, func(f *item) string { return f.Host })
		var kids []*Node
		for _, h := range ho {
			hf := hm[h]
			hn := fill(&Node{ID: gn.ID + "/h:" + h, Kind: KindHost, Label: h, OS: hosts.os(h), Exposure: hf[0].Exposure}, hf)
			hn.lz = units(hn.ID, hf, hosts)
			kids = append(kids, hn)
		}
		slices.SortFunc(kids, urgency)
		return kids
	})
	return gn
}

var (
	osParen = regexp.MustCompile(`\s*\([^)]*\)`)
	osPoint = regexp.MustCompile(`\b(\d+\.\d+)\.\d+\b`)
)

// ShortOS: an os-release name as short as still tells releases apart: "Ubuntu 22.04.5 LTS" -> "Ubuntu 22.04",
// "Debian GNU/Linux 12 (bookworm)" -> "Debian 12".
func ShortOS(name string) string {
	s := osParen.ReplaceAllString(name, "")
	s = strings.ReplaceAll(s, " GNU/Linux", "")
	s = strings.TrimSuffix(strings.TrimSpace(s), " LTS")
	return strings.TrimSpace(osPoint.ReplaceAllString(s, "$1"))
}

// disambiguate: package updates of the same name side by side (libc6 of Ubuntu 22.04 and of Debian 12) get the
// OS releases they are on, in OS and after the label, when that tells them apart.
func disambiguate(nodes []*Node, hosts Hosts) {
	byLabel := map[string][]*Node{}
	for _, n := range nodes {
		if n.Kind == KindPkg {
			byLabel[n.Path+"\x00"+n.Label] = append(byLabel[n.Path+"\x00"+n.Label], n)
		}
	}
	for _, same := range byLabel {
		if len(same) < 2 {
			continue
		}
		oses := make([]string, len(same))
		short := map[string]string{} // host -> ShortOS of its OS (a node has many findings per host)
		for i, n := range same {
			var l []string
			for _, f := range n.fs {
				o, ok := short[f.Host]
				if !ok {
					o = ShortOS(hosts.os(f.Host))
					short[f.Host] = o
				}
				if o != "" && !slices.Contains(l, o) {
					l = append(l, o)
				}
			}
			slices.Sort(l)
			oses[i] = strings.Join(l, ", ")
		}
		if len(slices.Compact(slices.Sorted(slices.Values(oses)))) < 2 {
			continue // the same OS everywhere: the versions tell them apart
		}
		for i, n := range same {
			if oses[i] != "" {
				n.OS = oses[i]
				n.Label += " (" + oses[i] + ")"
			}
		}
	}
}

// Full: the tree with every level made, as plain nodes (t itself is not changed: it may be cached).
func (t *Tree) Full() *Tree {
	c := *t
	c.Nodes = full(t.Nodes)
	return &c
}

func full(ns []*Node) []*Node {
	if ns == nil {
		return nil // an empty tree reads "nodes": null, as it always has
	}
	out := make([]*Node, len(ns))
	for i, n := range ns {
		c := *n
		c.lz, c.Kids = nil, nil
		if kids := n.Children(); kids != nil {
			c.Kids = full(kids)
		}
		out[i] = &c
	}
	return out
}

// Shallow: the tree with levels kids under the top rows (0: the top rows only); deeper kids are left out and
// counted in More (an image's row names its parts in Parts). t itself is not changed (it is cached).
func (t *Tree) Shallow(levels int) *Tree {
	c := *t
	c.Nodes = shallow(t.Nodes, levels)
	return &c
}

// Page: the tree with limit top rows from offset (limit <= 0: all of them after offset); Rows says how many there
// are. t itself is not changed.
func (t *Tree) Page(offset, limit int) *Tree {
	c := *t
	c.Rows = len(t.Nodes)
	offset = min(max(offset, 0), len(t.Nodes))
	end := len(t.Nodes)
	if limit > 0 {
		end = min(offset+limit, end)
	}
	c.Nodes = t.Nodes[offset:end]
	return &c
}

// FullUnder: the kids of node id with every level under them made; nil when there is no such node.
func (t *Tree) FullUnder(id string) []*Node {
	n := t.Find(id)
	if n == nil {
		return nil
	}
	return full(n.Children())
}

// Under: the kids of node id, with levels kids under them, as Shallow; nil when there is no such node.
func (t *Tree) Under(id string, levels int) []*Node {
	n := t.Find(id)
	if n == nil {
		return nil
	}
	return shallow(n.Children(), levels)
}

func shallow(ns []*Node, levels int) []*Node {
	out := make([]*Node, len(ns))
	for i, n := range ns {
		c := *n
		c.lz = nil
		switch {
		case levels > 0:
			c.Kids = shallow(n.Children(), levels-1)
		default:
			c.Kids, c.More = nil, n.count()
		}
		out[i] = &c
	}
	return out
}

// Find: the node with id anywhere in the tree, nil if none. Only the levels on the way to it are made: a node's
// kids' ids start with its own and "/" (but a host group's under a fix: its hosts' ids start with the fix's).
func (t *Tree) Find(id string) *Node {
	var walk func([]*Node) *Node
	walk = func(ns []*Node) *Node {
		for _, n := range ns {
			if n.ID == id {
				return n
			}
			if !strings.HasPrefix(id, n.ID+"/") && n.Kind != KindGroup { // hosts grouped under a fix keep the fix's id
				continue
			}
			if k := walk(n.Children()); k != nil {
				return k
			}
		}
		return nil
	}
	return walk(t.Nodes)
}
