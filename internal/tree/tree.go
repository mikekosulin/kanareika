// Package tree groups an environment's findings into what to do: by fix (one package update on many hosts, one
// image to rebuild), by CVE, or by host. The web page, the TUI and MCP draw the same nodes, so they can't drift
// apart. Nodes carry aggregates (priority, earliest due date, hosts, CVEs, EPSS, flags, fix states); Detail adds
// what a details pane shows.
package tree

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	"github.com/mikekosulin/kanareika/internal/finding"
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
	Keys     []string       `json:"-"`                // the report keys of the findings under it

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
	fs   []*finding.Finding
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
}

// Key: a finding's selection key, stable between runs (the report key).
func Key(f *finding.Finding) string {
	k := report.KeyOf(f)
	return strings.Join(k[:], "|")
}

// actionable: what the tree shows; inventory and accepted risks are not to-dos.
func actionable(f *finding.Finding) bool { return report.Actionable(f) }

func installable(f *finding.Finding) bool { return report.Installable(f) }

func state(f *finding.Finding) string {
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

func (o Opts) keep(f *finding.Finding) bool {
	if !actionable(f) || (f.Backported && !o.Backported) {
		return false
	}
	for _, x := range o.Filters {
		switch x {
		case FKEV:
			if !f.KEV {
				return false
			}
		case FRCE:
			if !(f.Preauth && f.RCE) {
				return false
			}
		case FEPSS:
			if f.EPSS == nil || *f.EPSS < 0.1 {
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
	if q := strings.ToLower(strings.TrimSpace(o.Query)); q != "" {
		hay := strings.ToLower(strings.Join([]string{f.Host, f.Group, f.Pkg, f.ID, f.Title, f.Target, f.Image, f.PkgPath}, " "))
		if !strings.Contains(hay, q) {
			return false
		}
	}
	return true
}

// unit: what one change fixes (report.FixKey, which every count of fixes uses).
func unit(f *finding.Finding) (key, kind string) { return report.FixKey(f) }

// Hosts: what the tree needs to know about hosts (from the view's facts).
type Hosts map[string]report.Fact

func (h Hosts) os(name string) string {
	if f, ok := h[name]; ok && f.OS != nil {
		return *f.OS
	}
	return ""
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
	return map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[s]
}

// noFixOrder: why there is nothing to install, from the closest to a fix to the farthest.
var noFixOrder = []string{finding.NoFixRepos, finding.NoFixESM, finding.NoFixPending, finding.NoFixDeferred, finding.NoFixWontFix}

// fill sets a node's aggregates from its findings.
func fill(n *Node, fs []*finding.Finding) *Node {
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
			cves[f.ID] = true
		}
		if f.EPSS != nil && *f.EPSS > n.EPSS {
			n.EPSS = *f.EPSS
		}
		n.KEV = n.KEV || f.KEV
		n.RCE = n.RCE || f.Preauth && f.RCE
		n.Preauth = n.Preauth || f.Preauth
		if sevRank(f.Severity) > sevRank(n.Severity) {
			n.Severity = f.Severity
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
		n.Keys = append(n.Keys, Key(f))
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
	slices.Sort(n.Keys)
	n.Keys = slices.Compact(n.Keys)
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

func byKey(fs []*finding.Finding, key func(*finding.Finding) string) ([]string, map[string][]*finding.Finding) {
	m := map[string][]*finding.Finding{}
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

// hostKids: the hosts under a node, grouped by host group when there are many.
func hostKids(id string, fs []*finding.Finding, hosts Hosts) []*Node {
	leaf := func(h string, hf []*finding.Finding) *Node {
		n := fill(&Node{ID: id + "/h:" + h, Kind: KindHost, Label: h, OS: hosts.os(h), Exposure: hf[0].Exposure}, hf)
		return n
	}
	order, byHost := byKey(fs, func(f *finding.Finding) string { return f.Host })
	if len(order) < minGroupSize {
		var out []*Node
		for _, h := range order {
			out = append(out, leaf(h, byHost[h]))
		}
		slices.SortFunc(out, func(a, b *Node) int { return strings.Compare(a.Label, b.Label) })
		return out
	}
	gorder, byGroup := byKey(fs, func(f *finding.Finding) string { return f.Group })
	var out []*Node
	for _, g := range gorder {
		gf := byGroup[g]
		n := fill(&Node{ID: id + "/g:" + g, Kind: KindGroup, Label: g, OS: hosts.os(gf[0].Host), Exposure: gf[0].Exposure}, gf)
		ho, bh := byKey(gf, func(f *finding.Finding) string { return f.Host })
		for _, h := range ho {
			n.Kids = append(n.Kids, leaf(h, bh[h]))
		}
		slices.SortFunc(n.Kids, func(a, b *Node) int { return strings.Compare(a.Label, b.Label) })
		out = append(out, n)
	}
	slices.SortFunc(out, func(a, b *Node) int { return cmp.Or(b.Hosts-a.Hosts, strings.Compare(a.Label, b.Label)) })
	return out
}

func where(f *finding.Finding) string {
	if f.Module == "k8s" {
		return strings.TrimPrefix(f.Host, "k8s:") + " · " + f.Target
	}
	return f.Target
}

// unitNode: one unit and what is under it. deep: include where it is (hosts, or for images their components and
// where they run); the host grouping lists units under a host without repeating the host.
func unitNode(id string, fs []*finding.Finding, hosts Hosts, deep bool) *Node {
	f0 := fs[0]
	_, kind := unit(f0)
	switch kind {
	case KindOther:
		n := fill(&Node{ID: id, Kind: KindOther, Label: f0.Title, Title: f0.Module}, fs)
		if deep {
			n.Kids = hostKids(id, fs, hosts)
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
			n.Kids = hostKids(id, fs, hosts)
		}
		return n
	}
	runtime := "docker"
	img := strings.TrimPrefix(f0.Target, "image:")
	if f0.Module == "k8s" {
		runtime, img = "k8s", cmp.Or(f0.Image, f0.Target)
	}
	n := fill(&Node{ID: id, Kind: KindImage, Label: img, Runtime: runtime}, fs)
	porder, parts := byKey(fs, func(f *finding.Finding) string { return f.Pkg + "|" + f.PkgPath + "|" + f.Installed + "|" + f.Fixed })
	var comps []*Node
	for _, k := range porder {
		pf := parts[k]
		comps = append(comps, fill(&Node{ID: id + "/p:" + k, Kind: KindPart, Label: pf[0].Pkg, Installed: pf[0].Installed,
			Fixed: pf[0].Fixed, Path: pf[0].PkgPath}, pf))
	}
	slices.SortFunc(comps, urgency)
	n.Kids = append([]*Node{{ID: id + "/s:parts", Kind: KindSection, Label: "parts"}}, comps...)
	if deep {
		worder, ws := byKey(fs, where)
		n.Kids = append(n.Kids, &Node{ID: id + "/s:where", Kind: KindSection, Label: "where"})
		for _, w := range worder {
			wf := ws[w]
			wn := fill(&Node{ID: id + "/w:" + w, Kind: KindWhere, Label: w, Runtime: runtime}, wf)
			if runtime == "docker" {
				wn.Kids = hostKids(wn.ID, wf, hosts)
			}
			n.Kids = append(n.Kids, wn)
		}
	}
	return n
}

// Build: the tree of an environment's findings.
func Build(findings []finding.Finding, hosts Hosts, o Opts) *Tree {
	t := &Tree{By: cmp.Or(o.By, ByFix), Counts: map[string]int{}}
	var fs, all []*finding.Finding
	tally := report.NewTally()
	for i := range findings {
		f := &findings[i]
		if actionable(f) && f.Backported && !o.Backported {
			t.Hidden++
		}
		if actionable(f) && (!f.Backported || o.Backported) {
			all = append(all, f)
		}
		if !o.keep(f) {
			continue
		}
		fs = append(fs, f)
		tally.Add(f)
	}
	tot := tally.Totals()
	t.Counts, t.Fixes, t.NoFix, t.CVEs, t.Hosts = tot.ByPriority(), tot.Fixes, tot.NoFix, tot.CVEs, tot.Hosts
	switch t.By {
	case ByCVE:
		order, m := byKey(fs, func(f *finding.Finding) string {
			if f.Kind == finding.Vuln {
				return "cve:" + f.ID
			}
			k, _ := unit(f)
			return k
		})
		for _, k := range order {
			g := m[k]
			if !strings.HasPrefix(k, "cve:") {
				t.Nodes = append(t.Nodes, unitNode(k, g, hosts, true))
				continue
			}
			n := fill(&Node{ID: k, Kind: KindCVE, Label: g[0].ID, Title: g[0].Title}, g)
			uo, us := byKey(g, func(f *finding.Finding) string { k, _ := unit(f); return k })
			for _, u := range uo {
				n.Kids = append(n.Kids, unitNode(k+"/"+u, us[u], hosts, true))
			}
			disambiguate(n.Kids, hosts)
			slices.SortFunc(n.Kids, urgency)
			t.Nodes = append(t.Nodes, n)
		}
	case ByHost:
		if o.All {
			servers(t, all, fs, hosts, o)
			return t
		}
		order, m := byKey(fs, func(f *finding.Finding) string { return f.Group })
		for _, g := range order {
			gf := m[g]
			gn := fill(&Node{ID: "g:" + g, Kind: KindGroup, Label: g, OS: hosts.os(gf[0].Host), Exposure: gf[0].Exposure}, gf)
			ho, hm := byKey(gf, func(f *finding.Finding) string { return f.Host })
			for _, h := range ho {
				hf := hm[h]
				hn := fill(&Node{ID: gn.ID + "/h:" + h, Kind: KindHost, Label: h, OS: hosts.os(h), Exposure: hf[0].Exposure}, hf)
				uo, us := byKey(hf, func(f *finding.Finding) string { k, _ := unit(f); return k })
				for _, u := range uo {
					hn.Kids = append(hn.Kids, unitNode(hn.ID+"/"+u, us[u], hosts, false))
				}
				slices.SortFunc(hn.Kids, urgency)
				gn.Kids = append(gn.Kids, hn)
			}
			slices.SortFunc(gn.Kids, urgency)
			t.Nodes = append(t.Nodes, gn)
		}
	default:
		t.By = ByFix
		order, m := byKey(fs, func(f *finding.Finding) string { k, _ := unit(f); return k })
		for _, k := range order {
			t.Nodes = append(t.Nodes, unitNode(k, m[k], hosts, true))
		}
	}
	disambiguate(t.Nodes, hosts)
	slices.SortFunc(t.Nodes, urgency)
	return t
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
		for i, n := range same {
			var l []string
			for _, f := range n.fs {
				if o := ShortOS(hosts.os(f.Host)); o != "" && !slices.Contains(l, o) {
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

// Shallow: the tree with levels kids under the top rows (0: the top rows only); deeper kids are left out and
// counted in More. An image keeps its own kids, the parts its row names. t itself is not changed (it is cached).
func (t *Tree) Shallow(levels int) *Tree {
	c := *t
	c.Nodes = shallow(t.Nodes, levels)
	return &c
}

// Under: the kids of node id, with levels kids under them, as Shallow; nil when there is no such node.
func (t *Tree) Under(id string, levels int) []*Node {
	n := t.Find(id)
	if n == nil {
		return nil
	}
	return shallow(n.Kids, levels)
}

func shallow(ns []*Node, levels int) []*Node {
	out := make([]*Node, len(ns))
	for i, n := range ns {
		c := *n
		switch {
		case levels > 0 || n.Kind == KindImage && levels == 0:
			c.Kids = shallow(n.Kids, levels-1)
		default:
			c.Kids, c.More = nil, len(n.Kids)
		}
		out[i] = &c
	}
	return out
}

// Find: the node with id anywhere in the tree, nil if none.
func (t *Tree) Find(id string) *Node {
	var walk func([]*Node) *Node
	walk = func(ns []*Node) *Node {
		for _, n := range ns {
			if n.ID == id {
				return n
			}
			if k := walk(n.Kids); k != nil {
				return k
			}
		}
		return nil
	}
	return walk(t.Nodes)
}
