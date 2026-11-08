// Package tree groups an environment's findings into what to do: by fix (one package update on many hosts, one
// image to rebuild), by CVE, or by host. The web page, the TUI and MCP draw the same nodes, so they can't drift
// apart. Nodes carry aggregates (priority, earliest due date, hosts, CVEs, EPSS, flags, fix states); Detail adds
// what a details pane shows.
package tree

import (
	"cmp"
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
	KindPkg      = "pkg"     // an OS package update: pkg installed -> fixed, on hosts
	KindImage    = "image"   // an image to rebuild (docker, or a k8s workload's)
	KindPart     = "part"    // a component inside an image (a library, a package of the base image)
	KindWhere    = "where"   // where an image runs: a container name on hosts, a k8s workload
	KindCVE      = "cve"     // one vulnerability
	KindGroup    = "group"   // a host group
	KindHost     = "host"    // one host
	KindOther    = "other"   // a misconfiguration, an exposure, a health problem
	KindSection  = "section" // a heading inside a node: "components", "runs on", "OS packages"
	minGroupSize = 7         // fewer hosts than this are listed, more are grouped by host group
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
	Installed string `json:"installed,omitempty"`
	Fixed     string `json:"fixed,omitempty"`
	Path      string `json:"path,omitempty"`    // a library's file in the image
	Runtime   string `json:"runtime,omitempty"` // image / where: docker, k8s
	Title     string `json:"title,omitempty"`   // CVE: the advisory's title; other: what it is
	Severity  string `json:"severity,omitempty"`
	OS        string `json:"os,omitempty"` // host, group: the OS
	Exposure  int    `json:"exposure,omitempty"`

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
	Keys     []string       `json:"-"`                // the report keys of the findings under it

	Kids []*Node `json:"kids,omitempty"`
	fs   []*finding.Finding
}

// Tree: the env's nodes for a grouping, most urgent first.
type Tree struct {
	By     string         `json:"by"`
	Nodes  []*Node        `json:"nodes"`
	Counts map[string]int `json:"counts"` // fixes per priority (what the priority filter chips show)
	Fixes  int            `json:"fixes"`
	CVEs   int            `json:"cves"`
	Hosts  int            `json:"hosts"`
	Hidden int            `json:"hidden_backported"` // findings left out because a backport fixed them
}

// Key: a finding's selection key, stable between runs (the report key).
func Key(f *finding.Finding) string {
	k := report.KeyOf(f)
	return strings.Join(k[:], "|")
}

// actionable: what the tree shows; inventory and accepted risks are not to-dos.
func actionable(f *finding.Finding) bool {
	return f.Kind != finding.Inventory && !f.Accepted && f.Priority != nil
}

func installable(f *finding.Finding) bool {
	switch f.FixState {
	case finding.FixAvailable, finding.FixReboot:
		return true
	case finding.FixVendor:
		return false
	}
	return f.Kind != finding.Vuln || f.Fixed != ""
}

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

// unit: what one change fixes. OS packages: the package update (same versions = same command); docker: the image;
// k8s: the workload's image (or the workload when the image is unknown); everything else: the check on its hosts.
func unit(f *finding.Finding) (key, kind string) {
	switch {
	case f.Kind != finding.Vuln:
		return "other:" + f.Module + ":" + f.ID + ":" + f.Title, KindOther
	case f.Module == "k8s":
		img := f.Image
		if img == "" {
			img = f.Target
		}
		return "image:k8s:" + img, KindImage
	case strings.HasPrefix(f.Target, "image:"):
		return "image:docker:" + strings.TrimPrefix(f.Target, "image:"), KindImage
	case f.Target != "" && f.Target != "os":
		return "pkg:" + f.Target + ":" + f.Pkg + ":" + f.Installed + ":" + f.Fixed, KindPkg // a library on the host
	}
	return "pkg:os:" + f.Pkg + ":" + f.Installed + ":" + f.Fixed, KindPkg
}

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

// fill sets a node's aggregates from its findings.
func fill(n *Node, fs []*finding.Finding) *Node {
	n.fs = fs
	hosts := map[string]string{} // host -> its state (the most urgent of its findings')
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
		if groups[f.Group] == nil {
			groups[f.Group] = map[string]bool{}
		}
		groups[f.Group][f.Host] = true
		n.Keys = append(n.Keys, Key(f))
	}
	n.Hosts, n.CVEs = len(hosts), len(cves)
	n.States = map[string]int{}
	for _, st := range hosts {
		n.States[st]++
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
		n := fill(&Node{ID: id, Kind: KindPkg, Label: f0.Pkg, Installed: f0.Installed, Fixed: f0.Fixed}, fs)
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
	var fs []*finding.Finding
	allHosts, allCVEs := map[string]bool{}, map[string]bool{}
	units := map[string]string{}
	for i := range findings {
		f := &findings[i]
		if actionable(f) && f.Backported && !o.Backported {
			t.Hidden++
		}
		if !o.keep(f) {
			continue
		}
		fs = append(fs, f)
		allHosts[f.Host] = true
		if f.Kind == finding.Vuln {
			allCVEs[f.ID] = true
		}
		k, _ := unit(f)
		if p, ok := units[k]; !ok || prioRank(f.PriorityOr()) < prioRank(p) {
			units[k] = f.PriorityOr()
		}
	}
	for _, p := range units {
		t.Counts[p]++
	}
	t.Fixes, t.CVEs, t.Hosts = len(units), len(allCVEs), len(allHosts)
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
			slices.SortFunc(n.Kids, urgency)
			t.Nodes = append(t.Nodes, n)
		}
	case ByHost:
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
	slices.SortFunc(t.Nodes, urgency)
	return t
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
