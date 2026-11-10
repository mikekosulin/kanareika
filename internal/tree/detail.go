package tree

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/fset"
	"github.com/mikekosulin/kanareika/internal/report"
)

// Reason: why a node has its priority; Code is a message key for the interfaces (tree.why.<code>), Args its values.
type Reason struct {
	Code string         `json:"code"`
	Args map[string]any `json:"args,omitempty"`
}

// Due: the date and where it comes from (priority.Apply's clock).
type Due struct {
	Date       string `json:"date,omitempty"`
	Why        string `json:"why,omitempty"` // first_seen, fix_available, published, scan, escalated, exception_ended, kev, no_fix
	ClockStart string `json:"clock_start,omitempty"`
	FirstSeen  string `json:"first_seen,omitempty"`
	KEVDue     string `json:"kev_due,omitempty"`
	Overdue    int    `json:"overdue,omitempty"` // days past the date
	In         int    `json:"in"`                // days left (negative: overdue)
}

// CVE: what the details pane says about one vulnerability.
type CVE struct {
	ID          string   `json:"id"`
	Title       string   `json:"title,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	CVSS        *float64 `json:"cvss,omitempty"`
	Vector      string   `json:"vector,omitempty"`
	EPSS        *float64 `json:"epss,omitempty"`
	KEV         bool     `json:"kev,omitempty"`
	KEVDue      string   `json:"kev_due,omitempty"`
	Preauth     bool     `json:"preauth,omitempty"`
	RCE         bool     `json:"rce,omitempty"`
	Published   string   `json:"published,omitempty"`
	Description string   `json:"description,omitempty"`
	URL         string   `json:"url,omitempty"`
	Hosts       int      `json:"hosts"`
}

// Where: hosts of one group under the node.
type Where struct {
	Group    string         `json:"group"`
	Hosts    []string       `json:"hosts"`
	OS       string         `json:"os,omitempty"`
	Exposure int            `json:"exposure,omitempty"`
	States   map[string]int `json:"states"`
}

// Step: one command for the hosts of one OS family.
type Step struct {
	OS      string   `json:"os"`
	Hosts   []string `json:"hosts"`
	Command string   `json:"command"`
	Reboot  bool     `json:"reboot,omitempty"`
	Unsafe  []string `json:"unsafe,omitempty"` // package names the hosts reported that no package manager has: left out of Command
}

type Detail struct {
	Node    *Node    `json:"node"`
	Why     []Reason `json:"why"`
	Due     Due      `json:"due"`
	CVEs    []CVE    `json:"cves"`      // the most urgent first, at most MaxCVEs
	More    int      `json:"cves_more"` // CVEs left out of CVEs
	Where   []Where  `json:"where"`
	Apply   []Step   `json:"apply,omitempty"`
	Actions []string `json:"actions"` // ids of the view's actions that cover the node (the agent task is built from them)
}

func days(from, to string) int {
	a, err1 := time.Parse(time.DateOnly, from)
	b, err2 := time.Parse(time.DateOnly, to)
	if err1 != nil || err2 != nil {
		return 0
	}
	return int(b.Sub(a).Hours() / 24)
}

// family: the package manager of an OS name from os-release.
func family(os string) string {
	l := strings.ToLower(os)
	switch {
	case strings.Contains(l, "debian"), strings.Contains(l, "ubuntu"), strings.Contains(l, "mint"), strings.Contains(l, "astra"):
		return "apt"
	case strings.Contains(l, "alpine"):
		return "apk"
	case strings.Contains(l, "suse"):
		return "zypper"
	case l == "":
		return ""
	}
	return "dnf" // RHEL, Rocky, Alma, CentOS, Oracle, Fedora, Amazon
}

// pkgName: a name a package manager could have (Debian, RPM, Alpine, SUSE): letters, digits and .+_:@~-, not starting
// with a dash. Anything else came from a host and is not put into a shell command.
func pkgName(s string) bool {
	if s == "" || s[0] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(".+_:@~-", r)) {
			return false
		}
	}
	return true
}

func command(fam, pkg string) string {
	switch fam {
	case "apt":
		return "apt-get update && apt-get install --only-upgrade " + pkg
	case "apk":
		return "apk upgrade " + pkg
	case "zypper":
		return "zypper update " + pkg
	case "dnf":
		return "dnf update " + pkg
	}
	return ""
}

// covers: the action deals with the finding (same host, and its package, image, or check).
func covers(a *report.Action, f *item) bool {
	if !slices.Contains(a.Hosts, f.Host) {
		return false
	}
	if f.Kind != finding.Vuln {
		return a.Title == f.C.Title || a.Msg != "" && a.Msg == f.Msg && a.Target != nil && *a.Target == f.Target
	}
	if a.Image != nil && strings.TrimPrefix(f.Target, "image:") == *a.Image {
		return true
	}
	return slices.ContainsFunc(a.Packages, func(p report.Package) bool { return p.Pkg == f.Pkg })
}

// MaxCVEs: the most CVEs a node's details list. A group of servers can close tens of thousands (megabytes with
// their texts); the details show the most urgent, the count says how many more.
const MaxCVEs = 50

// Describe: the details of node n (from tree t, built over findings).
func Describe(n *Node, hosts Hosts, view *report.View, today string) *Detail {
	d := &Detail{Node: n, Why: []Reason{}, CVEs: []CVE{}, Where: []Where{}, Actions: []string{}}
	fs := n.items()
	// why
	front := map[string]bool{}
	for _, f := range fs {
		if f.Exposure == 1 {
			front[f.Host] = true
		}
	}
	if n.KEV {
		d.Why = append(d.Why, Reason{Code: "kev"})
	}
	switch {
	case n.RCE:
		d.Why = append(d.Why, Reason{Code: "rce"})
	case n.Preauth:
		d.Why = append(d.Why, Reason{Code: "preauth"})
	}
	if n.EPSS >= 0.1 {
		d.Why = append(d.Why, Reason{Code: "epss", Args: map[string]any{"epss": n.EPSS}})
	}
	if len(front) > 0 {
		d.Why = append(d.Why, Reason{Code: "front", Args: map[string]any{"n": len(front), "of": n.Hosts}})
	}
	if n.States[finding.FixVendor] > 0 {
		args := map[string]any{"n": n.States[finding.FixVendor]}
		for r, k := range n.NoFix { // hosts per reason: pending, repos, esm, deferred, wontfix
			args[r] = k
		}
		d.Why = append(d.Why, Reason{Code: "nofix", Args: args})
	}
	if n.States[finding.FixReboot] > 0 {
		d.Why = append(d.Why, Reason{Code: "reboot", Args: map[string]any{"n": n.States[finding.FixReboot]}})
	}
	if n.Severity != "" && len(d.Why) == 0 {
		d.Why = append(d.Why, Reason{Code: "severity", Args: map[string]any{"severity": n.Severity}})
	}
	// due: the finding that sets the earliest date explains it
	var first *item
	for _, f := range fs {
		if f.DueOr() != "" && (first == nil || f.DueOr() < first.DueOr()) {
			first = f
		}
	}
	if first != nil {
		d.Due = Due{Date: first.DueOr(), Why: first.DueWhy, ClockStart: first.ClockStart, FirstSeen: first.FirstSeen,
			KEVDue: first.C.KEVDue, In: days(today, first.DueOr())}
		if d.Due.In < 0 {
			d.Due.Overdue = -d.Due.In
		}
	} else if len(fs) > 0 {
		d.Due.Why, d.Due.FirstSeen = fs[0].DueWhy, fs[0].FirstSeen
	}
	// CVEs
	cves := map[string]*CVE{}
	parts := map[string]*fset.CVE{} // where each row's description is
	cveHosts := map[string]map[string]bool{}
	for _, f := range fs {
		if f.Kind != finding.Vuln {
			continue
		}
		c := cves[f.C.ID]
		if c == nil {
			parts[f.C.ID] = f.C
			c = &CVE{ID: f.C.ID, Title: f.C.Title, Severity: f.C.Severity, CVSS: f.C.CVSSScore, Vector: f.C.Vector, EPSS: f.C.EPSS, KEV: f.C.KEV,
				KEVDue: f.C.KEVDue, Preauth: f.C.Preauth, RCE: f.C.Preauth && f.C.RCE, Published: f.C.Published, URL: f.C.URL}
			cves[f.C.ID], cveHosts[f.C.ID] = c, map[string]bool{}
		} else if sevRank(f.C.Severity) > sevRank(c.Severity) {
			// one CVE rated differently on different hosts (the distribution's rating, NVD's): the highest, whatever
			// order the findings come in
			c.Severity, c.CVSS, c.Vector = f.C.Severity, f.C.CVSSScore, f.C.Vector
		}
		cveHosts[f.C.ID][f.Host] = true
	}
	for id, c := range cves {
		c.Hosts = len(cveHosts[id])
		d.CVEs = append(d.CVEs, *c)
	}
	epss := func(c CVE) float64 {
		if c.EPSS == nil {
			return 0
		}
		return *c.EPSS
	}
	slices.SortFunc(d.CVEs, func(a, b CVE) int {
		return cmp.Or(boolFirst(a.KEV, b.KEV), cmp.Compare(epss(b), epss(a)), cmp.Compare(sevRank(b.Severity), sevRank(a.Severity)),
			strings.Compare(a.ID, b.ID))
	})
	if len(d.CVEs) > MaxCVEs {
		d.More, d.CVEs = len(d.CVEs)-MaxCVEs, d.CVEs[:MaxCVEs:MaxCVEs]
	}
	// the texts of the ones listed only (the store's sets leave them out until asked)
	ps := make([]*fset.CVE, len(d.CVEs))
	for i, c := range d.CVEs {
		ps[i] = parts[c.ID]
	}
	if texts, err := fset.Descriptions(ps); err == nil {
		for i := range d.CVEs {
			d.CVEs[i].Description = texts[i]
		}
	}
	// where
	byGroup := map[string]*Where{}
	seen := map[string]bool{}
	for _, f := range fs {
		w := byGroup[f.Group]
		if w == nil {
			w = &Where{Group: f.Group, Exposure: f.Exposure, States: map[string]int{}}
			byGroup[f.Group] = w
		}
		if !seen[f.Host] {
			seen[f.Host] = true
			w.Hosts = append(w.Hosts, f.Host)
			w.States[state(f)]++
		}
	}
	for _, w := range byGroup {
		slices.Sort(w.Hosts)
		w.OS = hosts.common(w.Hosts)
		d.Where = append(d.Where, *w)
	}
	slices.SortFunc(d.Where, func(a, b Where) int { return cmp.Or(len(b.Hosts)-len(a.Hosts), strings.Compare(a.Group, b.Group)) })
	// how: one command per OS family for package updates that can be installed
	if n.Kind == KindPkg && n.Fixed != "" && n.Path == "" {
		steps := map[string]*Step{}
		pkgs := map[string][]string{}
		var order []string
		for _, f := range fs {
			if !installable(f) || state(f) == finding.FixReboot {
				continue
			}
			fam := family(hosts.os(f.Host))
			if fam == "" {
				continue
			}
			s := steps[fam]
			if s == nil {
				s = &Step{}
				steps[fam] = s
				order = append(order, fam)
			}
			s.Reboot = s.Reboot || f.Kernel
			if !slices.Contains(s.Hosts, f.Host) {
				s.Hosts = append(s.Hosts, f.Host)
			}
			switch {
			case !pkgName(f.Pkg):
				if !slices.Contains(s.Unsafe, f.Pkg) {
					s.Unsafe = append(s.Unsafe, f.Pkg)
				}
			case !slices.Contains(pkgs[fam], f.Pkg):
				pkgs[fam] = append(pkgs[fam], f.Pkg)
			}
		}
		for _, fam := range order {
			s := steps[fam]
			slices.Sort(s.Hosts)
			s.OS = hosts.common(s.Hosts)
			slices.Sort(pkgs[fam])
			slices.Sort(s.Unsafe)
			if len(pkgs[fam]) > 0 {
				s.Command = command(fam, strings.Join(pkgs[fam], " ")) // every binary package of the source
			}
			d.Apply = append(d.Apply, *s)
		}
	}
	// the view's actions that cover it
	if view != nil {
		for i := range view.Actions {
			a := &view.Actions[i]
			if slices.ContainsFunc(fs, func(f *item) bool { return covers(a, f) }) {
				d.Actions = append(d.Actions, a.ID)
			}
		}
	}
	return d
}
