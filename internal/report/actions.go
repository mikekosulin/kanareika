package report

import (
	"cmp"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

// PlanRow is one package update in the view (Group flattened, sets reduced to counts and the top CVEs).
type PlanRow struct {
	Host        string   `json:"host"`
	Target      string   `json:"target"`
	Pkg         string   `json:"pkg"`
	Installed   string   `json:"installed"`
	Fixed       string   `json:"fixed"` // the highest fixed version, "" when no CVE has a fix
	FixedN      int      `json:"fixed_n"`
	CVEs        int      `json:"cves"`
	CVETop      []string `json:"cve_top"`
	Unfixed     int      `json:"unfixed"`
	Priority    *string  `json:"priority"`
	Due         *string  `json:"due"`
	KEV         bool     `json:"kev"`
	Inactive    bool     `json:"inactive"`
	Kernel      bool     `json:"kernel"`
	Module      string   `json:"module"`
	Preauth     int      `json:"preauth"`
	PreauthRCE  int      `json:"preauth_rce"`
	FixState    *string  `json:"fix_state"`
	RepoVersion *string  `json:"repo_version"`
	Pending     bool     `json:"pending"`
}

func planRow(host string, g *Group) PlanRow {
	fixed := sortedVersions(g.Fixed)
	r := PlanRow{Host: host, Target: g.Target, Pkg: g.Pkg, Installed: g.Installed, FixedN: len(fixed), CVEs: len(g.CVEs),
		CVETop: topIDs(g.CVEs), Unfixed: g.Unfixed, Priority: g.Priority, Due: g.Due, KEV: g.KEV,
		Inactive: g.Inactive, Kernel: g.Kernel, Module: g.Module, Preauth: g.Preauth, PreauthRCE: g.PreauthRCE,
		FixState: g.FixState, RepoVersion: g.RepoVersion, Pending: g.Pending}
	if len(fixed) > 0 {
		r.Fixed = fixed[len(fixed)-1]
	}
	return r
}

// PlanRows flattens a plan in host order, as the view lists it.
func PlanRows(plan Plan) []PlanRow {
	rows := []PlanRow{}
	for _, h := range plan {
		for _, g := range h.Groups {
			rows = append(rows, planRow(h.Host, g))
		}
	}
	return rows
}

// Action is one line of the to-do list: one thing to do, on one or more hosts. Which optional fields are set
// depends on the category, as in the Python version (the dashboard and MCP test for their presence).
type Action struct {
	ID       string         `json:"id"`  // stable: the same problem on the same hosts keeps its id between runs
	Cat      string         `json:"cat"` // kernel, os, vendor, cleanup, image, app, config, exposure, health, eol
	Priority *string        `json:"priority"`
	Due      *string        `json:"due"`
	Hosts    []string       `json:"hosts"`
	Title    string         `json:"title"`
	Msg      string         `json:"msg,omitempty"`
	Args     map[string]any `json:"args,omitzero"` // nil: absent; {}: present and empty
	Image    *string        `json:"image,omitempty"`
	Path     *string        `json:"path,omitempty"`
	Target   *string        `json:"target,omitempty"`
	Detail   string         `json:"detail"`
	// config / exposure / health: each host's detail keeps its own message key, so the UI can localize the parts
	DetailParts []DetailPart   `json:"detail_parts,omitzero"`
	KEV         bool           `json:"kev"`
	CVEs        int            `json:"cves"`
	RCE         *int           `json:"rce,omitempty"`
	Packages    []Package      `json:"packages,omitzero"`
	Hint        string         `json:"hint"`
	HintMsg     string         `json:"hint_msg,omitempty"`
	HintArgs    map[string]any `json:"hint_args,omitzero"`
}

type DetailPart struct {
	Host     string         `json:"host"`
	Text     string         `json:"text"`
	TextMsg  string         `json:"text_msg,omitempty"`
	TextArgs map[string]any `json:"text_args,omitzero"`
}

// Package: a row of the action's expandable table (one row per package, the worst instance).
type Package struct {
	Pkg         string  `json:"pkg"`
	Installed   string  `json:"installed"`
	Fixed       string  `json:"fixed"`
	CVEs        int     `json:"cves"`
	Priority    *string `json:"priority"`
	KEV         bool    `json:"kev"`
	RCE         int     `json:"rce"`
	FixState    string  `json:"fix_state,omitempty"`
	RepoVersion string  `json:"repo_version,omitempty"`
}

// Fact: what the view shows about a host's system.
type Fact struct {
	OS     *string  `json:"os"`
	Kernel []string `json:"kernel"` // [] or [release]
}

func (a *Action) setTitle(t i18n.Text) { a.Title, a.Msg, a.Args = t.Text, t.Key, t.Args }

func (a *Action) setHint(t i18n.Text) { a.Hint, a.HintMsg, a.HintArgs = t.Text, t.Key, t.Args }

func best[T any](rows []T, prio func(T) *string) *string {
	var out *string
	for _, r := range rows {
		if p := prio(r); deref(p) != "" && (out == nil || prioRank(*p) < prioRank(*out)) {
			out = p
		}
	}
	return out
}

func minDue[T any](rows []T, due func(T) *string) *string {
	var out *string
	for _, r := range rows {
		if d := due(r); deref(d) != "" && (out == nil || *d < *out) {
			out = d
		}
	}
	return out
}

func rowPrio(r PlanRow) *string { return r.Priority }
func rowDue(r PlanRow) *string  { return r.Due }

var rhelLike = []string{"CentOS", "Red Hat", "Rocky", "Alma", "Oracle", "Amazon", "Fedora"}

func osHint(osName *string, what string) i18n.Text {
	key := map[string]string{"kernel": "hint.kernel", "old-kernels": "hint.old_kernels"}[what]
	if key == "" {
		key = "hint.os"
	}
	rhel := slices.ContainsFunc(rhelLike, func(x string) bool { return strings.Contains(deref(osName), x) })
	if rhel {
		key += ".rpm"
	} else {
		key += ".deb"
	}
	return i18n.Msg(key, nil)
}

func byUrgency(rows []PlanRow) []PlanRow {
	out := slices.Clone(rows)
	slices.SortStableFunc(out, func(a, b PlanRow) int {
		return cmp.Or(cmp.Compare(rankPtr(a.Priority), rankPtr(b.Priority)), cmp.Compare(b.CVEs, a.CVEs))
	})
	return out
}

func pkgs(rows []PlanRow) []Package {
	out := []Package{}
	seen := map[string]bool{}
	for _, r := range byUrgency(rows) {
		if seen[r.Pkg] {
			continue
		}
		seen[r.Pkg] = true
		out = append(out, Package{Pkg: r.Pkg, Installed: r.Installed, Fixed: r.Fixed, CVEs: r.CVEs, Priority: r.Priority,
			KEV: r.KEV, RCE: r.PreauthRCE, FixState: deref(r.FixState), RepoVersion: deref(r.RepoVersion)})
	}
	return out[:min(300, len(out))]
}

func isKernelPkg(p string) bool {
	return slices.Contains(kernelPkgs, p) || strings.HasPrefix(p, "linux-image-")
}

func anyKEV(rows []PlanRow) bool {
	return slices.ContainsFunc(rows, func(r PlanRow) bool { return r.KEV })
}

func sumOf(rows []PlanRow, v func(PlanRow) int) int {
	n := 0
	for _, r := range rows {
		n += v(r)
	}
	return n
}

func maxOf(rows []PlanRow, v func(PlanRow) int) int {
	n := v(rows[0])
	for _, r := range rows[1:] {
		n = max(n, v(r))
	}
	return n
}

func cvesOf(r PlanRow) int { return r.CVEs }
func rceOf(r PlanRow) int  { return r.PreauthRCE }

func sortedHosts(rows []PlanRow) []string {
	set := map[string]bool{}
	for _, r := range rows {
		set[r.Host] = true
	}
	return sortedKeys(set)
}

// ordered groups rows by a key, keeping the order keys first appeared in (Python's defaultdict).
type ordered[K comparable, V any] struct {
	keys []K
	m    map[K][]V
}

func (o *ordered[K, V]) add(k K, v V) {
	if o.m == nil {
		o.m = map[K][]V{}
	}
	if _, ok := o.m[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.m[k] = append(o.m[k], v)
}

func pkgList(rows []PlanRow) string {
	const n = 6 // packages named in an action's detail; the rest is "…"
	parts := make([]string, 0, n)
	for _, r := range rows[:min(n, len(rows))] {
		parts = append(parts, r.Pkg+" → "+r.Fixed)
	}
	return strings.Join(parts, ", ")
}

var protoSuffix = regexp.MustCompile(`-(tcp|udp)`)

// BuildActions turns packages and findings into a to-do list: one line = one thing to do, on one or more hosts.
func BuildActions(planRows []PlanRow, other []*finding.Finding, facts map[string]Fact) []Action {
	acts := []Action{}
	var fixable []PlanRow
	for _, r := range planRows {
		if r.Fixed != "" {
			fixable = append(fixable, r)
		}
	}
	osOf := func(h string) *string { return facts[h].OS }

	// 1. running kernel: group hosts with the same installed -> fixed. A newer kernel already installed
	// (fix_state reboot) is a reboot, not an update; a fix missing from the repositories goes to step 2b
	var kern []PlanRow
	for _, r := range fixable {
		if r.Kernel && deref(r.FixState) != finding.FixVendor {
			kern = append(kern, r)
		}
	}
	type kk struct {
		inst, fixed string
		reboot      bool
	}
	var byKernel ordered[kk, PlanRow]
	for _, r := range kern {
		if isKernelPkg(r.Pkg) {
			reboot := deref(r.FixState) == finding.FixReboot
			fixed := r.Fixed
			if reboot {
				fixed = pyOpt(r.RepoVersion)
			}
			byKernel.add(kk{r.Installed, fixed, reboot}, r)
		}
	}
	for _, k := range byKernel.keys {
		rows := byKernel.m[k]
		hosts := sortedHosts(rows)
		var allk []PlanRow
		for _, r := range kern {
			if slices.Contains(hosts, r.Host) && (deref(r.FixState) == finding.FixReboot) == k.reboot {
				allk = append(allk, r)
			}
		}
		a := Action{Cat: "kernel", Priority: best(allk, rowPrio), Due: minDue(allk, rowDue), Hosts: hosts,
			Detail: k.inst + " → " + k.fixed, KEV: anyKEV(allk), CVEs: maxOf(rows, cvesOf), RCE: ptr(maxOf(rows, rceOf)),
			Packages: pkgs(allk)}
		if k.reboot {
			a.setTitle(i18n.Msg("act.reboot", nil))
			a.setHint(i18n.Msg("hint.reboot", nil))
		} else {
			a.setTitle(i18n.Msg("act.kernel", nil))
			a.setHint(osHint(osOf(hosts[0]), "kernel"))
		}
		acts = append(acts, a)
	}

	// 2. OS packages per host (everything fixable in the OS except the kernel)
	var perHost, waiting ordered[string, PlanRow]
	for _, r := range fixable {
		if r.Target != "os" {
			continue
		}
		if deref(r.FixState) == finding.FixVendor {
			waiting.add(r.Host, r)
		} else if !r.Kernel {
			perHost.add(r.Host, r)
		}
	}
	more := func(n int) string {
		if n > 6 {
			return " …"
		}
		return ""
	}
	for _, h := range perHost.keys {
		rows := perHost.m[h]
		a := Action{Cat: "os", Priority: best(rows, rowPrio), Due: minDue(rows, rowDue), Hosts: []string{h},
			Detail: pkgList(byUrgency(rows)) + more(len(rows)), KEV: anyKEV(rows), CVEs: sumOf(rows, cvesOf),
			RCE: ptr(sumOf(rows, rceOf)), Packages: pkgs(rows)}
		a.setTitle(i18n.Msg("act.os", map[string]any{"n": len(rows)}))
		a.setHint(osHint(osOf(h), "os"))
		acts = append(acts, a)
	}

	// 2b. fixed in the advisory, but the host's repositories have nothing to install yet
	for _, h := range waiting.keys {
		rows := waiting.m[h]
		a := Action{Cat: "vendor", Priority: best(rows, rowPrio), Due: minDue(rows, rowDue), Hosts: []string{h},
			Detail: pkgList(byUrgency(rows)) + more(len(rows)), KEV: anyKEV(rows), CVEs: sumOf(rows, cvesOf),
			RCE: ptr(sumOf(rows, rceOf)), Packages: pkgs(rows)}
		a.setTitle(i18n.Msg("act.vendor", map[string]any{"n": len(rows)}))
		a.setHint(i18n.Msg("hint.vendor", nil))
		acts = append(acts, a)
	}

	// 3. old kernels
	old := map[string]map[string]bool{}
	for _, r := range planRows {
		if r.Inactive && !r.Pending && isKernelPkg(r.Pkg) {
			if old[r.Host] == nil {
				old[r.Host] = map[string]bool{}
			}
			old[r.Host][r.Installed] = true
		}
	}
	if len(old) > 0 {
		hosts := make([]string, 0, len(old))
		for h := range old {
			hosts = append(hosts, h)
		}
		slices.Sort(hosts)
		parts := make([]string, len(hosts))
		for i, h := range hosts {
			parts[i] = fmt.Sprintf("%s: %d", h, len(old[h]))
		}
		a := Action{Cat: "cleanup", Priority: ptr("P4"), Hosts: hosts, Detail: strings.Join(parts, "; ")}
		a.setTitle(i18n.Msg("act.old_kernels", nil))
		a.setHint(osHint(osOf(hosts[0]), "old-kernels"))
		acts = append(acts, a)
	}

	// 4. container images: one action per image across hosts
	var images ordered[string, PlanRow]
	for _, r := range fixable {
		if strings.HasPrefix(r.Target, "image:") {
			images.add(r.Target, r)
		}
	}
	for _, target := range images.keys {
		rows := images.m[target]
		var first []PlanRow // the worst row of each package, in urgency order
		seen := map[string]bool{}
		for _, r := range byUrgency(rows) {
			if !seen[r.Pkg] {
				seen[r.Pkg] = true
				first = append(first, r)
			}
		}
		name, _, _ := strings.Cut(target[len("image:"):], "@")
		short := name[strings.LastIndex(name, "/")+1:]
		a := Action{Cat: "image", Priority: best(rows, rowPrio), Due: minDue(rows, rowDue), Hosts: sortedHosts(rows),
			Image: ptr(name), Detail: pkgList(first) + more(len(first)), KEV: anyKEV(rows), CVEs: maxOf(rows, cvesOf),
			Target: ptr(target), RCE: ptr(sumOf(first, rceOf)), Packages: pkgs(rows)}
		a.setTitle(i18n.Msg("act.image", map[string]any{"name": short, "n": len(first)}))
		acts = append(acts, a)
	}

	// 5. application dependencies found on disk
	type ht struct{ host, target string }
	var apps ordered[ht, PlanRow]
	for _, r := range fixable {
		if r.Module == "software_fs" {
			apps.add(ht{r.Host, r.Target}, r)
		}
	}
	for _, k := range apps.keys {
		rows := apps.m[k]
		a := Action{Cat: "app", Priority: best(rows, rowPrio), Due: minDue(rows, rowDue), Hosts: []string{k.host},
			Path: ptr(k.target), Detail: pkgList(rows), KEV: anyKEV(rows), CVEs: sumOf(rows, cvesOf),
			RCE: ptr(sumOf(rows, rceOf)), Packages: pkgs(rows)}
		a.setTitle(i18n.Msg("act.app", map[string]any{"n": len(rows)}))
		acts = append(acts, a)
	}

	// 6. configuration / exposure / health findings, grouped by what they say
	type it struct{ id, title string }
	var groups ordered[it, *finding.Finding]
	for _, f := range other { // same id + same wording = one action on several hosts (tcp+udp of a port merge too)
		groups.add(it{protoSuffix.ReplaceAllString(f.ID, ""), f.Title}, f)
	}
	cats := map[string]string{finding.Misconfig: "config", finding.Exposure: "exposure", finding.Health: "health"}
	fprio := func(f *finding.Finding) *string { return f.Priority }
	fdue := func(f *finding.Finding) *string { return f.Due }
	for _, k := range groups.keys {
		fs := groups.m[k]
		cat := cats[fs[0].Kind]
		if cat == "" {
			cat = "config"
		}
		if k.id == "os-eol" {
			cat = "eol"
		}
		hostSet, targets := map[string]bool{}, map[string]bool{}
		parts := []DetailPart{}
		for _, f := range fs {
			hostSet[f.Host] = true
			if f.Target != "" {
				targets[f.Target] = true
				p := DetailPart{Host: f.Host, Text: f.Target}
				if f.TargetMsg != "" {
					p.TextMsg, p.TextArgs = f.TargetMsg, f.TargetArgs
					if p.TextArgs == nil {
						p.TextArgs = map[string]any{}
					}
				}
				parts = append(parts, p)
			}
		}
		args := fs[0].Args
		if args == nil && fs[0].Msg != "" { // msg() always stores args; finding.Finding drops an empty {} on write
			args = map[string]any{}
		}
		a := Action{Cat: cat, Priority: best(fs, fprio), Due: minDue(fs, fdue), Hosts: sortedKeys(hostSet), Title: k.title,
			Msg: fs[0].Msg, Args: args, Detail: pyfmt.Head(strings.Join(sortedKeys(targets), "; "), 400),
			DetailParts: parts[:min(50, len(parts))]}
		acts = append(acts, a)
	}

	slices.SortStableFunc(acts, func(a, b Action) int {
		return cmp.Or(cmp.Compare(rankPtr(a.Priority), rankPtr(b.Priority)), cmpBool(!a.KEV, !b.KEV),
			cmpBool(a.RCE == nil || *a.RCE == 0, b.RCE == nil || *b.RCE == 0), cmp.Compare(len(b.Hosts), len(a.Hosts)),
			cmp.Compare(b.CVEs, a.CVEs))
	})
	for i := range acts {
		a := &acts[i]
		where := ""
		if a.Image != nil && *a.Image != "" {
			where = *a.Image
		} else if a.Path != nil {
			where = *a.Path
		}
		sum := sha1.Sum([]byte(strings.Join([]string{a.Cat, a.Title, where, strings.Join(a.Hosts, ",")}, "|")))
		a.ID = hex.EncodeToString(sum[:])[:10]
	}
	return acts
}

func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	}
	return 1
}

// topN: how many CVE ids an action names (the rest are counted).
const topN = 8

// topIDs: the topN greatest ids of set, greatest first (the newest CVEs), without sorting the set.
func topIDs(set map[string]bool) []string {
	const n = topN
	top := make([]string, 0, n+1)
	for id := range set {
		if len(top) == n && id <= top[n-1] {
			continue
		}
		i, _ := slices.BinarySearchFunc(top, id, func(a, b string) int { return strings.Compare(b, a) })
		top = slices.Insert(top, i, id)
		if len(top) > n {
			top = top[:n]
		}
	}
	return slices.Clip(top)
}
