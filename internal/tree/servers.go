package tree

import (
	"cmp"
	"iter"
	"slices"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/onboard"
	"github.com/mikekosulin/kanareika/internal/report"
)

// Host states in the server view (Opts.All).
const (
	StateTodo       = "todo"        // scanned, something to do
	StateClean      = "clean"       // scanned, nothing to do
	StatePartial    = "partial"     // scanned, but some checks were not possible (no root, a module failed)
	StateFailed     = "failed"      // the last scan did not reach it (older data, if any, is still shown)
	StateNotScanned = "not_scanned" // in the org file, never scanned
)

// HostInfo: what the server view knows about a host of the env besides its findings.
type HostInfo struct {
	Name, Group string
	Exposure    int
	State       string    // failed, not_scanned, partial; "" when the last scan read everything
	Problem     i18n.Text // why, in plain words
	LastScan    string    // when its data was collected (RFC 3339, UTC); "" when never
}

// Servers: every host of org's env, with the state of its last scan, from the view and the findings the tree is
// built from (current/ or a run: Set.All, slices.Values of pointers).
func Servers(org *config.Org, env string, view *report.View, findings iter.Seq[*finding.Finding]) []HostInfo {
	var meta *report.Meta
	if view != nil {
		meta = view.Meta
	}
	if meta == nil {
		meta = &report.Meta{}
	}
	limited := map[string][]string{} // host -> denied keys (from the *-limited findings)
	why := map[string]i18n.Text{}
	for f := range findings {
		if f.Kind != finding.Inventory || !strings.HasSuffix(f.ID, "-limited") {
			continue
		}
		for _, k := range keysOf(f.Args["what_keys"]) {
			if !slices.Contains(limited[f.Host], k) {
				limited[f.Host] = append(limited[f.Host], k)
			}
		}
		if _, ok := why[f.Host]; !ok && f.Target != "" {
			why[f.Host] = i18n.Text{Text: f.Target, Key: f.TargetMsg, Args: f.TargetArgs}
		}
	}
	scanned := map[string]bool{}
	for _, h := range meta.HostsScanned {
		scanned[h] = true
	}
	var out []HostInfo
	for _, h := range org.Hosts {
		if h.Env != env {
			continue
		}
		hi := HostInfo{Name: h.Name, Group: h.Group, Exposure: h.Exposure, LastScan: lastScan(meta, h.Name)}
		reason, failed := meta.HostsFailed.Get(h.Name)
		errs, _ := meta.ModuleErrors.Get(h.Name)
		switch {
		case failed:
			hi.State = StateFailed
			hint := onboard.Hint(reason)
			if hint == "" {
				hint = reason
			} else {
				hint += " (" + reason + ")"
			}
			hi.Problem = i18n.Msg("host.failed", map[string]any{"why": hint})
		case !scanned[h.Name]:
			hi.State, hi.Problem = StateNotScanned, i18n.Msg("host.not_scanned", nil)
		case len(limited[h.Name]) > 0:
			hi.State = StatePartial
			t := i18n.Msg("denied.title", map[string]any{"what_keys": limited[h.Name]})
			if w, ok := why[h.Name]; ok {
				t = i18n.Msg("host.partial", map[string]any{"what_keys": limited[h.Name], "why": w.Text})
			}
			hi.Problem = t
		case len(errs) > 0:
			hi.State = StatePartial
			hi.Problem = i18n.Msg("host.module_errors", map[string]any{"errors": strings.Join(errs, "; ")})
		}
		out = append(out, hi)
	}
	return out
}

func keysOf(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		var out []string
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// lastScan: when the host's data was collected — the newest run it comes from (current/), or the run itself.
func lastScan(meta *report.Meta, host string) string {
	run := ""
	if src, ok := meta.Sources[host]; ok {
		for _, r := range src {
			run = max(run, r)
		}
	} else if slices.Contains(meta.HostsScanned, host) && !meta.HostsFailed.Has(host) {
		run = meta.RunID
	}
	t, err := time.Parse("2006-01-02_150405", run)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// servers: the by-host grouping with every host (Opts.All): one flat row per host, most urgent first, clean ones
// last. Host rows are counted from all their findings; the filters and the query narrow what is under them.
func servers(t *Tree, all []*item, kept []*item, hosts Hosts, o Opts) {
	allBy := map[string][]*item{}
	for _, f := range all {
		allBy[f.Host] = append(allBy[f.Host], f)
	}
	keptBy := map[string][]*item{}
	for _, f := range kept {
		keptBy[f.Host] = append(keptBy[f.Host], f)
	}
	q := strings.ToLower(strings.TrimSpace(o.Query))
	t.Servers = map[string]int{}
	seen := map[string]bool{}
	add := func(hi HostInfo) {
		seen[hi.Name] = true
		hf := allBy[hi.Name]
		if q != "" && len(keptBy[hi.Name]) == 0 && !strings.Contains(strings.ToLower(hi.Name+" "+hi.Group), q) {
			return
		}
		n := &Node{ID: "h:" + hi.Name, Kind: KindHost, Label: hi.Name, OS: hosts.os(hi.Name), Exposure: hi.Exposure,
			LastScan: hi.LastScan}
		n.OSShort = ShortOS(n.OS)
		if len(hf) > 0 {
			fill(n, hf)
		} else {
			n.Priority, n.Hosts, n.Groups = "", 1, []Count{{hi.Group, 1}}
			n.HostList = []string{hi.Name}
		}
		tally := report.NewTally() // report.TotalsOf: backported findings (shown with Opts.Backported) are not counted
		for _, f := range hf {
			if !f.Backported {
				tally.AddParts(f.U.Key, f.PriorityOr(), f.Installable(), f.Kind == finding.Vuln, f.C.ID, f.Host)
			}
		}
		tot := tally.Totals()
		n.Fixes, n.Counts = tot.Fixes, tot.ByPriority()
		n.Overdue = n.Due != "" && o.Today != "" && n.Due < o.Today
		n.State = hi.State
		if n.State == "" {
			n.State = StateClean
			if len(hf) > 0 {
				n.State = StateTodo
			}
		}
		n.Problem, n.ProblemMsg, n.ProblemArgs = hi.Problem.Text, hi.Problem.Key, hi.Problem.Args
		if kf := keptBy[hi.Name]; len(kf) > 0 {
			n.lz = units(n.ID, kf, hosts)
		}
		t.Servers[n.State]++
		t.Nodes = append(t.Nodes, n)
	}
	for _, hi := range o.Inventory {
		add(hi)
	}
	for _, h := range slices.Sorted(func(yield func(string) bool) { // findings of hosts not in the org file (any more)
		for h := range allBy {
			if !seen[h] && !yield(h) {
				return
			}
		}
	}) {
		f := allBy[h][0]
		add(HostInfo{Name: h, Group: f.Group, Exposure: f.Exposure})
	}
	stateRank := func(s string) int {
		if s == StateClean {
			return 1
		}
		return 0
	}
	slices.SortFunc(t.Nodes, func(a, b *Node) int {
		return cmp.Or(cmp.Compare(prioRank(a.Priority), prioRank(b.Priority)), boolFirst(a.Overdue, b.Overdue),
			cmp.Compare(stateRank(a.State), stateRank(b.State)), strings.Compare(a.Label, b.Label))
	})
}
