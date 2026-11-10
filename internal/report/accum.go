package report

import (
	"cmp"
	"hash/maphash"
	"maps"
	"slices"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// viewAcc adds findings up into what a view and summary.md show, one finding at a time. Package groups keep
// their CVE sets only until flushHost: fed one host at a time, it holds one host's sets, never an environment's.
// Fed everything before one flushHost, it gives what BuildView gave from a slice.
type viewAcc struct {
	counts     Counts
	tally      *Tally
	acc, bp    int
	gidx       map[groupKey]*Group
	gorder     []*Group
	plan       []planHost
	other      []finding.Finding
	exceptions []excRow
	excSlim    []map[string]any
	inventory  []map[string]any
	bpIdx      map[bpKey]int
	bpPending  []BackportedRow
	bpIDs      []map[string]bool
	backported []BackportedRow
}

type groupKey struct{ host, target, pkg string }
type bpKey struct{ host, pkg string }

// planHost: one host's package updates as rows, most urgent first.
type planHost struct {
	host string
	rows []PlanRow
}

// excRow: a finding with an exception, as summary.md lists it.
type excRow struct {
	host, id, pkg string
	ex            finding.Exception
}

const slimLimit = 5000

func newViewAcc() *viewAcc {
	return &viewAcc{tally: NewTally(), gidx: map[groupKey]*Group{}, bpIdx: map[bpKey]int{}}
}

// add counts one finding; f may be reused afterwards (what is kept is copied).
func (a *viewAcc) add(f *finding.Finding) {
	switch { // CountsOf
	case f.Backported:
		a.counts.Backported++
	case f.Accepted:
		a.counts.Accepted++
	default:
		switch f.PriorityOr() {
		case "P1":
			a.counts.P1++
		case "P2":
			a.counts.P2++
		case "P3":
			a.counts.P3++
		case "P4":
			a.counts.P4++
		case "accepted":
			a.counts.Accepted++
		case "backported":
			a.counts.Backported++
		}
	}
	switch { // TotalsOf
	case f.Backported:
		if Actionable(f) {
			a.bp++
		}
	case f.Accepted:
		a.acc++
	case Actionable(f):
		a.tally.Add(f)
	}
	if f.Kind == finding.Vuln && !f.Accepted && !f.Backported {
		a.group(f)
	}
	if (f.Kind == finding.Misconfig || f.Kind == finding.Exposure || f.Kind == finding.Health) && !f.Accepted {
		a.other = append(a.other, *f)
	}
	if f.Exception != nil {
		a.exceptions = append(a.exceptions, excRow{host: f.Host, id: f.ID, pkg: f.Pkg, ex: *f.Exception})
		if len(a.excSlim) < slimLimit {
			a.excSlim = append(a.excSlim, slim(f))
		}
	}
	if f.Kind == finding.Inventory && len(a.inventory) < slimLimit {
		a.inventory = append(a.inventory, slim(f))
	}
	if f.Backported {
		k := bpKey{f.Host, f.Pkg}
		j, ok := a.bpIdx[k]
		if !ok {
			j = len(a.bpPending)
			a.bpIdx[k] = j
			a.bpPending = append(a.bpPending, BackportedRow{Host: f.Host, Pkg: f.Pkg, Installed: f.Installed})
			a.bpIDs = append(a.bpIDs, map[string]bool{})
		}
		a.bpIDs[j][f.ID] = true
	}
}

// group: PatchPlan's grouping of a vulnerability.
func (a *viewAcc) group(f *finding.Finding) {
	k := groupKey{f.Host, f.Target, f.Pkg}
	g := a.gidx[k]
	if g == nil {
		g = &Group{Host: f.Host, Target: f.Target, Pkg: f.Pkg, Installed: f.Installed, Fixed: map[string]bool{},
			CVEs: map[string]bool{}}
		a.gidx[k] = g
		a.gorder = append(a.gorder, g)
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

// flushHost turns the groups and backported sets gathered so far into rows and drops the sets.
func (a *viewAcc) flushHost() {
	for _, h := range planOf(a.gorder) {
		rows := make([]PlanRow, len(h.Groups))
		for i, g := range h.Groups {
			rows[i] = planRow(h.Host, g)
		}
		a.plan = append(a.plan, planHost{host: h.Host, rows: rows})
	}
	clear(a.gidx)
	a.gorder = nil
	for j := range a.bpPending {
		a.bpPending[j].CVEs = len(a.bpIDs[j])
		a.bpPending[j].IDs = topIDs(a.bpIDs[j], 8)
	}
	a.backported = append(a.backported, a.bpPending...)
	a.bpPending, a.bpIDs = nil, nil
	clear(a.bpIdx)
}

// planOf: groups by host in the order their first package came, most urgent first.
func planOf(order []*Group) Plan {
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

func (a *viewAcc) rows() []PlanRow {
	rows := []PlanRow{}
	for _, h := range a.plan {
		rows = append(rows, h.rows...)
	}
	return rows
}

func (a *viewAcc) totals() Totals {
	c := a.tally.Totals()
	c.Accepted, c.Backported = a.acc, a.bp
	return c
}

func (a *viewAcc) otherPtrs() []*finding.Finding {
	out := make([]*finding.Finding, len(a.other))
	for i := range a.other {
		out[i] = &a.other[i]
	}
	return out
}

// planCounts: PlanCountsOf over rows.
func planCounts(rows []PlanRow) PlanCounts {
	var c PlanCounts
	for _, r := range rows {
		switch deref(r.Priority) {
		case "P1":
			c.P1++
		case "P2":
			c.P2++
		case "P3":
			c.P3++
		case "P4":
			c.P4++
		case "cves":
			c.CVEs++
		}
		c.CVEs += r.CVEs
	}
	return c
}

// view: the View of what was added (flushHost called), diff the comparison with the previous run (nil: none).
func (a *viewAcc) view(runDir string, meta *Meta, d *diffAcc) *View {
	rows := a.rows()
	hosts := map[string]*HostCounts{}
	hc := func(h string) *HostCounts {
		if hosts[h] == nil {
			hosts[h] = &HostCounts{}
		}
		return hosts[h]
	}
	for _, r := range rows {
		c := hc(r.Host)
		c.add(deref(r.Priority))
		c.CVEs += r.CVEs
	}
	other := a.otherPtrs()
	for _, f := range other {
		if slices.Contains(Prios, f.PriorityOr()) {
			hc(f.Host).add(f.PriorityOr())
		}
	}
	fc := facts(runDir, meta.HostsScanned)
	otherSlim := []map[string]any{}
	for _, f := range other[:min(slimLimit, len(other))] {
		otherSlim = append(otherSlim, slim(f))
	}
	bp := sortBackported(slices.Clone(a.backported))
	v := &View{
		Version: ViewVersion, Meta: meta, Counts: a.counts, PlanCounts: planCounts(rows), Totals: a.totals(),
		Hosts: hosts, Facts: fc, Actions: BuildActions(rows, other, fc),
		Health: hostJSON(runDir, meta.HostsScanned, "health.json"), Access: accessView(runDir, meta.HostsScanned),
		Exposure:   exposureView(runDir, meta.HostsScanned),
		Plan:       rows,
		Other:      otherSlim,
		Exceptions: limit(a.excSlim, slimLimit),
		Inventory:  limit(a.inventory, slimLimit),
		Backported: limit(bp, 3000),
	}
	if d != nil {
		v.Prev = &d.prevID
		v.New = d.set(d.newN, d.newRows)
		v.Resolved = d.set(d.goneN, d.goneRows)
	}
	return v
}

// --- the comparison with the previous run --------------------------------------------------------------------------

// diffAcc compares a run with the previous one a host at a time. It holds a 64-bit hash of every key of the
// host in both runs (a collision among a host's keys: about one chance in 10^9 for 200k of them) and the items of
// what changed, which leave as DiffRows when the host is done.
type diffAcc struct {
	prevID            string
	prevDir, host     string
	prev, now         map[uint64]struct{}
	fresh             map[uint64]*diffItem
	newN, goneN       int
	newRows, goneRows []DiffRow
}

// diffItem: what DiffRows need of a finding.
type diffItem struct {
	key                   Key
	host, target, pkg, id string
	kind, title           string
	prio                  *string
	kev, rce              bool
}

func itemOf(f *finding.Finding) *diffItem {
	return &diffItem{key: KeyOf(f), host: f.Host, target: f.Target, pkg: f.Pkg, id: f.ID, kind: f.Kind, title: f.Title,
		prio: f.Priority, kev: f.KEV, rce: f.Preauth && f.RCE}
}

var keySeed = maphash.MakeSeed()

func keyHash(f *finding.Finding) uint64 { return maphash.Comparable(keySeed, KeyOf(f)) }

// startHost reads the keys of one host's findings in the previous run.
func (d *diffAcc) startHost(prevDir, host string) error {
	d.prevDir, d.host = prevDir, host
	d.prev, d.now, d.fresh = map[uint64]struct{}{}, map[uint64]struct{}{}, map[uint64]*diffItem{}
	return eachHostFinding(prevDir, host, func(f *finding.Finding) {
		if diffable(f, nil) {
			d.prev[keyHash(f)] = struct{}{}
		}
	})
}

// cur: a finding of the host in the run compared.
func (d *diffAcc) cur(f *finding.Finding) {
	if !diffable(f, nil) {
		return
	}
	h := keyHash(f)
	d.now[h] = struct{}{}
	if _, ok := d.prev[h]; !ok {
		d.fresh[h] = itemOf(f) // the last one wins, as in Diff
	}
}

// endHost: what is new on the host, and what is gone (the previous run read again for it), as rows.
func (d *diffAcc) endHost() error {
	gone := map[uint64]*diffItem{}
	err := eachHostFinding(d.prevDir, d.host, func(f *finding.Finding) {
		if diffable(f, nil) {
			if h := keyHash(f); !has(d.now, h) {
				gone[h] = itemOf(f)
			}
		}
	})
	if err != nil {
		return err
	}
	d.newN += len(d.fresh)
	d.goneN += len(gone)
	d.newRows = append(d.newRows, itemRows(slices.Collect(maps.Values(d.fresh)))...)
	d.goneRows = append(d.goneRows, itemRows(slices.Collect(maps.Values(gone)))...)
	d.prev, d.now, d.fresh = nil, nil, nil
	return nil
}

func has(m map[uint64]struct{}, h uint64) bool { _, ok := m[h]; return ok }

func (d *diffAcc) set(total int, rows []DiffRow) *DiffSet {
	sortDiffRows(rows)
	return &DiffSet{Total: total, Rows: limit(rows, 3000)}
}

// itemRows: diffRows of items: grouped by package, the top 8 ids kept.
func itemRows(items []*diffItem) []DiffRow {
	slices.SortFunc(items, func(x, y *diffItem) int { // sortDiff's order: a group takes its first item's title
		return cmp.Or(cmp.Compare(prioRank(deref(x.prio)), prioRank(deref(y.prio))), cmp.Compare(x.host, y.host),
			cmp.Compare(x.pkg, y.pkg), cmp.Compare(x.id, y.id), slices.Compare(x.key[:], y.key[:]))
	})
	type gk struct{ host, target, pkg string }
	idx := map[gk]int{}
	rows := []DiffRow{}
	for _, f := range items {
		pkg := f.pkg
		if pkg == "" {
			pkg = f.id
		}
		k := gk{f.host, f.target, pkg}
		j, ok := idx[k]
		if !ok {
			j = len(rows)
			idx[k] = j
			rows = append(rows, DiffRow{Host: f.host, Target: f.target, Pkg: pkg, Kind: f.kind, Title: f.title})
		}
		g := &rows[j]
		g.IDs = append(g.IDs, f.id)
		g.KEV = g.KEV || f.kev
		if f.rce {
			g.RCE++
		}
		if prioRank(deref(f.prio)) < rankPtr(g.Priority) {
			g.Priority = f.prio
		}
	}
	for i := range rows {
		g := &rows[i]
		g.Count = len(g.IDs)
		slices.Sort(g.IDs)
		slices.Reverse(g.IDs)
		g.IDs = slices.Clip(g.IDs[:min(8, len(g.IDs))])
	}
	return rows
}

func sortDiffRows(rows []DiffRow) {
	slices.SortStableFunc(rows, func(a, b DiffRow) int {
		return cmp.Or(cmp.Compare(rankPtr(a.Priority), rankPtr(b.Priority)), cmp.Compare(b.Count, a.Count),
			cmp.Compare(a.Host, b.Host), cmp.Compare(a.Pkg, b.Pkg))
	})
}

// diffRows: a diff aggregated by package, so a kernel with 15k CVEs is one row, not 15k.
func diffRows(items []finding.Finding) []DiffRow {
	its := make([]*diffItem, len(items))
	for i := range items {
		its[i] = itemOf(&items[i])
	}
	rows := itemRows(its)
	sortDiffRows(rows)
	return rows
}

// sortBackported: by host, most CVEs first.
func sortBackported(rows []BackportedRow) []BackportedRow {
	slices.SortStableFunc(rows, func(a, b BackportedRow) int {
		return cmp.Or(cmp.Compare(a.Host, b.Host), cmp.Compare(b.CVEs, a.CVEs), cmp.Compare(a.Pkg, b.Pkg))
	})
	if rows == nil {
		rows = []BackportedRow{}
	}
	return rows
}

// backported: the backported rows of findings.
func backported(findings []finding.Finding) []BackportedRow {
	a := newViewAcc()
	for i := range findings {
		a.add(&findings[i])
	}
	a.flushHost()
	return sortBackported(a.backported)
}
