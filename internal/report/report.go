// Package report stores runs (reports/<org>/<env>/<run>/), builds what the dashboard shows (view.json), the
// patch-plan summary (summary.md), history and diffs between runs, and the merged current state (current/).
//
// The files are shared with the Python implementation and with runs written by earlier versions: same keys, same
// nesting, same list order.
package report

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

// Current is reports/<org>/<env>/current: the merged latest state per host and module.
const Current = "current"

func EnvDir(p config.Paths, org, env string) string { return filepath.Join(p.Reports, org, env) }

// Busy: another process holds the environment's lock (a scan is running).
type Busy struct{ Env string }

func (e *Busy) Error() string { return "a scan is already running in " + e.Env }

// Lock is a flock on reports/<org>/<env>/.lock: one scan per environment, and the current-state merge never
// races a scan (the dashboard waits; a second scan refuses).
type Lock struct{ f *os.File }

// flock, rename and policy are seams for tests: failures that real files cannot produce.
var (
	flock  = lockFile
	rename = os.Rename
	policy = config.Policy
)

// EnvLock takes the lock; wait=false returns *Busy instead of blocking.
func EnvLock(env string, wait bool) (*Lock, error) {
	if err := os.MkdirAll(env, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(env, ".lock"), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	busy, err := flock(f, wait)
	if err != nil || busy {
		f.Close()
		if busy {
			return nil, &Busy{Env: env}
		}
		return nil, err
	}
	return &Lock{f: f}, nil
}

func (l *Lock) Unlock() error {
	_ = unlockFile(l.f)
	return l.f.Close()
}

// runDirs: finished runs (with run.json) in env, oldest first; current/ is not a run.
func runDirs(env string) []string {
	ents, err := os.ReadDir(env)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents { // ReadDir sorts by name, as Python's sorted(iterdir())
		if e.IsDir() && e.Name() != Current && exists(filepath.Join(env, e.Name(), "run.json")) {
			out = append(out, filepath.Join(env, e.Name()))
		}
	}
	return out
}

// Runs: run directories of an environment, oldest first.
func Runs(p config.Paths, org, env string) []string { return runDirs(EnvDir(p, org, env)) }

// LoadFindings reads every findings file of dir (see HostFiles), host after host; none = empty. It holds them
// all: a whole environment's findings are large, so what can go a host at a time uses EachFindingIn or
// EachFinding instead.
func LoadFindings(dir string) ([]finding.Finding, error) {
	hfs, err := HostFiles(dir)
	if err != nil {
		return nil, err
	}
	out := []finding.Finding{}
	for _, hf := range hfs {
		r, closeFn, err := openPath(hf.Path)
		if err != nil {
			return nil, err
		}
		fs, err := decodeFindings(r)
		closeFn()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", hf.Path, err)
		}
		out = append(out, fs...)
	}
	for i := range out {
		upgradeDenied(&out[i])
	}
	return out, nil
}

// EachFinding calls fn with every finding of dir (as LoadFindings reads them) without holding them all: f is
// reused, so fn copies what it keeps.
func EachFinding(dir string, fn func(f *finding.Finding)) error {
	hfs, err := HostFiles(dir)
	if err != nil {
		return err
	}
	for _, hf := range hfs {
		if err := EachFindingIn(hf.Path, fn); err != nil {
			return err
		}
	}
	return nil
}

// upgradeDenied: runs before 0.5 stored what a module could not read as raw keys in one text ("cannot read:
// denied.shadow, denied.keys (needs root or sudo)"); they read in plain words now, as new runs write them.
func upgradeDenied(f *finding.Finding) {
	what, ok := f.Args["what"].(string)
	if f.Msg != "health.limited" || !ok {
		return
	}
	var keys []string
	for _, k := range strings.Split(what, ", ") {
		if strings.HasPrefix(k, "denied.") {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return
	}
	t := i18n.Msg("denied.title", map[string]any{"what_keys": keys})
	f.Title, f.Msg, f.Args = t.Text, t.Key, t.Args
}

func LoadMeta(dir string) (*Meta, error) {
	b, err := os.ReadFile(filepath.Join(dir, "run.json"))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s/run.json: %w", dir, err)
	}
	return &m, nil
}

func LoadRun(dir string) (*Meta, []finding.Finding, error) {
	m, err := LoadMeta(dir)
	if err != nil {
		return nil, nil, err
	}
	fs, err := LoadFindings(dir)
	return m, fs, err
}

// IsPartial: a run limited to some hosts, groups or modules (statistics compare full runs only).
func IsPartial(m *Meta) bool {
	s := m.Selection
	return len(s.Hosts) > 0 || len(s.Groups) > 0 || len(s.Modules) > 0
}

func isPartialDir(dir string) (bool, error) {
	m, err := LoadMeta(dir)
	if err != nil {
		return false, err
	}
	return IsPartial(m), nil
}

// PreviousRun: the latest finished run before runDir (fullOnly: the latest full one); nil when there is none.
func PreviousRun(runDir string, fullOnly bool) (*Prev, error) {
	dir, err := PreviousRunDir(runDir, fullOnly)
	if dir == "" || err != nil {
		return nil, err
	}
	return loadPrev(dir)
}

// PreviousRunDir: the directory of the run PreviousRun loads; "" when there is none.
func PreviousRunDir(runDir string, fullOnly bool) (string, error) {
	var done []string
	for _, d := range runDirs(filepath.Dir(runDir)) {
		if filepath.Base(d) < filepath.Base(runDir) {
			done = append(done, d)
		}
	}
	if fullOnly {
		var full []string
		for _, d := range done {
			p, err := isPartialDir(d)
			if err != nil {
				return "", err
			}
			if !p {
				full = append(full, d)
			}
		}
		done = full
	}
	if len(done) == 0 {
		return "", nil
	}
	return done[len(done)-1], nil
}

func loadPrev(dir string) (*Prev, error) {
	m, fs, err := LoadRun(dir)
	if err != nil {
		return nil, err
	}
	return &Prev{ID: filepath.Base(dir), Meta: m, Findings: fs}, nil
}

// SaveRun writes a finished run from findings in memory: its host files, then what FinishRun writes.
func SaveRun(runDir string, meta *Meta, findings []finding.Finding) error {
	if _, err := os.Stat(runDir); err != nil { // a run directory is made by the scan; never one by accident
		return err
	}
	if err := writeFindings(runDir, findings); err != nil {
		return err
	}
	return FinishRun(runDir, meta)
}

// FinishRun completes a run whose host files are written (WriteHostFindings): run.json (with counts), view.json
// and summary.md, read one host at a time.
func FinishRun(runDir string, meta *Meta) error {
	prevDir := ""
	if !IsPartial(meta) { // statistics compare FULL runs only; a partial run has nothing comparable
		var err error
		if prevDir, err = PreviousRunDir(runDir, true); err != nil {
			return err
		}
	}
	view, acc, err := buildViewDir(runDir, meta, prevDir)
	if err != nil {
		return err
	}
	meta.Counts = acc.counts.Map()
	meta.PlanCounts = &view.PlanCounts
	meta.Totals = &view.Totals
	if err := writeMeta(runDir, meta); err != nil {
		return err
	}
	if err := WriteView(runDir, view); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(runDir, "summary.md"), []byte(acc.summary(meta)), 0o644)
}

// writeMeta: run.json indented by one space, like Python's json.dumps(indent=1).
func writeMeta(dir string, m *Meta) error {
	b, err := pyfmt.MarshalIndent(m)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "run.json"), func(w io.Writer) error { _, err := w.Write(b); return err })
}

// WriteView writes view.json (also used by the dashboard when it rebuilds the view of an old run).
func WriteView(dir string, v *View) error {
	b, err := pyfmt.Marshal(v)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "view.json"), func(w io.Writer) error { _, err := w.Write(b); return err })
}

// WriteMeta writes run.json (the dashboard adds plan_counts to old runs).
func WriteMeta(dir string, m *Meta) error { return writeMeta(dir, m) }

// writeAtomic: readers (the dashboard) never see a half-written file.
func writeAtomic(path string, write func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(tmp, 1<<20)
	if err = write(w); err == nil {
		err = w.Flush()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err == nil {
		err = rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// HistoryTable: the runs of an environment, one line each (CLI `history`); P1–P4 are fixes (runs before 0.5:
// finding rows).
func HistoryTable(p config.Paths, org, env string) (string, error) {
	rows := []string{"run                   hosts  fail   P1    P2    P3    P4  accepted  scope", strings.Repeat("-", 90)}
	for _, r := range Runs(p, org, env) {
		m, err := LoadMeta(r)
		if err != nil {
			return "", err
		}
		c := m.Counts
		scope := strings.Join(m.Selection.Hosts, ",")
		if scope == "" {
			scope = "all"
		}
		row := fmt.Sprintf("%-20s %6d %5d ", m.RunID, m.HostsOK, m.HostsFailed.Len())
		var ps []string
		if t := m.Totals; t != nil { // fixes per priority, as the scan's last line and every interface count them
			for _, n := range []int{t.P1, t.P2, t.P3, t.P4} {
				ps = append(ps, fmt.Sprintf("%5d", n))
			}
		} else { // a run from before 0.5: its finding rows, the only count it has
			for _, pr := range Prios {
				ps = append(ps, fmt.Sprintf("%5d", c[pr]))
			}
		}
		rows = append(rows, row+strings.Join(ps, " ")+fmt.Sprintf(" %9d  %s", c["accepted"], pyfmt.Head(scope, 30)))
	}
	return strings.Join(rows, "\n"), nil
}

// --- retention ---------------------------------------------------------------------------------------------------

// KeepDefault: take the number from policy/settings.yml (retention), or the built-in default.
const KeepDefault = -1

func retention(p config.Paths) (keepFull, keepPartial int) {
	keepFull, keepPartial = 12, 30
	b, err := policy(p, "settings.yml")
	if err != nil {
		return
	}
	v, err := config.YAML(b)
	if err != nil {
		return
	}
	root, _ := v.(map[string]any)
	r, _ := root["retention"].(map[string]any)
	if n, ok := r["keep_full"].(float64); ok {
		keepFull = int(n)
	}
	if n, ok := r["keep_partial"].(float64); ok {
		keepPartial = int(n)
	}
	return
}

// Prune drops old runs: keeps the last keepFull full and keepPartial partial runs (current/ holds the merged
// state anyway), plus leftovers of interrupted runs (no run.json) older than a day. Returns the dropped names.
func Prune(p config.Paths, env string, keepFull, keepPartial int, dryRun bool) ([]string, error) {
	defFull, defPartial := retention(p)
	if keepFull < 0 {
		keepFull = defFull
	}
	if keepPartial < 0 {
		keepPartial = defPartial
	}
	ents, err := os.ReadDir(env)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	var full, part, broken []string
	now := time.Now()
	for _, e := range ents {
		name := e.Name()
		if !e.IsDir() || name == Current || strings.HasPrefix(name, ".") {
			continue
		}
		d := filepath.Join(env, name)
		if !exists(filepath.Join(d, "run.json")) {
			running := false
			if st, err := os.Stat(filepath.Join(d, "status.json")); err == nil {
				running = now.Sub(st.ModTime()) < 120*time.Second
			}
			if st, err := os.Stat(d); err == nil && !running && now.Sub(st.ModTime()) > 24*time.Hour {
				broken = append(broken, d)
			}
			continue
		}
		partial, err := isPartialDir(d)
		if err != nil {
			return nil, err
		}
		if partial {
			part = append(part, d)
		} else {
			full = append(full, d)
		}
	}
	drop := slices.Concat(broken, full[:max(0, len(full)-keepFull)], part[:max(0, len(part)-keepPartial)])
	names := []string{}
	for _, d := range drop {
		if !dryRun {
			_ = os.RemoveAll(d)
		}
		names = append(names, filepath.Base(d))
	}
	return names, nil
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

// PrevIndex: the env's current state (reports/<org>/<env>/current) by finding key, for the due date's clock
// (priority.Prev). Findings saved before 0.5 have no first_seen: they get the date of the oldest kept run that
// has them (and fix_since of the oldest that had an installable fix), so upgrading does not restart every clock.
//
// It reads one host at a time, when asked about a finding of another host than the last: give it the findings
// host by host and it holds one host's clocks (HostPrev: one host's, for hosts scanned in parallel).
func PrevIndex(env string) (func(*finding.Finding) *finding.Finding, error) {
	cur := filepath.Join(env, Current)
	host := "\x00"
	var idx *clocks
	return func(f *finding.Finding) *finding.Finding {
		if h := FileHost(f); h != host {
			host = h
			var err error
			if idx, err = hostClocks(env, cur, h); err != nil {
				idx = nil
			}
		}
		return idx.get(keyHash(f))
	}, nil
}

// HostPrev: PrevIndex for the findings of one host (its file in current/), for scanning hosts in parallel: each
// holds its own host's clocks.
func HostPrev(env, host string) (func(*finding.Finding) *finding.Finding, error) {
	idx, err := hostClocks(env, filepath.Join(env, Current), host)
	if err != nil {
		return nil, err
	}
	return func(f *finding.Finding) *finding.Finding { return idx.get(keyHash(f)) }, nil
}

// clocks: what the due date's clock takes from each finding of a host's previous state, by keyHash. A host has
// up to a few hundred thousand findings: dates are kept as day numbers, priority and reason as small codes (about
// 40 bytes a finding, nothing pointing into the file's strings); what does not fit the codes is kept as it is.
type clocks struct {
	m   map[uint64]clock
	odd map[uint64]*clockOf
}

type clock struct {
	first, fix, start, due int32 // days since 1970 + 1; 0: none
	prio, why              uint8 // index+1 in Prios / dueWhys; 0: none
	accepted               bool
}

// clockOf: a clock as the strings it was read from.
type clockOf struct {
	firstSeen, fixSince, clockStart, dueWhy string
	priority, due                           *string
	accepted                                bool
}

var dueWhys = []string{finding.DueFirstSeen, finding.DueFixSince, finding.DuePublished, finding.DueScan,
	finding.DueEscalated, finding.DueAfterExcept, finding.DueKEV, finding.DueNoFix}

var epoch = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

// dayOf: a date as a day number (0: ""); ok=false when it is not a plain date.
func dayOf(s string) (int32, bool) {
	if s == "" {
		return 0, true
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil || t.Format(time.DateOnly) != s {
		return 0, false
	}
	d := int32(t.Sub(epoch)/(24*time.Hour)) + 1
	return d, d > 0 // before 1970: kept as it is
}

func dayString(d int32) string {
	if d == 0 {
		return ""
	}
	return epoch.AddDate(0, 0, int(d-1)).Format(time.DateOnly)
}

func codeOf(s *string, list []string) (uint8, bool) {
	if s == nil {
		return 0, true
	}
	i := slices.Index(list, *s)
	return uint8(i + 1), i >= 0
}

func (c *clocks) put(h uint64, o *clockOf) {
	var k clock
	ok := true
	set := func(d *int32, s string) {
		v, good := dayOf(s)
		*d, ok = v, ok && good
	}
	set(&k.first, o.firstSeen)
	set(&k.fix, o.fixSince)
	set(&k.start, o.clockStart)
	if o.due != nil {
		if k.due, ok = dayOf(*o.due); k.due == 0 { // a due date of "" is not a plain date: kept as it is
			ok = false
		}
	}
	p, pok := codeOf(o.priority, Prios)
	var why uint8
	wok := true
	if o.dueWhy != "" {
		why, wok = codeOf(&o.dueWhy, dueWhys)
	}
	k.prio, k.why, k.accepted = p, why, o.accepted
	if ok && pok && wok {
		c.m[h] = k
		delete(c.odd, h)
		return
	}
	delete(c.m, h)
	c.odd[h] = o
}

func (c *clocks) lookup(h uint64) (*clockOf, bool) {
	if c == nil {
		return nil, false
	}
	if o := c.odd[h]; o != nil {
		return o, true
	}
	k, ok := c.m[h]
	if !ok {
		return nil, false
	}
	o := &clockOf{firstSeen: dayString(k.first), fixSince: dayString(k.fix), clockStart: dayString(k.start),
		accepted: k.accepted}
	if k.due != 0 {
		d := dayString(k.due)
		o.due = &d
	}
	if k.prio != 0 {
		o.priority = &Prios[k.prio-1]
	}
	if k.why != 0 {
		o.dueWhy = dueWhys[k.why-1]
	}
	return o, true
}

// get: the previous state's finding with the key hash h (only its clock fields), nil when there is none.
func (c *clocks) get(h uint64) *finding.Finding {
	o, ok := c.lookup(h)
	if !ok {
		return nil
	}
	return &finding.Finding{FirstSeen: o.firstSeen, FixSince: o.fixSince, ClockStart: o.clockStart, DueWhy: o.dueWhy,
		Priority: o.priority, Due: o.due, Accepted: o.accepted}
}

// hostClocks: the clocks of one host's findings in current/.
func hostClocks(env, cur, host string) (*clocks, error) {
	idx := &clocks{m: map[uint64]clock{}, odd: map[uint64]*clockOf{}}
	missing := 0
	err := eachHostFinding(cur, host, func(f *finding.Finding) {
		if f.FirstSeen == "" {
			missing++
		}
		idx.put(keyHash(f), &clockOf{firstSeen: f.FirstSeen, fixSince: f.FixSince, clockStart: f.ClockStart,
			dueWhy: f.DueWhy, priority: f.Priority, due: f.Due, accepted: f.Accepted})
	})
	if err != nil || missing == 0 {
		return idx, err
	}
	for _, run := range runDirs(env) { // oldest first
		day := filepath.Base(run)
		if len(day) < 10 {
			continue
		}
		day = day[:10]
		// a damaged old run: the clock starts later, nothing else depends on it
		_ = eachHostFinding(run, host, func(rf *finding.Finding) {
			h := keyHash(rf)
			c, ok := idx.lookup(h)
			if !ok {
				return
			}
			changed := false
			if c.firstSeen == "" || day < c.firstSeen {
				c.firstSeen, changed = day, true
			}
			installable := rf.FixState == finding.FixAvailable || rf.FixState == finding.FixReboot ||
				(rf.FixState == "" && rf.Fixed != "")
			if installable && (c.fixSince == "" || day < c.fixSince) {
				c.fixSince, changed = day, true
			}
			if changed {
				idx.put(h, c)
			}
		})
	}
	return idx, nil
}
