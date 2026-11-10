package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mikekosulin/kanareika/internal/finding"
)

// hostFiles: per-host files current/ takes from a run, and the module that must have succeeded for it ("" =
// always: facts come with every scan of the host).
var hostFiles = []struct{ name, module string }{{"facts.json", ""}, {"health.json", "health"}, {"access.json", "access"},
	{"exposure.json", "exposure"}, {"docker.json", "docker"}, {"swarm.json", "swarm"}}

// pairs: host -> modules that ran successfully on it in this run.
func pairs(m *Meta) map[string]map[string]bool {
	byHost := m.ModulesByHost
	if byHost == nil { // runs made before modules_by_host existed
		mods := m.Selection.Modules
		if len(mods) == 0 {
			mods = m.Modules
		}
		byHost = map[string][]string{}
		for _, h := range m.HostsScanned {
			byHost[h] = mods
		}
	}
	out := map[string]map[string]bool{}
	for h, mods := range byHost {
		if m.HostsFailed.Has(h) {
			continue
		}
		e, _ := m.ModuleErrors.Get(h)
		errs := strings.Join(e, " ")
		ok := map[string]bool{}
		for _, mod := range mods {
			if !strings.HasPrefix(errs, mod+":") && !strings.Contains(" "+errs, " "+mod+":") {
				ok[mod] = true
			}
		}
		out[h] = ok
	}
	return out
}

// UpdateCurrent folds every finished run newer than the current snapshot into reports/<org>/<env>/current and
// returns its path ("" when there is nothing yet). locked: the caller (a scan) holds the env lock. wait=false: if
// a scan holds the lock, return the existing snapshot as is (the scan updates it at the end).
//
// It works a host at a time: a host's findings file in current/ is the run's (a hard link) when the run scanned
// every module current/ had for it, a merge of the two otherwise, read and written one finding at a time.
func UpdateCurrent(env string, locked, wait bool) (string, error) {
	cur := filepath.Join(env, Current)
	if !locked {
		l, err := EnvLock(env, wait)
		var busy *Busy
		if errors.As(err, &busy) {
			if exists(filepath.Join(cur, "view.json")) {
				return cur, nil
			}
			return "", nil
		}
		if err != nil {
			return "", err
		}
		defer l.Unlock()
	}
	// reading needs no split (HostFiles reads an older run's single file as it is): a scan, under the lock, splits
	// every run once; the dashboard only splits what it folds below, and never pays for the old runs
	if locked {
		if err := MigrateEnv(env); err != nil {
			return "", err
		}
	}
	var cmeta *Meta
	if exists(filepath.Join(cur, "run.json")) {
		var err error
		if cmeta, err = LoadMeta(cur); err != nil {
			return "", err
		}
	}
	done := runDirs(env)
	var todo []string
	for _, d := range done {
		if cmeta == nil || filepath.Base(d) > cmeta.LastRun {
			todo = append(todo, d)
		}
	}
	if len(todo) == 0 {
		if cmeta == nil {
			return "", nil
		}
		var stored struct {
			Version int `json:"version"`
		}
		if b, err := os.ReadFile(filepath.Join(cur, "view.json")); err == nil {
			_ = json.Unmarshal(b, &stored)
		}
		if stored.Version >= ViewVersion { // never downgrade a view built by newer code
			return cur, nil
		}
		// same data, newer report code: rebuild the view only
		base, err := fullBase(done, cmeta.LastRun)
		if err != nil {
			return "", err
		}
		view, _, err := buildViewDir(cur, cmeta, base)
		if err != nil {
			return "", err
		}
		view.Meta = cmeta
		return cur, WriteView(cur, view)
	}

	meta := cmeta
	if meta == nil {
		meta = &Meta{RunID: Current, Sources: map[string]map[string]string{}, HostsScanned: []string{}, Modules: []string{}}
	}
	if meta.Sources == nil {
		meta.Sources = map[string]map[string]string{}
	}
	if err := os.MkdirAll(cur, 0o755); err != nil {
		return "", err
	}
	// folding links and merges host files: current/ and the runs folded in must be split first
	for _, d := range append([]string{cur}, todo...) {
		if err := splitLegacy(d); err != nil {
			return "", fmt.Errorf("%s: %w", d, err)
		}
	}
	changed := map[string]bool{}
	for _, run := range todo {
		rmeta, err := LoadMeta(run)
		if err != nil {
			return "", err
		}
		pr := pairs(rmeta)
		for _, h := range sortedKeys(setOf(pr)) {
			if err := mergeHost(cur, run, h, meta.Sources[h], pr[h], rmeta); err != nil {
				return "", err
			}
			changed[h] = true
		}
		if ok, err := mergeOrg(cur, run, rmeta); err != nil {
			return "", err
		} else if ok {
			changed[OrgHost] = true
		}
		name := filepath.Base(run)
		for h, mods := range pr {
			src := meta.Sources[h]
			if src == nil {
				src = map[string]string{}
				meta.Sources[h] = src
			}
			src["_facts"] = name
			for m := range mods {
				src[m] = name
			}
			hd := filepath.Join(cur, "hosts", h)
			if err := os.MkdirAll(hd, 0o755); err != nil {
				return "", err
			}
			for _, hf := range hostFiles {
				if hf.module != "" && !mods[hf.module] {
					continue
				}
				if err := copyFile(filepath.Join(run, "hosts", h, hf.name), filepath.Join(hd, hf.name)); err != nil &&
					!errors.Is(err, os.ErrNotExist) {
					return "", err
				}
			}
		}
		for _, h := range rmeta.HostsScanned { // latest attempt decides reachability / module errors
			meta.HostsFailed.Delete(h)
			meta.ModuleErrors.Delete(h)
			if e, ok := rmeta.HostsFailed.Get(h); ok {
				meta.HostsFailed.Set(h, e)
			}
			if e, ok := rmeta.ModuleErrors.Get(h); ok {
				meta.ModuleErrors.Set(h, e)
			}
		}
		meta.Org, meta.Env, meta.LastRun, meta.Finished = rmeta.Org, rmeta.Env, name, rmeta.Finished
		if meta.Started == "" {
			meta.Started = rmeta.Started
		}
		meta.TrivyVersion = rmeta.TrivyVersion
		if deref(rmeta.FeedsUpdated) != "" {
			meta.FeedsUpdated = rmeta.FeedsUpdated
		}
		meta.HostsScanned = union(meta.HostsScanned, rmeta.HostsScanned)
		meta.Modules = union(meta.Modules, rmeta.Modules)
	}
	meta.HostsOK = len(meta.HostsScanned) - meta.HostsFailed.Len()
	// "new / resolved" in the current state = changes since the latest FULL scan
	base, err := fullBase(done, meta.LastRun)
	if err != nil {
		return "", err
	}
	view, acc, err := buildViewDir(cur, meta, base)
	if err != nil {
		return "", err
	}
	meta.Counts = acc.counts.Map()
	meta.PlanCounts = &view.PlanCounts
	meta.Totals = &view.Totals
	view.Meta = meta
	if err := writeMeta(cur, meta); err != nil {
		return "", err
	}
	if err := WriteView(cur, view); err != nil {
		return "", err
	}
	if OnCurrent != nil && len(changed) > 0 {
		OnCurrent(cur, sortedKeys(changed))
	}
	return cur, nil
}

func setOf[V any](m map[string]V) map[string]bool {
	s := make(map[string]bool, len(m))
	for k := range m {
		s[k] = true
	}
	return s
}

// mergeHost puts the run's findings of host h from the modules that succeeded (ok) into current/, keeping what
// current/ has of h from other modules. When the run covers every module current/ has for h (src: current/'s
// sources of h) and none of the run's modules failed there, the run's file is current/'s as it is.
func mergeHost(cur, run, h string, src map[string]string, ok map[string]bool, rmeta *Meta) error {
	runFile, curFile := hostFindingsPath(run, h), hostFindingsPath(cur, h)
	whole := !rmeta.ModuleErrors.Has(h) && (src != nil || !exists(curFile))
	for m := range src {
		if m != "_facts" && !ok[m] {
			whole = false
		}
	}
	for _, m := range rmeta.ModulesByHost[h] {
		if !ok[m] {
			whole = false
		}
	}
	if whole {
		if !exists(runFile) {
			if err := os.Remove(curFile); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		}
		return linkOrCopy(runFile, curFile)
	}
	w, err := newFindingsWriter(curFile)
	if err != nil {
		return err
	}
	var werr error
	add := func(keep bool, f *finding.Finding) {
		if keep && werr == nil {
			werr = w.Add(f)
		}
	}
	// the kept current state first, then the run's
	err = eachHostFinding(cur, h, func(f *finding.Finding) { add(!ok[f.Module], f) })
	if err == nil {
		err = eachHostFinding(run, h, func(f *finding.Finding) { add(ok[f.Module], f) })
	}
	if err = errors.Join(err, werr); err != nil {
		w.Abort()
		return err
	}
	return w.Commit()
}

// mergeOrg: the org-level findings (external:<target>, k8s:<cluster>) of the run replace current/'s of the
// modules the run ran (a full run: network_external and k8s even when they found nothing). The file is small.
// Reports whether current/'s file changed.
func mergeOrg(cur, run string, rmeta *Meta) (bool, error) {
	rfind, err := loadHost(run, OrgHost)
	if err != nil {
		return false, err
	}
	orgMods := map[string]bool{}
	for i := range rfind {
		orgMods[rfind[i].Module] = true
	}
	if !IsPartial(rmeta) {
		for _, m := range []string{"network_external", "k8s"} {
			if slices.Contains(rmeta.Modules, m) {
				orgMods[m] = true
			}
		}
	}
	if len(orgMods) == 0 {
		return false, nil
	}
	cfind, err := loadHost(cur, OrgHost)
	if err != nil {
		return false, err
	}
	out := keep(cfind, func(f *finding.Finding) bool { return !orgMods[f.Module] })
	out = append(out, rfind...)
	w, err := newFindingsWriter(hostFindingsPath(cur, OrgHost))
	if err != nil {
		return false, err
	}
	for i := range out {
		if err := w.Add(&out[i]); err != nil {
			w.Abort()
			return false, err
		}
	}
	return true, w.Commit()
}

// loadHost: one host's findings of dir.
func loadHost(dir, host string) ([]finding.Finding, error) {
	var out []finding.Finding
	err := eachHostFinding(dir, host, func(f *finding.Finding) { out = append(out, *f) })
	return out, err
}

// fullBase: the latest full run other than lastRun itself (when the latest is the run just merged, the one
// before it); "" when there is none.
func fullBase(done []string, lastRun string) (string, error) {
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
	switch {
	case len(full) > 0 && filepath.Base(full[len(full)-1]) != lastRun:
		return full[len(full)-1], nil
	case len(full) > 1:
		return full[len(full)-2], nil
	}
	return "", nil
}

// keep: the findings ok keeps, in order, in place.
func keep(fs []finding.Finding, ok func(*finding.Finding) bool) []finding.Finding {
	out := fs[:0]
	for i := range fs {
		if ok(&fs[i]) {
			out = append(out, fs[i])
		}
	}
	clear(fs[len(out):])
	return out
}

func union(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	return sortedKeys(set)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeAtomic(dst, func(w io.Writer) error { _, err := io.Copy(w, in); return err })
}
