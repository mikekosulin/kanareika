package report

import (
	"encoding/json"
	"errors"
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
		findings, err := LoadFindings(cur)
		if err != nil {
			return "", err
		}
		prev, err := fullBase(done, cmeta.LastRun)
		if err != nil {
			return "", err
		}
		view := BuildView(cur, cmeta, findings, prev)
		view.Meta = cmeta
		return cur, WriteView(cur, view)
	}

	var findings []finding.Finding
	meta := cmeta
	if cmeta != nil {
		var err error
		if findings, err = LoadFindings(cur); err != nil {
			return "", err
		}
	} else {
		meta = &Meta{RunID: Current, Sources: map[string]map[string]string{}, HostsScanned: []string{}, Modules: []string{}}
	}
	if meta.Sources == nil {
		meta.Sources = map[string]map[string]string{}
	}
	for _, run := range todo {
		rmeta, rfind, err := LoadRun(run)
		if err != nil {
			return "", err
		}
		pr := pairs(rmeta)
		orgMods := map[string]bool{}
		for i := range rfind {
			if strings.Contains(rfind[i].Host, ":") {
				orgMods[rfind[i].Module] = true
			}
		}
		if !IsPartial(rmeta) {
			for _, m := range []string{"network_external", "k8s"} {
				if slices.Contains(rmeta.Modules, m) {
					orgMods[m] = true
				}
			}
		}
		kept := findings[:0:0]
		for _, f := range findings {
			if !(pr[f.Host][f.Module] || (strings.Contains(f.Host, ":") && orgMods[f.Module])) {
				kept = append(kept, f)
			}
		}
		for _, f := range rfind {
			if pr[f.Host][f.Module] || strings.Contains(f.Host, ":") {
				kept = append(kept, f)
			}
		}
		findings = kept
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
	if err := os.MkdirAll(cur, 0o755); err != nil {
		return "", err
	}
	if err := writeFindings(cur, findings); err != nil {
		return "", err
	}
	c := CountsOf(findings)
	meta.Counts = c.Map()
	// "new / resolved" in the current state = changes since the latest FULL scan
	prev, err := fullBase(done, meta.LastRun)
	if err != nil {
		return "", err
	}
	view := BuildView(cur, meta, findings, prev)
	meta.PlanCounts = &view.PlanCounts
	view.Meta = meta
	if err := writeMeta(cur, meta); err != nil {
		return "", err
	}
	if err := WriteView(cur, view); err != nil {
		return "", err
	}
	return cur, nil
}

// fullBase: the latest full run other than lastRun itself (when the latest is the run just merged, the one
// before it), loaded; nil when there is none.
func fullBase(done []string, lastRun string) (*Prev, error) {
	var full []string
	for _, d := range done {
		p, err := isPartialDir(d)
		if err != nil {
			return nil, err
		}
		if !p {
			full = append(full, d)
		}
	}
	var base string
	switch {
	case len(full) > 0 && filepath.Base(full[len(full)-1]) != lastRun:
		base = full[len(full)-1]
	case len(full) > 1:
		base = full[len(full)-2]
	default:
		return nil, nil
	}
	return loadPrev(base)
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
