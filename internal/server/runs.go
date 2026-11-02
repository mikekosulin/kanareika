package server

import (
	"os"
	"path/filepath"
	"time"

	"github.com/mikekosulin/kanareika/internal/pyfmt"
	"github.com/mikekosulin/kanareika/internal/report"
)

// staleAfter: a running scan writes status.json every 5s; older than this, the process is gone.
const staleAfter = 60 * time.Second

// readJSON: the decoded file, nil when it is missing or broken (as the Python dashboard's _read_json).
func readJSON(path string) any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	v, err := decode(b)
	if err != nil {
		return nil
	}
	return v
}

// age of a status heartbeat; unknown or unparseable = very old, so the run shows as stale.
func age(v any) time.Duration {
	s, _ := v.(string)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00"} {
		if t, err := time.Parse(layout, s); err == nil {
			return time.Since(t)
		}
	}
	return 1 << 62
}

// status: status.json of a run, with a running scan whose heartbeat stopped marked "stale".
func status(runDir string) map[string]any {
	st := asMap(readJSON(filepath.Join(runDir, "status.json")))
	if st == nil {
		return nil
	}
	if st["state"] == "running" && age(st["updated"]) > staleAfter {
		st["state"] = "stale"
	}
	return st
}

// runInfo: one line of the run list. Fields come from run.json when the run finished, else from status.json.
type runInfo struct {
	RunID       string `json:"run_id"`
	State       any    `json:"state"`
	Started     any    `json:"started"`
	Finished    any    `json:"finished"`
	Counts      any    `json:"counts"`
	PlanCounts  any    `json:"plan_counts"`
	HostsTotal  int    `json:"hosts_total"`
	HostsFailed int    `json:"hosts_failed"`
	Selection   any    `json:"selection"`
	Partial     bool   `json:"partial"`
}

func isDir(path string) bool {
	st, err := os.Stat(path) // follows symlinks, as Path.is_dir
	return err == nil && st.IsDir()
}

// runs: every run directory of an environment, oldest first, including running, stale and failed ones.
func runs(envDir string) []runInfo {
	out := []runInfo{}
	ents, err := os.ReadDir(envDir)
	if err != nil {
		return out
	}
	for _, e := range ents { // sorted by name
		dir := filepath.Join(envDir, e.Name())
		if e.Name() == report.Current || !name.MatchString(e.Name()) || !isDir(dir) {
			continue
		}
		metaV := readJSON(filepath.Join(dir, "run.json"))
		st := status(dir)
		if !pyfmt.Truthy(metaV) && len(st) == 0 {
			continue
		}
		meta := asMap(metaV)
		if !pyfmt.Truthy(metaV) {
			meta = nil
		}
		state := pyfmt.Or(st["state"], "done")
		if meta != nil && (state == "running" || state == "stale") {
			state = "done"
		}
		src := meta
		if src == nil {
			src = st
		}
		out = append(out, runInfo{
			RunID: e.Name(), State: state, Started: src["started"], Finished: src["finished"],
			Counts:      pyfmt.Or(meta["counts"], st["counts"]),
			PlanCounts:  meta["plan_counts"],
			HostsTotal:  pyfmt.Len(pyfmt.Or(meta["hosts_scanned"], st["hosts"], nil)),
			HostsFailed: pyfmt.Len(meta["hosts_failed"]),
			Selection:   meta["selection"],
			Partial:     partial(meta),
		})
	}
	return out
}

// partial is report.is_partial over the decoded run.json.
func partial(meta map[string]any) bool {
	sel := asMap(meta["selection"])
	return pyfmt.Truthy(sel["hosts"]) || pyfmt.Truthy(sel["groups"]) || pyfmt.Truthy(sel["modules"])
}
