package server

import (
	"encoding/json"
	"path/filepath"
)

// historyRun: one line of History — a run with what it found and what changed since the run it compares with.
type historyRun struct {
	runInfo
	Prev     *string `json:"prev"`     // the full run the changes are against; null for the first one (or a partial run)
	New      int     `json:"new"`      // findings that appeared since prev
	Resolved int     `json:"resolved"` // findings gone since prev
}

// apiHistory: GET /api/history?org=&env= -> {runs: newest first, with totals and the number of new and resolved
// findings}. The rows of a run's changes come from /api/run?run=<id> (new / resolved), loaded when one is opened;
// this is what a merged list of runs and changes needs without loading every run's view.
func (s *Server) apiHistory(q query) (any, error) {
	o, env, err := s.orgEnv(q)
	if err != nil {
		return nil, err
	}
	rs := runs(s.envDir(o.ID, env))
	out := []historyRun{}
	for i := len(rs) - 1; i >= 0; i-- {
		h := historyRun{runInfo: rs[i]}
		if rs[i].State == "done" {
			if b, err := s.historyView(filepath.Join(s.envDir(o.ID, env), rs[i].RunID)); err == nil {
				var v struct {
					Prev     *string `json:"prev"`
					New      *struct{ Total int }
					Resolved *struct{ Total int }
				}
				if json.Unmarshal(b, &v) == nil {
					h.Prev = v.Prev
					if v.New != nil {
						h.New = v.New.Total
					}
					if v.Resolved != nil {
						h.Resolved = v.Resolved.Total
					}
				}
			}
		}
		out = append(out, h)
	}
	return map[string]any{"runs": out}, nil
}

// historyView: the run's stored view.json, read without the server lock and without the view cache (History reads
// every run: through s.view it would hold the lock for all of them and push the views people have open out of the
// cache). Only a run whose view must be rebuilt (an older version, or none) goes through s.view, once.
func (s *Server) historyView(dir string) ([]byte, error) {
	if b, ok := storedView(filepath.Join(dir, "view.json"), false); ok {
		return b, nil
	}
	return s.view(dir)
}
