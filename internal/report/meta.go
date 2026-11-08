package report

import (
	"encoding/json"
	"maps"

	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

// Meta is run.json of a run (and of current/). Typed for the fields the report code and the dashboard use; Extra
// keeps the rest so a rewrite (e.g. adding plan_counts to an old run) loses nothing.
//
// Nullable fields are pointers without omitempty because Python always writes them (as null when unknown); fields
// that only some runs have are omitempty.
type Meta struct {
	Org           string                  `json:"org"`
	Env           string                  `json:"env"`
	RunID         string                  `json:"run_id"`
	Kanareika     string                  `json:"kanareika,omitempty"`
	TrivyVersion  *string                 `json:"trivy_version"`
	Started       string                  `json:"started"`
	Finished      string                  `json:"finished"`
	Selection     Selection               `json:"selection"`
	Modules       []string                `json:"modules"`
	HostsScanned  []string                `json:"hosts_scanned"`
	HostsOK       int                     `json:"hosts_ok"`
	ModulesByHost map[string][]string     `json:"modules_by_host,omitzero"` // nil: runs made before it existed
	HostsFailed   pyfmt.Ordered[string]   `json:"hosts_failed"`
	ModuleErrors  pyfmt.Ordered[[]string] `json:"module_errors"`
	FeedsUpdated  *string                 `json:"feeds_updated"`
	Counts        map[string]int          `json:"counts,omitempty"` // as stored: runs of older versions lack "backported"
	PlanCounts    *PlanCounts             `json:"plan_counts,omitempty"`
	Totals        *Totals                 `json:"totals,omitempty"` // what there is to do (see Totals); runs before 0.5 lack it
	// current/ only
	Sources map[string]map[string]string `json:"sources,omitzero"` // host -> module -> run it comes from
	LastRun string                       `json:"last_run,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

// Selection of a run; an empty one is a full run. nil and empty lists differ so {} (current/) and
// {"groups": [], ...} (a run) are written back as they were.
type Selection struct {
	Groups  []string `json:"groups,omitzero"`
	Hosts   []string `json:"hosts,omitzero"`
	Modules []string `json:"modules,omitzero"`
}

type plainMeta Meta

var metaKnown = []string{"org", "env", "run_id", "kanareika", "trivy_version", "started", "finished", "selection",
	"modules", "hosts_scanned", "hosts_ok", "modules_by_host", "hosts_failed", "module_errors", "feeds_updated",
	"counts", "plan_counts", "totals", "sources", "last_run"}

func (m *Meta) UnmarshalJSON(b []byte) error {
	var p plainMeta
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	_ = json.Unmarshal(b, &all) // b decoded into a struct above: an object or null, so it decodes as a map too
	for _, k := range metaKnown {
		delete(all, k)
	}
	if len(all) > 0 {
		p.Extra = all
	}
	*m = Meta(p)
	return nil
}

func (m Meta) MarshalJSON() ([]byte, error) {
	p := plainMeta(m)
	if p.Modules == nil {
		p.Modules = []string{}
	}
	if p.HostsScanned == nil {
		p.HostsScanned = []string{}
	}
	b, err := pyfmt.Marshal(p)
	if err != nil || len(m.Extra) == 0 {
		return b, err
	}
	var all map[string]json.RawMessage
	_ = json.Unmarshal(b, &all) // b is a marshalled struct: always an object
	extra := maps.Clone(m.Extra)
	maps.Copy(extra, all)
	return pyfmt.Marshal(extra)
}
