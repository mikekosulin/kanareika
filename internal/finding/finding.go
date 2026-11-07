// Package finding is the unit every check produces: one vulnerable package × CVE, one misconfiguration, one
// exposed port, one health problem. The JSON shape is the report format (reports/<org>/<env>/<run>/findings.json.gz)
// shared with the dashboard and with runs written by earlier versions.
package finding

import (
	"encoding/json"
	"maps"
)

// Kinds.
const (
	Vuln      = "vuln"
	Misconfig = "misconfig"
	Exposure  = "exposure"
	Health    = "health"
	Inventory = "inventory" // facts worth keeping, not a to-do
)

// Fix states of an OS package fix, as the host's own repositories see it (see package vendor).
const (
	FixAvailable = "available" // the repositories have a newer build: update
	FixReboot    = "reboot"    // installed (newer kernel), the host runs the old one
	FixVendor    = "vendor"    // the advisory has a fix, the repositories don't
)

type Exception struct {
	Reason       string `json:"reason"`
	Owner        string `json:"owner"`
	ReviewBy     string `json:"review_by"`
	Expired      bool   `json:"expired"`
	FixAvailable bool   `json:"fix_available,omitempty"`
}

type Finding struct {
	// where
	Org      string `json:"org"`
	Host     string `json:"host"` // "external:<target>" / "k8s:<cluster>" for org-level checks
	Group    string `json:"group"`
	Exposure int    `json:"exposure"`
	Module   string `json:"module"`
	// what
	Kind      string `json:"kind"`
	ID        string `json:"id"` // CVE id or check id
	Pkg       string `json:"pkg"`
	PkgPath   string `json:"pkg_path,omitempty"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	Status    string `json:"status"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	URL       string `json:"url"`
	Target    string `json:"target"` // "os", "image:<ref>", a path, or human text for config findings
	// i18n: the English title/target above + key and args to render other languages
	Msg        string         `json:"msg,omitempty"`
	Args       map[string]any `json:"args,omitzero"`
	TargetMsg  string         `json:"target_msg,omitempty"`
	TargetArgs map[string]any `json:"target_args,omitzero"`
	// vulnerability details
	Vector      string `json:"vector,omitempty"`
	Preauth     bool   `json:"preauth,omitempty"`
	RCE         bool   `json:"rce,omitempty"`
	Kernel      bool   `json:"kernel,omitempty"`         // a package of the running kernel
	Inactive    bool   `json:"inactive,omitempty"`       // an installed kernel that is not booted
	Pending     bool   `json:"pending_reboot,omitempty"` // ... and it is newer: the reboot is pending
	Backported  bool   `json:"backported,omitempty"`     // the package changelog lists the CVE as fixed
	FixState    string `json:"fix_state,omitempty"`
	RepoVersion string `json:"repo_version,omitempty"`
	ImageInUse  *bool  `json:"image_in_use,omitempty"`
	// prioritization (package priority)
	KEV       bool       `json:"kev"`
	EPSS      *float64   `json:"epss"`
	Priority  *string    `json:"priority"`
	Due       *string    `json:"due"`
	Accepted  bool       `json:"accepted"`
	Exception *Exception `json:"exception"`

	// Extra keeps fields this version does not know (newer or older writers), so they survive a rewrite.
	Extra map[string]json.RawMessage `json:"-"`
}

type plain Finding

func (f *Finding) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, (*plain)(f)); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return err
	}
	for _, k := range known {
		delete(all, k)
	}
	if len(all) > 0 {
		f.Extra = all
	}
	return nil
}

func (f Finding) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(plain(f))
	if err != nil || len(f.Extra) == 0 {
		return b, err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	extra := maps.Clone(f.Extra)
	maps.Copy(extra, all)
	return json.Marshal(extra)
}

var known = []string{"org", "host", "group", "exposure", "module", "kind", "id", "pkg", "pkg_path", "installed", "fixed",
	"status", "severity", "title", "url", "target", "msg", "args", "target_msg", "target_args", "vector", "preauth",
	"rce", "kernel", "inactive", "pending_reboot", "backported", "fix_state", "repo_version", "image_in_use", "kev",
	"epss", "priority", "due", "accepted", "exception"}

// PriorityOr: the priority or "" when none was assigned.
func (f *Finding) PriorityOr() string {
	if f.Priority == nil {
		return ""
	}
	return *f.Priority
}

func (f *Finding) DueOr() string {
	if f.Due == nil {
		return ""
	}
	return *f.Due
}
