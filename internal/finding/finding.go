// Package finding is the unit every check produces: one vulnerable package × CVE, one misconfiguration, one
// exposed port, one health problem. The JSON shape is the report format (reports/<org>/<env>/<run>/findings.json.gz)
// shared with the dashboard and with runs written by earlier versions.
package finding

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"strings"
)

// Kinds.
const (
	Vuln      = "vuln"
	Misconfig = "misconfig"
	Exposure  = "exposure"
	Health    = "health"
	Inventory = "inventory" // facts worth keeping, not a to-do
)

// Why a due date is what it is (Finding.DueWhy).
const (
	DueFirstSeen   = "first_seen"      // SLA days from the first scan that saw it
	DueFixSince    = "fix_available"   // ... from the first scan that saw an installable fix
	DuePublished   = "published"       // ... from the advisory's publication date
	DueScan        = "scan"            // ... from this scan (the behaviour before 0.5)
	DueEscalated   = "escalated"       // the priority went up: the new SLA from that day, never later than before
	DueAfterExcept = "exception_ended" // an accepted risk expired: the clock starts again that day
	DueKEV         = "kev"             // CISA's KEV due date comes first
	DueNoFix       = "no_fix"          // counting from the fix, and there is none yet
)

// Fix states of an OS package fix, as the host's own repositories see it (see package vendor).
const (
	FixAvailable = "available" // the repositories have a newer build: update
	FixReboot    = "reboot"    // installed (newer kernel), the host runs the old one
	FixVendor    = "vendor"    // the advisory has a fix, the repositories don't
)

// Why a vulnerable package has nothing to install (Finding.NoFix). Derived from what the scanner already stores
// (the advisory status, the fixed version, the fix state), so runs written before it read the same way.
const (
	NoFixPending  = "pending"  // the vendor has not released a fix yet (advisory status affected / under investigation)
	NoFixRepos    = "repos"    // released, but not in the host's repositories yet (fix state vendor)
	NoFixESM      = "esm"      // released only to Ubuntu Pro / ESM subscribers (a +esm build)
	NoFixDeferred = "deferred" // the vendor postponed the fix (fix_deferred)
	NoFixWontFix  = "wontfix"  // the vendor will not fix it (will_not_fix, end_of_life)
)

// IsESM: an Ubuntu build only Ubuntu Pro / ESM subscribers get (1.2-3ubuntu0.1+esm1, 2.0~esm2).
func IsESM(version string) bool {
	return strings.Contains(version, "+esm") || strings.Contains(version, "~esm")
}

// NoFix: why the vulnerability has nothing to install on the host; "" when a fix can be installed, or for other
// findings.
func (f *Finding) NoFix() string {
	if f.Kind != Vuln {
		return ""
	}
	if f.Fixed == "" {
		switch f.Status {
		case "will_not_fix", "end_of_life":
			return NoFixWontFix
		case "fix_deferred":
			return NoFixDeferred
		}
		return NoFixPending
	}
	switch f.FixState {
	case FixAvailable, FixReboot:
		return ""
	case FixVendor:
		if IsESM(f.Fixed) {
			return NoFixESM
		}
		return NoFixRepos
	}
	if IsESM(f.Fixed) && f.Target == "os" { // the repositories were not asked: an ESM build is out of reach without Pro
		return NoFixESM
	}
	return ""
}

// Source: the source package of an OS package; the package itself when not known (or the same).
func (f *Finding) Source() string {
	if f.SrcPkg != "" {
		return f.SrcPkg
	}
	return f.Pkg
}

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
	SrcPkg    string `json:"src_pkg,omitempty"` // OS packages: the source package when its name differs (openssl for libssl3)
	PkgPath   string `json:"pkg_path,omitempty"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	Status    string `json:"status"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	URL       string `json:"url"`
	Target    string `json:"target"`          // "os", "image:<ref>", a path, or human text for config findings
	Image     string `json:"image,omitempty"` // k8s: the image of the workload the finding is in (Target is the workload)
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
	// the due date's clock (see priority.Apply): when the finding was first seen here, when a fix first became
	// installable, the date the clock counts from and why it starts there
	FirstSeen  string `json:"first_seen,omitempty"`
	FixSince   string `json:"fix_since,omitempty"`
	ClockStart string `json:"clock_start,omitempty"`
	DueWhy     string `json:"due_why,omitempty"`
	// advisory facts: publication date, CISA's KEV due date, CVSS base score, description (shortened)
	Published   string   `json:"published,omitempty"`
	KEVDue      string   `json:"kev_due,omitempty"`
	CVSSScore   *float64 `json:"cvss_score,omitempty"`
	Description string   `json:"description,omitempty"`

	// Extra keeps fields this version does not know (newer or older writers), so they survive a rewrite.
	Extra map[string]json.RawMessage `json:"-"`
}

type plain Finding

// wire: a Finding as stored, the members this version does not know collected by encoding/json/v2 in one pass
// (a findings file holds about a million of them: decoding each twice, or re-parsing what MarshalJSON returned,
// cost gigabytes).
type wire struct {
	*plain
	Extra map[string]jsontext.Value `json:",embed"`
}

// UnmarshalJSONFrom reads a finding from the stream; json.Unmarshal (v1) uses it too.
func (f *Finding) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	w := wire{plain: (*plain)(f)}
	if err := jsonv2.UnmarshalDecode(dec, &w); err != nil {
		return err
	}
	if len(w.Extra) > 0 {
		f.Extra = w.Extra // json.RawMessage is jsontext.Value
	}
	return nil
}

// MarshalJSONTo writes a finding to the stream; json.Marshal (v1) uses it too. Extra never overrides a known field.
func (f Finding) MarshalJSONTo(enc *jsontext.Encoder) error {
	w := wire{plain: (*plain)(&f)}
	for k, v := range f.Extra {
		if !known[k] {
			if w.Extra == nil {
				w.Extra = make(map[string]jsontext.Value, len(f.Extra))
			}
			w.Extra[k] = v
		}
	}
	return jsonv2.MarshalEncode(enc, &w)
}

var known = map[string]bool{"org": true, "host": true, "group": true, "exposure": true, "module": true, "kind": true,
	"id": true, "pkg": true, "pkg_path": true, "installed": true, "fixed": true, "status": true, "severity": true,
	"title": true, "url": true, "target": true, "msg": true, "args": true, "target_msg": true, "target_args": true,
	"vector": true, "preauth": true, "rce": true, "kernel": true, "inactive": true, "pending_reboot": true,
	"backported": true, "fix_state": true, "repo_version": true, "image_in_use": true, "kev": true, "epss": true,
	"priority": true, "due": true, "accepted": true, "exception": true, "first_seen": true, "fix_since": true,
	"clock_start": true, "due_why": true, "published": true, "kev_due": true, "cvss_score": true, "description": true,
	"image": true, "src_pkg": true}

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
