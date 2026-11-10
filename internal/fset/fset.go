// Package fset holds an environment's findings compactly. A large environment has about a million findings, most
// of them the same few thousand CVEs on the same few dozen package builds of the same hosts: a finding is split
// into what it says about the vulnerability (CVE: the advisory's id, title, scores, description) and the rest
// (where it is, what is installed and fixed, its priority and dates), each kept once however many findings share
// it, and an Item is two pointers. Every field of a finding is in exactly one of the two parts, so Item.Finding
// gives it back as it was read.
package fset

import (
	"encoding/json"
	"hash/fnv"
	"iter"
	"maps"
	"sync"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/report"
)

// CVE: what a finding says about the vulnerability (or the check, for other findings).
type CVE struct {
	ID        string   `json:"id,omitempty"`
	Title     string   `json:"title,omitempty"`
	URL       string   `json:"url,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	Vector    string   `json:"vector,omitempty"`
	Preauth   bool     `json:"preauth,omitempty"`
	RCE       bool     `json:"rce,omitempty"`
	KEV       bool     `json:"kev,omitempty"`
	EPSS      *float64 `json:"epss,omitempty"`
	Published string   `json:"published,omitempty"`
	KEVDue    string   `json:"kev_due,omitempty"`
	CVSSScore *float64 `json:"cvss,omitempty"`
	// Description: the advisory's text, the largest part of a CVE and only read in a node's details. Stored apart
	// (Encode gives it separately); a set read from the store leaves it out and Descriptions fetches it.
	Description string `json:"-"`
	DescHash    uint64 `json:"dh,omitempty"` // of Description: CVEs that differ only there are not one part

	Idx  int32 `json:"-"` // its index in Set.CVEs
	ref  int64 // where its description is (Lazy), 0: in Description
	lazy *Lazy
}

// Lazy: where the descriptions a set leaves out are, and the ones fetched.
type Lazy struct {
	// Fetch: the descriptions of refs (Builder.AddEncoded's dataset << 32 | the CVE's index in it).
	Fetch func(refs []int64) (map[int64]string, error)

	mu    sync.Mutex
	cache map[int64]string
}

// lazyKeep: descriptions a Lazy keeps (a node's details show at most a few thousand).
const lazyKeep = 20_000

// Descriptions: the descriptions of cs (in order), fetched once for the ones left out.
func Descriptions(cs []*CVE) ([]string, error) {
	out := make([]string, len(cs))
	want := map[*Lazy][]int64{}
	for i, c := range cs {
		out[i] = c.Description
		if c.ref != 0 && c.lazy != nil {
			want[c.lazy] = append(want[c.lazy], c.ref)
		}
	}
	for l, refs := range want {
		l.mu.Lock()
		var miss []int64
		seen := map[int64]bool{}
		for _, r := range refs {
			if _, ok := l.cache[r]; !ok && !seen[r] {
				seen[r] = true
				miss = append(miss, r)
			}
		}
		l.mu.Unlock()
		if len(miss) > 0 {
			got, err := l.Fetch(miss)
			if err != nil {
				return out, err
			}
			l.mu.Lock()
			if l.cache == nil || len(l.cache)+len(got) > lazyKeep {
				l.cache = map[int64]string{}
			}
			maps.Copy(l.cache, got)
			for _, r := range miss {
				if _, ok := got[r]; !ok {
					l.cache[r] = ""
				}
			}
			l.mu.Unlock()
		}
	}
	for i, c := range cs {
		if c.ref != 0 && c.lazy != nil {
			c.lazy.mu.Lock()
			out[i] = c.lazy.cache[c.ref]
			c.lazy.mu.Unlock()
		}
	}
	return out, nil
}

// Rest: the rest of a finding.
type Rest struct {
	Org         string                     `json:"org,omitempty"`
	Host        string                     `json:"host,omitempty"`
	Group       string                     `json:"group,omitempty"`
	Exposure    int                        `json:"exposure,omitempty"`
	Module      string                     `json:"module,omitempty"`
	Kind        string                     `json:"kind,omitempty"`
	Pkg         string                     `json:"pkg,omitempty"`
	SrcPkg      string                     `json:"src_pkg,omitempty"`
	PkgPath     string                     `json:"pkg_path,omitempty"`
	Installed   string                     `json:"installed,omitempty"`
	Fixed       string                     `json:"fixed,omitempty"`
	Status      string                     `json:"status,omitempty"`
	Target      string                     `json:"target,omitempty"`
	Image       string                     `json:"image,omitempty"`
	Msg         string                     `json:"msg,omitempty"`
	Args        map[string]any             `json:"args,omitzero"`
	TargetMsg   string                     `json:"target_msg,omitempty"`
	TargetArgs  map[string]any             `json:"target_args,omitzero"`
	Kernel      bool                       `json:"kernel,omitempty"`
	Inactive    bool                       `json:"inactive,omitempty"`
	Pending     bool                       `json:"pending,omitempty"`
	Backported  bool                       `json:"backported,omitempty"`
	FixState    string                     `json:"fix_state,omitempty"`
	RepoVersion string                     `json:"repo_version,omitempty"`
	ImageInUse  *bool                      `json:"image_in_use,omitempty"`
	Priority    *string                    `json:"priority,omitempty"`
	Due         *string                    `json:"due,omitempty"`
	Accepted    bool                       `json:"accepted,omitempty"`
	Exception   *finding.Exception         `json:"exception,omitempty"`
	FirstSeen   string                     `json:"first_seen,omitempty"`
	FixSince    string                     `json:"fix_since,omitempty"`
	ClockStart  string                     `json:"clock_start,omitempty"`
	DueWhy      string                     `json:"due_why,omitempty"`
	Extra       map[string]json.RawMessage `json:"extra,omitzero"`
	U           *Unit                      `json:"unit"` // the fix it belongs to (it depends on the rest, and for other findings on the check's id and title)

	Idx         int32  `json:"-"` // its index in Set.Rests
	noFix       string // finding.Finding.NoFix
	actionable  bool   // report.Actionable
	installable bool   // report.Installable
}

// Unit: the fix a finding belongs to (report.FixKey).
type Unit struct {
	Key  string `json:"k"`
	Kind string `json:"kind"`
}

// Item: one finding. Rest's fields are the item's own (f.Host, f.Pkg, f.U); the vulnerability's are under C.
type Item struct {
	*Rest
	C *CVE
}

// Set: an environment's findings, in the order they were read (host file by host file).
type Set struct {
	Items []Item
	CVEs  []*CVE
	Rests []*Rest
	Units []*Unit
}

// PriorityOr: the priority, "" when none.
func (r *Rest) PriorityOr() string {
	if r.Priority == nil {
		return ""
	}
	return *r.Priority
}

// DueOr: the due date, "" when none.
func (r *Rest) DueOr() string {
	if r.Due == nil {
		return ""
	}
	return *r.Due
}

// Source: the source package (finding.Finding.Source).
func (r *Rest) Source() string {
	if r.SrcPkg != "" {
		return r.SrcPkg
	}
	return r.Pkg
}

// NoFix: finding.Finding.NoFix.
func (r *Rest) NoFix() string { return r.noFix }

// Actionable: report.Actionable.
func (r *Rest) Actionable() bool { return r.actionable }

// Installable: report.Installable.
func (r *Rest) Installable() bool { return r.installable }

// strs: the rest's strings, to share them between parts.
func (r *Rest) strs() []*string {
	return []*string{&r.Org, &r.Host, &r.Group, &r.Module, &r.Kind, &r.Pkg, &r.SrcPkg, &r.PkgPath, &r.Installed, &r.Fixed,
		&r.Status, &r.Target, &r.Image, &r.Msg, &r.TargetMsg, &r.FixState, &r.RepoVersion, &r.FirstSeen, &r.FixSince,
		&r.ClockStart, &r.DueWhy}
}

func (c *CVE) strs() []*string {
	return []*string{&c.ID, &c.Title, &c.URL, &c.Severity, &c.Vector, &c.Published, &c.KEVDue}
}

// derive works out what is computed from the rest alone.
func (r *Rest) derive() {
	var f finding.Finding
	r.into(&f)
	r.noFix, r.actionable, r.installable = f.NoFix(), report.Actionable(&f), report.Installable(&f)
}

func (r *Rest) into(f *finding.Finding) {
	f.Org, f.Host, f.Group, f.Exposure, f.Module, f.Kind = r.Org, r.Host, r.Group, r.Exposure, r.Module, r.Kind
	f.Pkg, f.SrcPkg, f.PkgPath, f.Installed, f.Fixed, f.Status = r.Pkg, r.SrcPkg, r.PkgPath, r.Installed, r.Fixed, r.Status
	f.Target, f.Image, f.Msg, f.Args, f.TargetMsg, f.TargetArgs = r.Target, r.Image, r.Msg, r.Args, r.TargetMsg, r.TargetArgs
	f.Kernel, f.Inactive, f.Pending, f.Backported = r.Kernel, r.Inactive, r.Pending, r.Backported
	f.FixState, f.RepoVersion, f.ImageInUse, f.Priority, f.Due = r.FixState, r.RepoVersion, r.ImageInUse, r.Priority, r.Due
	f.Accepted, f.Exception, f.FirstSeen, f.FixSince = r.Accepted, r.Exception, r.FirstSeen, r.FixSince
	f.ClockStart, f.DueWhy, f.Extra = r.ClockStart, r.DueWhy, r.Extra
}

func (c *CVE) into(f *finding.Finding) {
	f.ID, f.Title, f.URL, f.Severity, f.Vector = c.ID, c.Title, c.URL, c.Severity, c.Vector
	f.Preauth, f.RCE, f.KEV, f.EPSS = c.Preauth, c.RCE, c.KEV, c.EPSS
	f.Published, f.KEVDue, f.CVSSScore, f.Description = c.Published, c.KEVDue, c.CVSSScore, c.Description
}

// split: f's two parts.
func split(f *finding.Finding) (CVE, Rest) {
	return CVE{ID: f.ID, Title: f.Title, URL: f.URL, Severity: f.Severity, Vector: f.Vector, Preauth: f.Preauth,
			RCE: f.RCE, KEV: f.KEV, EPSS: f.EPSS, Published: f.Published, KEVDue: f.KEVDue, CVSSScore: f.CVSSScore,
			Description: f.Description, DescHash: descHash(f.Description)},
		Rest{Org: f.Org, Host: f.Host, Group: f.Group, Exposure: f.Exposure, Module: f.Module, Kind: f.Kind, Pkg: f.Pkg,
			SrcPkg: f.SrcPkg, PkgPath: f.PkgPath, Installed: f.Installed, Fixed: f.Fixed, Status: f.Status,
			Target: f.Target, Image: f.Image, Msg: f.Msg, Args: f.Args, TargetMsg: f.TargetMsg, TargetArgs: f.TargetArgs,
			Kernel: f.Kernel, Inactive: f.Inactive, Pending: f.Pending, Backported: f.Backported, FixState: f.FixState,
			RepoVersion: f.RepoVersion, ImageInUse: f.ImageInUse, Priority: f.Priority, Due: f.Due, Accepted: f.Accepted,
			Exception: f.Exception, FirstSeen: f.FirstSeen, FixSince: f.FixSince, ClockStart: f.ClockStart,
			DueWhy: f.DueWhy, Extra: f.Extra}
}

// descHash: a description's hash, the same in every process (stored parts carry it); 0 for none.
func descHash(d string) uint64 {
	if d == "" {
		return 0
	}
	h := fnv.New64a()
	h.Write([]byte(d))
	return h.Sum64() | 1
}

// Finding: the item as a finding (into f, overwritten whole). A description left out (Lazy) stays empty:
// Set.Findings fetches them.
func (it Item) Finding(f *finding.Finding) {
	*f = finding.Finding{}
	it.into(f)
	it.C.into(f)
}

// All: the set's findings one at a time, made into one finding.Finding that is reused: copy what is kept.
// Descriptions left out (Lazy) stay empty.
func (s *Set) All() iter.Seq[*finding.Finding] {
	return func(yield func(*finding.Finding) bool) {
		var f finding.Finding
		for _, it := range s.Items {
			it.Finding(&f)
			if !yield(&f) {
				return
			}
		}
	}
}

// Findings: the set's findings as a slice, descriptions included (small sets: tests, one host).
func (s *Set) Findings() ([]finding.Finding, error) {
	out := make([]finding.Finding, len(s.Items))
	cs := make([]*CVE, len(s.Items))
	for i, it := range s.Items {
		it.Finding(&out[i])
		cs[i] = it.C
	}
	ds, err := Descriptions(cs)
	for i := range out {
		out[i].Description = ds[i]
	}
	return out, err
}

// Len: how many findings.
func (s *Set) Len() int { return len(s.Items) }
