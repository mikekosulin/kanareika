package tui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The parts of the API answers the TUI shows (the web page reads the same).

type runInfo struct {
	RunID       string         `json:"run_id"`
	State       string         `json:"state"`
	Started     string         `json:"started"`
	Finished    string         `json:"finished"`
	PlanCounts  map[string]int `json:"plan_counts"`
	HostsTotal  int            `json:"hosts_total"`
	HostsFailed int            `json:"hosts_failed"`
	Partial     bool           `json:"partial"`
}

type envRow struct {
	Env     string   `json:"env"`
	Hosts   int      `json:"hosts"`
	Last    *runInfo `json:"last"`
	Running *runInfo `json:"running"`
}

type orgRow struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Envs []envRow `json:"envs"`
}

type orgsResp struct {
	Errors []string `json:"errors"`
	Orgs   []orgRow `json:"orgs"`
}

type liveHost struct {
	State  string `json:"state"`
	Module string `json:"module"`
	Last   string `json:"last"`
	Errors int    `json:"errors"`
	Step   int    `json:"step"`
	Steps  int    `json:"steps"`
}

type liveInfo struct {
	State   string              `json:"state"`
	Started string              `json:"started"`
	Hosts   map[string]liveHost `json:"hosts"`
	LogTail []string            `json:"log_tail"`
}

type envResp struct {
	Runs []runInfo `json:"runs"`
	Live *liveInfo `json:"live"`
}

type pkgRow struct {
	Pkg       string `json:"pkg"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	CVEs      int    `json:"cves"`
	Priority  string `json:"priority"`
	KEV       bool   `json:"kev"`
}

type action struct {
	ID         string         `json:"id"`
	Cat        string         `json:"cat"`
	Priority   string         `json:"priority"`
	Due        string         `json:"due"`
	Hosts      []string       `json:"hosts"`
	Title      string         `json:"title"`
	Msg        string         `json:"msg"`
	Args       map[string]any `json:"args"`
	Detail     string         `json:"detail"`
	DetailMsg  string         `json:"detail_msg"`
	DetailArgs map[string]any `json:"detail_args"`
	KEV        bool           `json:"kev"`
	CVEs       int            `json:"cves"`
	RCE        int            `json:"rce"`
	Packages   []pkgRow       `json:"packages"`
}

type planRow struct {
	Host      string `json:"host"`
	Target    string `json:"target"`
	Pkg       string `json:"pkg"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	CVEs      int    `json:"cves"`
	Priority  string `json:"priority"`
	Due       string `json:"due"`
	KEV       bool   `json:"kev"`
}

type runMeta struct {
	RunID        string              `json:"run_id"`
	Started      string              `json:"started"`
	Finished     string              `json:"finished"`
	TrivyVersion string              `json:"trivy_version"`
	FeedsUpdated *string             `json:"feeds_updated"`
	HostsFailed  map[string]string   `json:"hosts_failed"`
	ModuleErrors map[string][]string `json:"module_errors"`
}

// diffRow: a package or check new or resolved since the previous full run.
type diffRow struct {
	Host     string   `json:"host"`
	Target   string   `json:"target"`
	Pkg      string   `json:"pkg"`
	IDs      []string `json:"ids"`
	Priority string   `json:"priority"`
	KEV      bool     `json:"kev"`
	RCE      int      `json:"rce"`
	Count    int      `json:"count"`
}

type diffSet struct {
	Total int       `json:"total"`
	Rows  []diffRow `json:"rows"`
}

type backported struct {
	Host      string   `json:"host"`
	Pkg       string   `json:"pkg"`
	Installed string   `json:"installed"`
	IDs       []string `json:"ids"`
	CVEs      int      `json:"cves"`
}

type runResp struct {
	Meta       runMeta                   `json:"meta"`
	PlanCounts map[string]int            `json:"plan_counts"`
	Hosts      map[string]map[string]int `json:"hosts"`
	Facts      map[string]struct {
		OS     string   `json:"os"`
		Kernel []string `json:"kernel"`
	} `json:"facts"`
	Actions []action  `json:"actions"`
	Plan    []planRow `json:"plan"`
	// per host: what the modules found (health.json, access.json, exposure.json as written)
	Health    map[string]map[string]any `json:"health"`
	Access    map[string]map[string]any `json:"access"`
	Exposure  map[string]map[string]any `json:"exposure"`
	Other     []map[string]any          `json:"other"`     // findings other than packages
	Inventory []map[string]any          `json:"inventory"` // facts worth knowing, not to fix
	// against the previous full run (nil: none to compare with)
	Prev       string           `json:"prev"`
	New        *diffSet         `json:"new"`
	Resolved   *diffSet         `json:"resolved"`
	Exceptions []map[string]any `json:"exceptions"` // findings under an accepted risk
	Backported []backported     `json:"backported"` // CVEs the installed builds already fix
}

type scanRequest struct {
	Org          string   `json:"org"`
	Env          string   `json:"env"`
	Hosts        []string `json:"hosts,omitempty"`
	Modules      []string `json:"modules,omitempty"`
	DryRun       bool     `json:"dry_run,omitempty"`
	IgnoreWindow bool     `json:"ignore_window,omitempty"`
	Offline      bool     `json:"offline,omitempty"`
}

type jobInfo struct {
	ID       string      `json:"id"`
	Request  scanRequest `json:"request"`
	State    string      `json:"state"`
	Code     int         `json:"code"`
	Started  time.Time   `json:"started"`
	Finished *time.Time  `json:"finished"`
	Output   []string    `json:"output"`
}

type jobsResp struct {
	Enabled bool      `json:"enabled"`
	Jobs    []jobInfo `json:"jobs"`
}

type scanOptions struct {
	Hosts   []string `json:"hosts"`
	Modules []string `json:"modules"`
}

// dbResp: the DBs scans use (GET /api/db) and the update started from here or the web.
type dbResp struct {
	DBs []struct {
		Name     string `json:"name"`
		Updated  string `json:"updated"`
		Next     string `json:"next_update"`
		Outdated bool   `json:"outdated"`
	} `json:"dbs"`
	Trivy        string   `json:"trivy"` // the server's built-in trivy
	FeedsUpdated string   `json:"feeds_updated"`
	Enabled      bool     `json:"enabled"`
	Updating     bool     `json:"updating"`
	Output       []string `json:"output"`
	Error        string   `json:"error"`
	Finished     string   `json:"finished"`
}

type i18nResp struct {
	Langs    []string                     `json:"langs"`
	Messages map[string]map[string]string `json:"messages"`
}

// --- texts --------------------------------------------------------------------------------------------------------

// tr: interface strings, keyed by the English text as in the web page (assets/locales/<lang>.json "ui").
type tr struct {
	lang    string
	zone    *time.Location               // where times are shown (the system's zone or UTC)
	ui      map[string]map[string]string // lang -> English -> translation
	catalog map[string]map[string]string // message key -> lang -> text (finding and action titles)
}

// T translates an interface string.
func (t *tr) T(s string) string {
	if v := t.ui[t.lang][s]; v != "" {
		return v
	}
	return s
}

// F translates a whole sentence and fills its {name}s (pairs: name, value). The sentence is the key, not its
// pieces, so every language puts the words in its own order ("hace 5 min", "il y a 5 min").
func (t *tr) F(s string, kv ...string) string { return fill(t.T(s), nil, kv) }

var argRE = regexp.MustCompile(`\{(\w+)\}`)

// msg: a catalog text with its arguments filled in (as L() in the web page); fallback when there is none.
func (t *tr) msg(key string, args map[string]any, fallback string) string {
	m := t.catalog[key]
	if m == nil || t.lang == "en" {
		return fallback
	}
	text := m[t.lang]
	if text == "" {
		text = m["en"]
	}
	a := map[string]string{}
	for k, v := range args {
		a[k] = fmt.Sprint(v)
	}
	for k, v := range args {
		if base, ok := strings.CutSuffix(k, "_key"); ok {
			if c := t.catalog[fmt.Sprint(v)]; c != nil {
				if x := c[t.lang]; x != "" {
					a[base] = x
				} else {
					a[base] = c["en"]
				}
			}
		}
	}
	return argRE.ReplaceAllStringFunc(text, func(s string) string {
		if v, ok := a[s[1:len(s)-1]]; ok {
			return v
		}
		return s
	})
}

// cat: a catalog text by its key, in the language shown (English when it has none; the key when unknown).
func (t *tr) cat(key string) string {
	m := t.catalog[key]
	if s := m[t.lang]; s != "" {
		return s
	}
	if s := m["en"]; s != "" {
		return s
	}
	return key
}

func (t *tr) title(a action) string  { return t.msg(a.Msg, a.Args, a.Title) }
func (t *tr) detail(a action) string { return t.msg(a.DetailMsg, a.DetailArgs, a.Detail) }

// ago: "5 min ago" for an ISO time; "—" when there is none or it can't be read.
func (t *tr) ago(iso string, now time.Time) string {
	at, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		if at, err = time.Parse("2006-01-02T15:04:05.000000-07:00", iso); err != nil {
			return "—"
		}
	}
	s := now.Sub(at)
	switch {
	case s < time.Minute:
		return t.T("just now")
	case s < time.Hour:
		return t.F("{n} min ago", "n", strconv.Itoa(int(s.Minutes()+.5)))
	case s < 24*time.Hour:
		return t.F("{n} h ago", "n", strconv.Itoa(int(s.Hours()+.5)))
	}
	return t.F("{n} d ago", "n", strconv.Itoa(int(s.Hours()/24+.5)))
}

// runShort: a run id (its start in UTC, 2026-11-01_204722) as 2026-11-01 20:47 in the zone shown; "current"
// translated.
func (t *tr) runShort(id string) string {
	if id == "current" || id == "" {
		return t.T("Current state")
	}
	at, err := time.ParseInLocation("2006-01-02_150405", id, time.UTC)
	if err != nil {
		return id
	}
	return t.clock(at)
}

// clock: a moment as date and minute in the zone shown.
func (t *tr) clock(at time.Time) string {
	z := t.zone
	if z == nil {
		z = time.UTC
	}
	return at.In(z).Format("2006-01-02 15:04")
}

// zoneName: UTC, or the system zone's abbreviation (MSK, CET) at now.
func (t *tr) zoneName(now time.Time) string {
	if t.zone == nil || t.zone == time.UTC {
		return "UTC"
	}
	return now.In(t.zone).Format("MST")
}
