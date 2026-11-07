package tui

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/assets"
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
	RunID        string  `json:"run_id"`
	Started      string  `json:"started"`
	Finished     string  `json:"finished"`
	TrivyVersion string  `json:"trivy_version"`
	FeedsUpdated *string `json:"feeds_updated"`
}

type runResp struct {
	Meta       runMeta                   `json:"meta"`
	PlanCounts map[string]int            `json:"plan_counts"`
	Hosts      map[string]map[string]int `json:"hosts"`
	Facts      map[string]struct {
		OS string `json:"os"`
	} `json:"facts"`
	Actions []action  `json:"actions"`
	Plan    []planRow `json:"plan"`
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

type i18nResp struct {
	Langs    []string                     `json:"langs"`
	Messages map[string]map[string]string `json:"messages"`
}

// --- texts --------------------------------------------------------------------------------------------------------

// tr: interface strings, keyed by the English text as in the web page (assets/locales/<lang>.json "ui").
type tr struct {
	lang    string
	ui      map[string]map[string]string // lang -> English -> translation
	catalog map[string]map[string]string // message key -> lang -> text (finding and action titles)
}

func loadUI() map[string]map[string]string {
	out := map[string]map[string]string{}
	files, _ := fs.Glob(assets.Locales(), "*.json")
	for _, f := range files {
		b, err := fs.ReadFile(assets.Locales(), f)
		if err != nil {
			continue
		}
		var l struct {
			UI map[string]string `json:"ui"`
		}
		if json.Unmarshal(b, &l) == nil && len(l.UI) > 0 {
			out[strings.TrimSuffix(f, ".json")] = l.UI
		}
	}
	return out
}

// T translates an interface string.
func (t *tr) T(s string) string {
	if v := t.ui[t.lang][s]; v != "" {
		return v
	}
	return s
}

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
		return fmt.Sprintf("%d %s", int(s.Minutes()+.5), t.T("min ago"))
	case s < 24*time.Hour:
		return fmt.Sprintf("%d %s", int(s.Hours()+.5), t.T("h ago"))
	}
	return fmt.Sprintf("%d %s", int(s.Hours()/24+.5), t.T("d ago"))
}

// runShort: 2026-11-01_204722 -> 2026-11-01 20:47; "current" translated.
func (t *tr) runShort(id string) string {
	if id == "current" || id == "" {
		return t.T("Current state")
	}
	if len(id) >= 15 {
		return id[:10] + " " + id[11:13] + ":" + id[13:15]
	}
	return id
}
