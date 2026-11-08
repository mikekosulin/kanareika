// Package priority: KEV / EPSS enrichment, accepted-risk exceptions and P1..P4 assignment from policy/priority.yml.
package priority

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

// UserAgent: some feeds reject the default client UA. SetVersion puts the running version in it.
var UserAgent = userAgent("dev")

func userAgent(version string) string {
	return "github.com/mikekosulin/kanareika/" + strings.TrimPrefix(version, "v") + " (+vulnerability audit)"
}

// SetVersion: the version the downloads announce.
func SetVersion(version string) { UserAgent = userAgent(version) }

// FeedsDir: KANAREIKA_FEEDS_DIR, else the user cache dir (the Docker image sets the variable to /data/feeds).
func FeedsDir() string {
	if d := os.Getenv("KANAREIKA_FEEDS_DIR"); d != "" {
		return d
	}
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "kanareika", "feeds")
}

type Rule struct {
	Priority string
	When     map[string]any // conditions, ANDed; values as decoded from YAML (numbers are float64)
}

type Policy struct {
	Rules   []Rule
	SLADays map[string]float64 // priority -> days to fix (Due.SLADays; kept for callers that read it)
	Due     DueRules
	KEVURL  string
	EPSSURL string
}

// DueRules: how a due date is counted. SLA days per priority from a start date:
//
//	start: first_seen     the first scan that saw the finding on this host (default)
//	       fix_available  the first scan that saw an installable fix (no fix: no due date yet)
//	       published      the advisory's publication date (first_seen for findings without one)
//	       scan           every scan restarts it (the behaviour before 0.5)
//	kev: cisa             never later than CISA's KEV due date (default); off
//	escalation: restart   priority went up: the new SLA counts from that day, never later than the old date
//	            keep      the new SLA from the start date, even if that is already past
//	after_exception: restart  an accepted risk expired: the clock starts again that day (default); keep
type DueRules struct {
	SLADays        map[string]float64
	Start          string
	KEV            string
	Escalation     string
	AfterException string
}

var dueEnums = map[string][]string{
	"start":           {finding.DueFirstSeen, finding.DueFixSince, finding.DuePublished, finding.DueScan},
	"kev":             {"cisa", "off"},
	"escalation":      {"restart", "keep"},
	"after_exception": {"restart", "keep"},
}

func defaultDue() DueRules {
	return DueRules{SLADays: map[string]float64{}, Start: finding.DueFirstSeen, KEV: "cisa", Escalation: "restart",
		AfterException: "restart"}
}

// overlay: d with the keys of m (a `due:` block) applied; unknown keys and values are errors.
func (d DueRules) overlay(m map[string]any, where string) (DueRules, error) {
	out := d
	out.SLADays = maps.Clone(d.SLADays)
	for k, v := range m {
		switch k {
		case "sla_days":
			sla, ok := v.(map[string]any)
			if !ok {
				return d, fmt.Errorf("%s.sla_days: a map of priority -> days is required", where)
			}
			for p, n := range sla {
				days, ok := n.(float64)
				if !ok || days < 0 {
					return d, fmt.Errorf("%s.sla_days.%s: a number of days is required", where, p)
				}
				out.SLADays[p] = days
			}
		case "start", "kev", "escalation", "after_exception":
			sv, _ := v.(string)
			if !slices.Contains(dueEnums[k], sv) {
				return d, fmt.Errorf("%s.%s: one of %s", where, k, strings.Join(dueEnums[k], ", "))
			}
			switch k {
			case "start":
				out.Start = sv
			case "kev":
				out.KEV = sv
			case "escalation":
				out.Escalation = sv
			default:
				out.AfterException = sv
			}
		case "envs":
			if where != "due" {
				return d, fmt.Errorf("%s.envs: only at the top of the org's due block", where)
			}
		default:
			return d, fmt.Errorf("%s.%s: unknown key", where, k)
		}
	}
	return out, nil
}

// DueFor: the policy's due rules with the org's `due:` block on top, then its `due.envs.<env>` block.
func (pol *Policy) DueFor(org *config.Org, env string) (DueRules, error) {
	d := pol.Due
	if d.SLADays == nil {
		d = defaultDue()
		d.SLADays = maps.Clone(pol.SLADays)
	}
	if org == nil {
		return d, nil
	}
	m, ok := org.Data["due"].(map[string]any)
	if !ok {
		return d, nil
	}
	d, err := d.overlay(m, "due")
	if err != nil {
		return d, err
	}
	envs, _ := m["envs"].(map[string]any)
	if e, ok := envs[env].(map[string]any); ok {
		return d.overlay(e, "due.envs."+env)
	}
	return d, nil
}

// policyFile reads a policy file; tests replace it (the built-in fallback never fails otherwise).
var policyFile = config.Policy

// LoadPolicy: policy/priority.yml of the working directory, else the built-in one.
func LoadPolicy(p config.Paths) (*Policy, error) {
	b, err := policyFile(p, "priority.yml")
	if err != nil {
		return nil, err
	}
	pol, err := ParsePolicy(b)
	if err != nil {
		return nil, fmt.Errorf("priority.yml: %w", err)
	}
	return pol, nil
}

// condition types: the Python version failed at scan time on a wrong type; here the policy is rejected on load
var (
	boolConds = []string{"kev", "fixable", "kernel", "preauth", "rce"}
	listConds = []string{"severity", "exposure", "kind", "id"}
)

func ParsePolicy(b []byte) (*Policy, error) {
	v, err := config.YAML(b)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	rules, ok := m["rules"].([]any)
	if !ok {
		return nil, errors.New("rules: a list is required")
	}
	pol := &Policy{SLADays: map[string]float64{}}
	for i, r := range rules {
		rm, _ := r.(map[string]any)
		when, _ := rm["when"].(map[string]any)
		if rm["priority"] == nil {
			return nil, fmt.Errorf("rules[%d]: priority is required", i)
		}
		for k, c := range when {
			_, isNum := c.(float64)
			_, isBool := c.(bool)
			_, isList := c.([]any)
			switch {
			case slices.Contains(boolConds, k) && !isBool && !isNum,
				k == "epss_gte" && !isNum && !isBool,
				k == "exposure" && !isList,
				slices.Contains(listConds, k) && !isList && !isString(c):
				return nil, fmt.Errorf("rules[%d].when.%s: wrong type %T", i, k, c)
			}
		}
		pol.Rules = append(pol.Rules, Rule{Priority: pyfmt.Str(rm["priority"]), When: when})
	}
	sla, _ := m["sla_days"].(map[string]any)
	for k, d := range sla {
		n, ok := d.(float64)
		if !ok {
			return nil, fmt.Errorf("sla_days.%s: a number is required", k)
		}
		pol.SLADays[k] = n
	}
	pol.Due = defaultDue()
	pol.Due.SLADays = maps.Clone(pol.SLADays)
	if due, ok := m["due"].(map[string]any); ok {
		d, err := pol.Due.overlay(due, "due")
		if err != nil {
			return nil, err
		}
		if _, ok := due["envs"]; ok {
			return nil, errors.New("due.envs: per-environment rules belong in orgs/<org>.yml")
		}
		pol.Due = d
		pol.SLADays = maps.Clone(d.SLADays)
	}
	feeds, _ := m["feeds"].(map[string]any)
	pol.KEVURL, _ = feeds["kev_url"].(string)
	pol.EPSSURL, _ = feeds["epss_url"].(string)
	return pol, nil
}

func isString(v any) bool { _, ok := v.(string); return ok }

// --- feeds ----------------------------------------------------------------------------------------------------------

type Feeds struct {
	KEV     map[string]bool
	KEVDue  map[string]string // CVE -> CISA's due date (YYYY-MM-DD), from kev_due.json
	EPSS    map[string]float64
	Updated string // when `kanareika feeds` last ran, "" = never
}

// Stats of a feed update, for the log.
type Stats struct {
	KEV      int    `json:"kev"`
	EPSS     int    `json:"epss"`
	IPDBCity string `json:"ipdb_city,omitempty"` // month of the DB-IP file, "" = none downloaded
	IPDBASN  string `json:"ipdb_asn,omitempty"`
}

// get: a response whose body must deliver data at least every `idle` (socket-timeout semantics of the Python
// version: a large download may take long as long as it keeps flowing).
func get(ctx context.Context, url string, idle time.Duration) (io.ReadCloser, error) {
	ctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(idle, cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
	return &idleBody{resp.Body, timer, idle, cancel}, nil
}

type idleBody struct {
	io.ReadCloser
	timer  *time.Timer
	idle   time.Duration
	cancel context.CancelFunc
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.timer.Reset(b.idle)
	return n, err
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	b.cancel()
	return b.ReadCloser.Close()
}

// writeFile: tmp + rename, so a reader never sees half a file.
func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// UpdateFeeds downloads the CISA KEV catalog, EPSS scores and the DB-IP Lite databases into FeedsDir.
func UpdateFeeds(ctx context.Context, pol *Policy) (Stats, error) {
	var st Stats
	dir := FeedsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return st, err
	}
	if pol.KEVURL == "" || pol.EPSSURL == "" {
		return st, errors.New("priority.yml: feeds.kev_url and feeds.epss_url are required")
	}
	ids, due, err := fetchKEV(ctx, pol.KEVURL)
	if err != nil {
		return st, err
	}
	b, _ := json.Marshal(ids)
	if err := writeFile(filepath.Join(dir, "kev.json"), b); err != nil {
		return st, err
	}
	b, _ = json.Marshal(due)
	if err := writeFile(filepath.Join(dir, "kev_due.json"), b); err != nil {
		return st, err
	}
	st.KEV = len(ids)
	epss, err := fetchEPSS(ctx, pol.EPSSURL)
	if err != nil {
		return st, err
	}
	b, _ = json.Marshal(epss)
	if err := writeFile(filepath.Join(dir, "epss.json"), b); err != nil {
		return st, err
	}
	st.EPSS = len(epss)
	ip := UpdateIPDB(ctx)
	st.IPDBCity, st.IPDBASN = ip["city"], ip["asn"]
	updated := time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00")
	return st, writeFile(filepath.Join(dir, "updated"), []byte(updated))
}

// fetchKEV: the catalog's CVE ids, and CISA's due date of each (the earliest when listed twice).
func fetchKEV(ctx context.Context, url string) ([]string, map[string]string, error) {
	r, err := get(ctx, url, 60*time.Second)
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()
	var kev struct {
		Vulnerabilities []struct {
			CveID   string `json:"cveID"`
			DueDate string `json:"dueDate"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&kev); err != nil {
		return nil, nil, fmt.Errorf("KEV: %w", err)
	}
	set := map[string]bool{}
	due := map[string]string{}
	for _, v := range kev.Vulnerabilities {
		set[v.CveID] = true
		if d, err := time.Parse(time.DateOnly, v.DueDate); err == nil {
			if old, ok := due[v.CveID]; !ok || d.Format(time.DateOnly) < old {
				due[v.CveID] = d.Format(time.DateOnly)
			}
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, due, nil
}

// fetchEPSS: a gzipped CSV, "#" comment lines first, then cve,epss,percentile.
func fetchEPSS(ctx context.Context, url string) (map[string]float64, error) {
	r, err := get(ctx, url, 120*time.Second)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("EPSS: %w", err)
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("EPSS: %w", err)
	}
	var lines []string
	for _, ln := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if !strings.HasPrefix(ln, "#") {
			lines = append(lines, ln)
		}
	}
	cr := csv.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	cr.FieldsPerRecord = -1
	rows, err := cr.ReadAll()
	if err != nil || len(rows) == 0 {
		return nil, fmt.Errorf("EPSS: bad CSV: %w", err)
	}
	cveCol, epssCol := slices.Index(rows[0], "cve"), slices.Index(rows[0], "epss")
	if cveCol < 0 || epssCol < 0 {
		return nil, fmt.Errorf("EPSS: no cve/epss columns in %v", rows[0])
	}
	out := make(map[string]float64, len(rows))
	for _, row := range rows[1:] {
		if len(row) <= max(cveCol, epssCol) {
			return nil, fmt.Errorf("EPSS: short row %v", row)
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(row[epssCol]), 64)
		if err != nil {
			return nil, fmt.Errorf("EPSS: %w", err)
		}
		out[row[cveCol]] = v
	}
	return out, nil
}

// ipdbURL: the DB-IP Lite file of a kind (city, asn) and month; tests point it at a local server.
var ipdbURL = "https://download.db-ip.com/free/dbip-%s-lite-%s.mmdb.gz"

// UpdateIPDB: DB-IP Lite (CC-BY 4.0, https://db-ip.com) — offline country/city + ASN, so IP lookups never leave the
// machine. Files: FeedsDir()/dbip-city.mmdb, dbip-asn.mmdb. Returns kind -> month downloaded; a kind that could not
// be fetched (this month's file may not be published yet, then last month's is tried) is missing.
func UpdateIPDB(ctx context.Context) map[string]string {
	out := map[string]string{}
	dir := FeedsDir()
	today := time.Now()
	months := []string{today.Format("2006-01"), today.AddDate(0, 0, -today.Day()).Format("2006-01")}
	for _, kind := range []string{"city", "asn"} {
		for _, m := range months {
			url := fmt.Sprintf(ipdbURL, kind, m)
			if err := download(ctx, url, filepath.Join(dir, "dbip-"+kind+".mmdb")); err != nil {
				continue
			}
			out[kind] = m
			break
		}
	}
	return out
}

func download(ctx context.Context, url, dest string) error {
	r, err := get(ctx, url, 300*time.Second)
	if err != nil {
		return err
	}
	defer r.Close()
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tmp := dest + ".tmp"
	w, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, gz)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// LoadFeeds: what `kanareika feeds` stored; missing files leave the rest empty (no feeds = no KEV/EPSS).
func LoadFeeds() (Feeds, error) {
	f := Feeds{KEV: map[string]bool{}, KEVDue: map[string]string{}, EPSS: map[string]float64{}}
	dir := FeedsDir()
	b, err := os.ReadFile(filepath.Join(dir, "kev.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	} else if err != nil {
		return f, err
	}
	var ids []string
	if err := json.Unmarshal(b, &ids); err != nil {
		return f, fmt.Errorf("kev.json: %w", err)
	}
	for _, id := range ids {
		f.KEV[id] = true
	}
	if b, err := os.ReadFile(filepath.Join(dir, "kev_due.json")); err == nil { // feeds from before 0.5 have none
		if err := json.Unmarshal(b, &f.KEVDue); err != nil {
			return f, fmt.Errorf("kev_due.json: %w", err)
		}
	}
	if b, err = os.ReadFile(filepath.Join(dir, "epss.json")); errors.Is(err, fs.ErrNotExist) {
		return f, nil
	} else if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f.EPSS); err != nil {
		return f, fmt.Errorf("epss.json: %w", err)
	}
	if b, err = os.ReadFile(filepath.Join(dir, "updated")); errors.Is(err, fs.ErrNotExist) {
		return f, nil
	} else if err != nil {
		return f, err
	}
	f.Updated = strings.TrimSpace(string(b))
	return f, nil
}

// --- rules ----------------------------------------------------------------------------------------------------------

// num: a YAML scalar as a number the way Python compares it (True == 1).
func num(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// eq is Python's == between a finding field and a policy value.
func eq(a, b any) bool {
	if x, ok := num(a); ok {
		y, ok := num(b)
		return ok && x == y
	}
	return a == b
}

// in is Python's `x in v`: membership for a list, substring for a string.
func in(x any, v any) bool {
	switch t := v.(type) {
	case []any:
		return slices.ContainsFunc(t, func(e any) bool { return eq(x, e) })
	case string:
		s, ok := x.(string)
		return ok && strings.Contains(t, s)
	}
	return false
}

func matches(f *finding.Finding, when map[string]any) bool {
	for k, v := range when {
		switch k {
		case "kev":
			if !eq(f.KEV, v) {
				return false
			}
		case "epss_gte":
			e := 0.0
			if f.EPSS != nil {
				e = *f.EPSS
			}
			if t, _ := num(v); e < t {
				return false
			}
		case "severity":
			if !in(f.Severity, v) {
				return false
			}
		case "exposure":
			if !in(f.Exposure, v) {
				return false
			}
		case "fixable":
			if !eq(f.Fixed != "", v) {
				return false
			}
		case "kind":
			if !in(f.Kind, v) {
				return false
			}
		case "kernel":
			if !eq(f.Kernel, v) {
				return false
			}
		case "preauth":
			if !eq(f.Preauth, v) {
				return false
			}
		case "rce":
			if !eq(f.RCE, v) {
				return false
			}
		case "id":
			if !in(f.ID, v) {
				return false
			}
		}
	}
	return true
}

func str(m map[string]any, k string) string {
	if m[k] == nil {
		return ""
	}
	return pyfmt.Str(m[k])
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

func fixInstallable(f *finding.Finding) bool {
	return f.FixState == finding.FixAvailable || f.FixState == finding.FixReboot
}

// exceptionFor: the first exception of the org that covers f, and whether it is active.
func exceptionFor(f *finding.Finding, org *config.Org, today string) (map[string]any, bool) {
	for _, ex := range org.Exceptions() {
		id, pkg := str(ex, "id"), str(ex, "package")
		if id != f.ID && !(id == "*" && pkg != "") { // "*" = every CVE of the package
			continue
		}
		if truthy(ex["hosts"]) && !in(f.Host, ex["hosts"]) {
			continue
		}
		if pkg != "" && !strings.Contains(f.Pkg, pkg) {
			continue
		}
		if truthy(ex["until_available"]) && fixInstallable(f) {
			return ex, false // accepted only while there was nothing to install; now there is
		}
		review, err := time.Parse(time.DateOnly, str(ex, "review_by"))
		return ex, err == nil && review.Format(time.DateOnly) >= today
	}
	return nil, false
}

// Prev: the same finding (report.KeyOf) in the env's state before this scan, nil when it is new.
type Prev func(*finding.Finding) *finding.Finding

func prioRank(p string) int {
	switch p {
	case "P1":
		return 1
	case "P2":
		return 2
	case "P3":
		return 3
	case "P4":
		return 4
	}
	return 9
}

// fixKnown: an installable fix exists. OS packages: the host's repositories say so; images and libraries: the
// advisory names a fixed version; misconfigurations and health findings are always fixable.
func fixKnown(f *finding.Finding) bool {
	if f.Kind != finding.Vuln {
		return true
	}
	if f.FixState != "" {
		return fixInstallable(f)
	}
	return f.Fixed != ""
}

func addDays(date string, days float64) string {
	t, err := time.Parse(time.DateOnly, date)
	if err != nil {
		return ""
	}
	return t.AddDate(0, 0, int(days)).Format(time.DateOnly)
}

// clock sets FirstSeen, FixSince, ClockStart, DueWhy and Due of a prioritized finding (see DueRules).
func clock(f *finding.Finding, p *finding.Finding, d DueRules, kevDue map[string]string, today string) {
	f.FirstSeen, f.FixSince, f.ClockStart, f.DueWhy, f.KEVDue, f.Due = today, "", "", "", "", nil
	if p != nil && p.FirstSeen != "" && p.FirstSeen < today {
		f.FirstSeen = p.FirstSeen
	}
	if fixKnown(f) {
		f.FixSince = today
		switch {
		case f.Kind != finding.Vuln:
			f.FixSince = f.FirstSeen
		case p != nil && p.FixSince != "" && p.FixSince < today:
			f.FixSince = p.FixSince
		}
	}
	if f.Kind == finding.Vuln {
		f.KEVDue = kevDue[f.ID]
	}
	days, ok := d.SLADays[f.PriorityOr()]
	if f.Priority == nil || !ok {
		return
	}
	start, why := f.FirstSeen, finding.DueFirstSeen
	switch d.Start {
	case finding.DueScan:
		start, why = today, finding.DueScan
	case finding.DueFixSince:
		if f.FixSince == "" {
			f.DueWhy = finding.DueNoFix
			return
		}
		start, why = f.FixSince, finding.DueFixSince
	case finding.DuePublished:
		if f.Published != "" {
			start, why = f.Published, finding.DuePublished
		}
	}
	due := addDays(start, days)
	if p != nil && d.Start != finding.DueScan {
		pr, cur := prioRank(p.PriorityOr()), prioRank(f.PriorityOr())
		switch {
		case p.Accepted && !f.Accepted && d.AfterException == "restart":
			start, why, due = today, finding.DueAfterExcept, addDays(today, days)
		case cur < pr && d.Escalation == "restart":
			// went up: the new SLA from today, but never later than the date it already had
			start, why, due = today, finding.DueEscalated, addDays(today, days)
			if p.DueOr() != "" && p.DueOr() < due {
				due = p.DueOr()
			}
		case cur == pr && (p.DueWhy == finding.DueEscalated || p.DueWhy == finding.DueAfterExcept) &&
			p.ClockStart != "" && p.DueOr() != "":
			start, why, due = p.ClockStart, p.DueWhy, p.DueOr() // still the restarted clock
		}
	}
	if d.KEV == "cisa" && f.KEVDue != "" && f.KEVDue < due {
		due, why = f.KEVDue, finding.DueKEV
	}
	f.ClockStart, f.DueWhy, f.Due = start, why, &due
}

// Apply sets kev / epss / priority / due / accepted / exception on every finding (in place; returned for
// convenience). scanDate: the date the run started; env: the environment (its due rules); prev: the env's state
// before this scan (nil: none), where the due date's clock carries over from.
func Apply(findings []finding.Finding, org *config.Org, env string, pol *Policy, feeds Feeds,
	scanDate time.Time, prev Prev) ([]finding.Finding, error) {
	today := scanDate.Format(time.DateOnly)
	rules, err := pol.DueFor(org, env)
	if err != nil {
		return findings, err
	}
	for i := range findings {
		f := &findings[i]
		f.KEV = feeds.KEV[f.ID]
		f.EPSS = nil
		if e, ok := feeds.EPSS[f.ID]; ok {
			f.EPSS = &e
		}
		f.Priority = nil
		if f.Inactive {
			p := "P4"
			f.Priority = &p
		} else if f.Kind != finding.Inventory {
			for _, r := range pol.Rules {
				if matches(f, r.When) {
					p := r.Priority
					f.Priority = &p
					break
				}
			}
		}
		ex, active := exceptionFor(f, org, today)
		f.Accepted = ex != nil && active
		f.Exception = nil
		if ex != nil {
			f.Exception = &finding.Exception{Reason: str(ex, "reason"), Owner: str(ex, "owner"),
				ReviewBy: str(ex, "review_by"), Expired: !active,
				FixAvailable: truthy(ex["until_available"]) && !active && fixInstallable(f)}
		}
		var p *finding.Finding
		if prev != nil {
			p = prev(f)
		}
		clock(f, p, rules, feeds.KEVDue, today)
	}
	return findings, nil
}
