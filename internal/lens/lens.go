// Package lens defines the per-server columns of the server view: a lens (priorities, logins, network, health)
// is a set of columns, and for every host a row of cells with a raw value, a display string, a level that decides
// the colour and a note saying why. The web page, the TUI and MCP only render what is defined here, so a new
// metric is a change in this package alone.
package lens

import (
	"cmp"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/report"
	"github.com/mikekosulin/kanareika/internal/tree"
)

// Column kinds: how a value is shown and sorted.
const (
	Text     = "text"
	Number   = "number"
	Percent  = "percent"  // v in 0..100
	Duration = "duration" // v in seconds
	Bytes    = "bytes"
	Bool     = "bool"
	Mark     = "mark" // a flag: v true shows a mark, false nothing
)

// Levels: the colour of a cell.
const (
	OK   = "ok"
	Warn = "warn"
	Bad  = "bad"
	None = "none" // nothing to judge (no data, not checked, or only informative)
)

// Thresholds: the limits every interface colours by (the health module raises findings at the same ones).
var (
	DiskWarn, DiskBad = 85.0, 95.0 // % used, disks and inodes
	MemWarn, MemBad   = 10.0, 5.0  // % free
	LoadWarnPerCPU    = 2.0        // 15-minute load per CPU
	OffsetWarn        = 1.0        // s, the NTP offset
	SkewWarn, SkewBad = 2.0, 30.0  // s, the clock vs the scanner's
	FailedLoginsWarn  = 1          // failed logins in the last day of the log, from one
	FailedLoginsBad   = 1000       // ... and many
)

// What a cell shows when the value is unknown (not checked) or there is none.
const (
	ResultUnknown = "?"
	NoData        = "—"
)

type Column struct {
	Key       string `json:"key"`
	Title     string `json:"title"`     // in the asked language
	TitleKey  string `json:"title_key"` // its message key
	Kind      string `json:"kind"`
	Align     string `json:"align"` // left, right, center
	Unit      string `json:"unit,omitempty"`
	WidthHint int    `json:"width_hint"` // characters
	Drop      int    `json:"drop"`       // hidden first on narrow screens: the highest first; 0 = always shown
	Sortable  bool   `json:"sortable"`
}

type Cell struct {
	V     any    `json:"v"`              // the raw value (number, string, bool, list) or null
	S     string `json:"s"`              // what to show
	Level string `json:"level"`          // ok, warn, bad, none
	Note  string `json:"note,omitempty"` // why, in plain words (in the asked language)
}

type Row struct {
	Host    string          `json:"host"`
	State   string          `json:"state"`             // as the server view: todo, clean, partial, failed, not_scanned
	Problem string          `json:"problem,omitempty"` // failed / not scanned / partial: why (in the asked language)
	Cells   map[string]Cell `json:"cells"`
}

// Lens: a lens definition. Its Title and the columns' titles are message keys (lens.<id>, lens.col.<key>).
type Lens struct {
	ID      string
	Columns []Column
	cells   func(c *ctx, h *host) map[string]Cell
}

// Ref: a lens in a list (id and title).
type Ref struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Info: one lens with its localized columns.
type Info struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Columns []Column `json:"columns"`
}

// Result: what /api/lens and MCP list_servers answer.
type Result struct {
	Lenses []Ref  `json:"lenses"`
	Lens   Info   `json:"lens"`
	Rows   []Row  `json:"rows"`
	Totals Totals `json:"totals"` // rows per state
}

type Totals map[string]int

func col(key, kind, align, unit string, width, drop int) Column {
	return Column{Key: key, TitleKey: "lens.col." + key, Kind: kind, Align: align, Unit: unit, WidthHint: width, Drop: drop,
		Sortable: true}
}

// All: the lenses, in the order the switch shows them.
var All = []Lens{
	{ID: "priorities", Columns: []Column{
		col("os", Text, "left", "", 16, 3), col("internet", Mark, "center", "", 3, 4),
		col("P1", Number, "right", "", 4, 0), col("P2", Number, "right", "", 4, 0), col("P3", Number, "right", "", 4, 1),
		col("P4", Number, "right", "", 4, 2), col("fixes", Number, "right", "", 5, 0), col("cves", Number, "right", "", 5, 1),
		col("last_scan", Text, "left", "", 16, 5),
	}, cells: priorities},
	{ID: "logins", Columns: []Column{
		col("password", Bool, "left", "", 6, 0), col("root", Text, "left", "", 8, 1), col("pw_users", Number, "right", "", 6, 2),
		col("keys", Number, "right", "", 5, 3), col("failed_24h", Number, "right", "", 7, 0), col("last_attack", Text, "left", "", 16, 4),
	}, cells: logins},
	{ID: "network", Columns: []Column{
		col("public_ips", Text, "left", "", 16, 1), col("open_ports", Text, "left", "", 18, 0), col("firewall", Text, "left", "", 12, 0),
		col("listening", Number, "right", "", 5, 2),
	}, cells: network},
	{ID: "health", Columns: []Column{
		col("disk", Percent, "right", "%", 12, 0), col("inodes", Percent, "right", "%", 5, 4), col("mem_free", Percent, "right", "%", 5, 1),
		col("load", Number, "right", "", 7, 3), col("failed_units", Number, "right", "", 4, 2), col("reboot", Mark, "center", "", 3, 5),
		col("journal", Number, "right", "", 6, 6), col("clock", Duration, "right", "s", 7, 2), col("timezone", Text, "left", "", 14, 7),
	}, cells: health},
}

// Get: the lens with id; the first one when id is empty; nil when unknown.
func Get(id string) *Lens {
	if id == "" {
		return &All[0]
	}
	for i := range All {
		if All[i].ID == id {
			return &All[i]
		}
	}
	return nil
}

// IDs of the lenses.
func IDs() []string {
	out := make([]string, len(All))
	for i, l := range All {
		out[i] = l.ID
	}
	return out
}

// Input: what the rows are made from: the server view's host rows (order, state, counts), the run's view (per-host
// facts of access, exposure and health) and its findings.
type Input struct {
	Servers  *tree.Tree // tree.Build by host with Opts.All
	View     *report.View
	Findings []finding.Finding
	Lang     string
}

type ctx struct {
	in     Input
	tzMain string
	reboot map[string]bool
	lang   string
}

type host struct {
	node                     *tree.Node
	access, exposure, health map[string]any
}

// Build: lens l over the input, localized.
func Build(l *Lens, in Input) Result {
	lang := cmp.Or(in.Lang, i18n.Default)
	c := &ctx{in: in, lang: lang, reboot: map[string]bool{}}
	tzs := map[string]int{}
	if in.View != nil {
		for _, v := range in.View.Health {
			if tz := str(get(v, "time", "timezone")); tz != "" {
				tzs[tz]++
			}
		}
	}
	for tz, n := range tzs {
		if n > tzs[c.tzMain] || n == tzs[c.tzMain] && tz < c.tzMain {
			c.tzMain = tz
		}
	}
	for _, f := range in.Findings {
		if f.ID == "reboot-required" && !f.Accepted {
			c.reboot[f.Host] = true
		}
	}
	res := Result{Lens: Info{ID: l.ID, Title: i18n.T("lens."+l.ID, lang, nil)}, Rows: []Row{}, Totals: Totals{}}
	for _, x := range All {
		res.Lenses = append(res.Lenses, Ref{ID: x.ID, Title: i18n.T("lens."+x.ID, lang, nil)})
	}
	for _, cl := range l.Columns {
		cl.Title = i18n.T(cl.TitleKey, lang, nil)
		res.Lens.Columns = append(res.Lens.Columns, cl)
	}
	if in.Servers == nil {
		return res
	}
	for _, n := range in.Servers.Nodes {
		r := Row{Host: n.Label, State: n.State, Cells: map[string]Cell{}}
		if n.ProblemMsg != "" {
			r.Problem = i18n.Render(n.Problem, n.ProblemMsg, n.ProblemArgs, lang)
		} else {
			r.Problem = n.Problem
		}
		res.Totals[n.State]++
		if n.State != tree.StateFailed && n.State != tree.StateNotScanned {
			h := &host{node: n}
			if in.View != nil {
				h.access, _ = in.View.Access[n.Label].(map[string]any)
				h.exposure, _ = in.View.Exposure[n.Label].(map[string]any)
				h.health, _ = in.View.Health[n.Label].(map[string]any)
			}
			r.Cells = l.cells(c, h)
		}
		res.Rows = append(res.Rows, r)
	}
	return res
}

// --- cells -------------------------------------------------------------------------------------------------------

func (c *ctx) t(key string, args map[string]any) string { return i18n.T(key, c.lang, args) }

// notChecked: a cell the module could not fill without root.
func (c *ctx) notChecked() Cell {
	return Cell{V: nil, S: ResultUnknown, Level: None, Note: c.t("lens.not_checked", nil)}
}

func none() Cell { return Cell{V: nil, S: NoData, Level: None} }

func num(v int, level string) Cell { return Cell{V: v, S: strconv.Itoa(v), Level: level} }

func priorities(c *ctx, h *host) map[string]Cell {
	n := h.node
	out := map[string]Cell{}
	if n.OSShort != "" {
		out["os"] = Cell{V: n.OS, S: n.OSShort, Level: None}
	} else {
		out["os"] = none()
	}
	if n.Exposure == 1 {
		out["internet"] = Cell{V: true, S: "●", Level: None, Note: c.t("lens.note.internet", nil)}
	} else {
		out["internet"] = Cell{V: false, S: "", Level: None}
	}
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		v, lv := n.Counts[p], OK
		switch {
		case v > 0 && p == "P1":
			lv = Bad
		case v > 0 && p == "P2":
			lv = Warn
		case v > 0:
			lv = None
		}
		out[p] = num(v, lv)
	}
	out["fixes"] = num(n.Fixes, None)
	out["cves"] = num(n.CVEs, None)
	if n.LastScan != "" {
		out["last_scan"] = Cell{V: n.LastScan, S: strings.Replace(n.LastScan[:min(16, len(n.LastScan))], "T", " ", 1), Level: None}
	} else {
		out["last_scan"] = none()
	}
	return out
}

func denied(data map[string]any, key string) bool {
	return slices.Contains(strs(data["denied"]), key)
}

func logins(c *ctx, h *host) map[string]Cell {
	a := h.access
	out := map[string]Cell{}
	if a == nil {
		for _, k := range []string{"password", "root", "pw_users", "keys", "failed_24h", "last_attack"} {
			out[k] = none()
		}
		return out
	}
	nc := c.notChecked()
	users := strs(a["users_with_password"])
	usersKnown := a["users_with_password"] != nil && !denied(a, "denied.shadow")
	switch pw := a["password_auth"].(type) {
	case bool:
		switch {
		case !pw:
			out["password"] = Cell{V: false, S: c.t("lens.off", nil), Level: OK}
		case len(users) > 0:
			out["password"] = Cell{V: true, S: c.t("lens.on", nil), Level: Bad,
				Note: c.t("ssh.password.users", map[string]any{"users": strings.Join(users, ", ")})}
		case usersKnown:
			out["password"] = Cell{V: true, S: c.t("lens.on", nil), Level: Warn, Note: c.t("ssh.password.none", nil)}
		default:
			out["password"] = Cell{V: true, S: c.t("lens.on", nil), Level: Warn, Note: c.t("ssh.password.unknown", nil)}
		}
	default:
		out["password"] = nc
	}
	switch v := str(get(a, "sshd", "permitrootlogin")); v {
	case "":
		if denied(a, "denied.sshd") {
			out["root"] = nc
		} else {
			out["root"] = none()
		}
	case "yes":
		out["root"] = Cell{V: v, S: c.t("lens.yes", nil), Level: Bad, Note: c.t("lens.note.root_password", nil)}
	case "no":
		out["root"] = Cell{V: v, S: c.t("lens.no", nil), Level: OK}
	case "without-password", "prohibit-password":
		out["root"] = Cell{V: v, S: c.t("lens.key_only", nil), Level: OK}
	case "forced-commands-only":
		out["root"] = Cell{V: v, S: c.t("lens.commands", nil), Level: OK}
	default:
		out["root"] = Cell{V: v, S: v, Level: None}
	}
	if usersKnown {
		lv := OK
		if len(users) > 0 {
			lv = Warn
		}
		cl := num(len(users), lv)
		if len(users) > 0 {
			cl.Note = strings.Join(users, ", ")
		}
		out["pw_users"] = cl
	} else {
		out["pw_users"] = nc
	}
	keys := list(a["keys"])
	root := 0
	for _, k := range keys {
		if str(get(k, "user")) == "root" {
			root++
		}
	}
	kc := num(len(keys), None)
	kc.Note = c.t("lens.note.root_keys", map[string]any{"n": root})
	if denied(a, "denied.keys") {
		kc.Note = c.t("lens.note.own_keys_only", nil)
	}
	out["keys"] = kc
	if denied(a, "denied.authlog") {
		out["failed_24h"], out["last_attack"] = nc, nc
		return out
	}
	daily, _ := get(a, "logins", "failed_daily").(map[string]any)
	lastDay := ""
	for d := range daily {
		lastDay = max(lastDay, d)
	}
	n := 0
	if lastDay != "" && c.recentDay(h, lastDay) {
		n = int(number(daily[lastDay]))
	}
	lv := OK
	if n >= FailedLoginsBad {
		lv = Bad
	} else if n >= FailedLoginsWarn {
		lv = Warn
	}
	fc := num(n, lv)
	if total := int(number(get(a, "logins", "failed_total"))); total > 0 {
		fc.Note = c.t("lens.note.failed_total", map[string]any{"n": total, "ips": int(number(get(a, "logins", "failed_ips")))})
	}
	out["failed_24h"] = fc
	last := str(get(a, "logins", "failed_last"))
	for _, at := range list(get(a, "logins", "attackers")) {
		last = max(last, str(get(at, "last")))
	}
	if last != "" {
		out["last_attack"] = Cell{V: last, S: strings.Replace(last[:min(16, len(last))], "T", " ", 1), Level: None}
	} else {
		out["last_attack"] = none()
	}
	return out
}

// recentDay: day (YYYY-MM-DD) is within 24 h of when the host's logins were read: that day or the one before (the
// access module's own run, else the host's last scan). An older day is not "the last 24 h". Unknown scan time: true.
func (c *ctx) recentDay(h *host, day string) bool {
	at := time.Time{}
	if v := c.in.View; v != nil && v.Meta != nil {
		if run := v.Meta.Sources[h.node.Label]["access"]; run != "" {
			at, _ = time.Parse("2006-01-02_150405", run)
		}
	}
	if at.IsZero() {
		at, _ = time.Parse(time.RFC3339, h.node.LastScan)
	}
	if at.IsZero() {
		return true
	}
	d, err := time.Parse(time.DateOnly, day)
	if err != nil {
		return false
	}
	scanDay := at.UTC().Truncate(24 * time.Hour)
	return !d.Before(scanDay.AddDate(0, 0, -1))
}

func network(c *ctx, h *host) map[string]Cell {
	e := h.exposure
	out := map[string]Cell{}
	if e == nil {
		for _, k := range []string{"public_ips", "open_ports", "firewall", "listening"} {
			out[k] = none()
		}
		return out
	}
	pub, unlisted := strs(e["public"]), strs(e["unlisted_public"])
	switch {
	case len(unlisted) > 0:
		out["public_ips"] = Cell{V: pub, S: strings.Join(pub, " "), Level: Bad,
			Note: c.t("lens.note.unlisted", map[string]any{"ips": strings.Join(unlisted, ", ")})}
	case len(pub) > 0:
		out["public_ips"] = Cell{V: pub, S: strings.Join(pub, " "), Level: None}
	default:
		out["public_ips"] = Cell{V: []string{}, S: NoData, Level: None, Note: c.t("lens.note.no_public", nil)}
	}
	ports := map[int]bool{}
	listening := 0
	for _, l := range list(e["listen"]) {
		if b, _ := get(l, "local_only").(bool); b {
			continue
		}
		listening++
		if b, _ := get(l, "public").(bool); b {
			ports[int(number(get(l, "port")))] = true
		}
	}
	pl := make([]int, 0, len(ports))
	for p := range ports {
		pl = append(pl, p)
	}
	sort.Ints(pl)
	if len(pl) == 0 {
		out["open_ports"] = Cell{V: pl, S: NoData, Level: OK}
	} else {
		s := make([]string, len(pl))
		for i, p := range pl {
			s[i] = strconv.Itoa(p)
		}
		out["open_ports"] = Cell{V: pl, S: strings.Join(s, " "), Level: Warn, Note: c.t("lens.note.open_ports", nil)}
	}
	fw, _ := e["firewall"].(map[string]any)
	switch {
	case fw == nil || fw["readable"] == false || denied(e, "denied.firewall"):
		out["firewall"] = c.notChecked()
	default:
		var parts []string
		if fw["firewalld"] == "running" {
			parts = append(parts, "firewalld")
		}
		if b, _ := fw["ufw_active"].(bool); b {
			parts = append(parts, "ufw")
		}
		if p := str(fw["iptables_input_policy"]); p != "" {
			parts = append(parts, "INPUT "+p)
		}
		if b, _ := fw["docker_rules"].(bool); b {
			parts = append(parts, "docker")
		}
		if b, _ := fw["has_input_filtering"].(bool); b {
			out["firewall"] = Cell{V: true, S: cmp.Or(first(parts), c.t("lens.filtering", nil)), Level: OK, Note: strings.Join(parts, " · ")}
		} else {
			out["firewall"] = Cell{V: false, S: c.t("lens.no_filtering", nil), Level: Bad, Note: strings.Join(parts, " · ")}
		}
	}
	out["listening"] = num(listening, None)
	return out
}

func first(l []string) string {
	if len(l) == 0 {
		return ""
	}
	return l[0]
}

// worst: the fullest mount of a list of {mount, use}.
func worst(rows []any) (string, float64, string) {
	var mount, all string
	use := -1.0
	var parts []string
	for _, r := range rows {
		u := number(get(r, "use"))
		parts = append(parts, fmt.Sprintf("%s %.0f%%", str(get(r, "mount")), u))
		if u > use {
			mount, use = str(get(r, "mount")), u
		}
	}
	all = strings.Join(parts, ", ")
	return mount, use, all
}

func usedLevel(use float64) string {
	switch {
	case use >= DiskBad:
		return Bad
	case use >= DiskWarn:
		return Warn
	}
	return OK
}

func health(c *ctx, h *host) map[string]Cell {
	x := h.health
	out := map[string]Cell{}
	keys := []string{"disk", "inodes", "mem_free", "load", "failed_units", "journal", "clock", "timezone"}
	if c.reboot[h.node.Label] {
		out["reboot"] = Cell{V: true, S: "●", Level: Warn, Note: c.t("hardening.reboot", nil)}
	} else {
		out["reboot"] = Cell{V: false, S: "", Level: None}
	}
	if x == nil {
		for _, k := range keys {
			out[k] = none()
		}
		return out
	}
	for _, k := range []string{"disks", "inodes"} {
		key := map[string]string{"disks": "disk", "inodes": "inodes"}[k]
		rows := list(x[k])
		if len(rows) == 0 {
			out[key] = none()
			continue
		}
		mount, use, all := worst(rows)
		s := fmt.Sprintf("%.0f%%", use)
		if key == "disk" {
			s += " " + mount
		}
		out[key] = Cell{V: use, S: s, Level: usedLevel(use), Note: all}
	}
	if total := number(get(x, "mem", "total_mb")); total > 0 {
		exact := 100 * number(get(x, "mem", "available_mb")) / total // compared unrounded, as the health module does
		free := math.Round(exact)
		lv := OK
		if exact < MemBad {
			lv = Bad
		} else if exact <= MemWarn {
			lv = Warn
		}
		out["mem_free"] = Cell{V: free, S: fmt.Sprintf("%.0f%%", free), Level: lv,
			Note: c.t("health.mem.detail", map[string]any{"avail": int(number(get(x, "mem", "available_mb"))), "total": int(total)})}
	} else {
		out["mem_free"] = none()
	}
	if ld, ok := x["load"].(map[string]any); ok {
		l15, cpus := number(ld["load15"]), max(1, number(ld["cpus"]))
		lv := OK
		if l15 > cpus*LoadWarnPerCPU {
			lv = Warn
		}
		out["load"] = Cell{V: l15, S: fmt.Sprintf("%s/%d", strconv.FormatFloat(l15, 'f', -1, 64), int(cpus)), Level: lv,
			Note: c.t("health.load.detail", map[string]any{"load": l15, "cpus": int(cpus)})}
	} else {
		out["load"] = none()
	}
	units := strs(x["failed_units"])
	uc := num(len(units), OK)
	if len(units) > 0 {
		uc.Level, uc.Note = Warn, strings.Join(units, ", ")
	}
	out["failed_units"] = uc
	if denied(x, "denied.journal") {
		out["journal"] = c.notChecked()
	} else if j := get(x, "journal", "errors_7d"); j != nil {
		out["journal"] = num(int(number(j)), None)
	} else {
		out["journal"] = none()
	}
	out["clock"] = c.clock(x)
	if tz := str(get(x, "time", "timezone")); tz == "" {
		out["timezone"] = none()
	} else if c.tzMain != "" && tz != c.tzMain {
		out["timezone"] = Cell{V: tz, S: tz, Level: Warn, Note: c.t("lens.note.tz", map[string]any{"tz": c.tzMain})}
	} else {
		out["timezone"] = Cell{V: tz, S: tz, Level: OK}
	}
	return out
}

// clock: the NTP offset, judged with the sync state and the skew against the scanner.
func (c *ctx) clock(x map[string]any) Cell {
	tm, ok := x["time"].(map[string]any)
	if !ok {
		return none()
	}
	off, hasOff := tm["offset_s"], tm["offset_s"] != nil
	skew, hasSkew := number(tm["skew_s"]), tm["skew_s"] != nil
	cl := Cell{V: nil, S: NoData, Level: OK}
	if hasOff {
		o := number(off)
		cl.V = o
		if math.Abs(o) < 1 {
			cl.S = fmt.Sprintf("%.0f ms", o*1000)
		} else {
			cl.S = fmt.Sprintf("%.1f s", o)
		}
	}
	active, _ := tm["service_active"].(bool)
	switch {
	case str(tm["synced"]) == "no":
		cl.Level, cl.Note = Bad, c.t("lens.note.not_synced", nil)
	case hasSkew && math.Abs(skew) > SkewBad:
		cl.Level, cl.Note = Bad, c.t("health.skew", map[string]any{"skew": fmt.Sprintf("%.0f", skew)})
	case hasOff && math.Abs(number(off)) > OffsetWarn:
		cl.Level, cl.Note = Warn, c.t("health.ntp_offset", nil)
	case hasSkew && math.Abs(skew) > SkewWarn:
		cl.Level, cl.Note = Warn, c.t("health.skew", map[string]any{"skew": fmt.Sprintf("%.0f", skew)})
	case !active:
		cl.Level, cl.Note = Warn, c.t("lens.note.no_ntp_service", nil)
	}
	return cl
}

// --- decoded JSON helpers ----------------------------------------------------------------------------------------

func get(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func strs(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		out := make([]string, 0, len(l))
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func number(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}
