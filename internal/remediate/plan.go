// Package remediate builds fix plans for selected actions: per host, how to connect, what to run as root, how to
// verify and how to roll back.
//
// Each step runs on the host over SSH as the ADMIN user (the audit user is read-only by design) with sudo, keeps
// its backups in /var/backups/kanareika/<fix id>/step<n>/ and knows how to undo itself. Nothing reboots: when a
// reboot is needed the step says so. The shell is the same, byte for byte, as the Python implementation's.
package remediate

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
	"github.com/mikekosulin/kanareika/internal/report"
)

// Now is the clock fix ids and review dates come from (tests pin it).
var Now = time.Now

// Plan: what fix_plan returns and render_markdown prints. ExceptionsYAML is set when vendor actions were selected.
type Plan struct {
	FixID          string   `json:"fix_id"`
	Steps          []Step   `json:"steps"`
	Manual         []Manual `json:"manual"`
	ExceptionsYAML string   `json:"exceptions_yaml,omitempty"`
}

type Step struct {
	Step       int     `json:"step"`
	Host       string  `json:"host"`
	Priority   *string `json:"priority"`
	Action     string  `json:"action"`
	Connect    string  `json:"connect"`
	RunAs      string  `json:"run_as"`
	Reversible bool    `json:"reversible"`
	Note       string  `json:"note"`
	BackupDir  string  `json:"backup_dir"`
	Apply      string  `json:"apply"`
	Verify     string  `json:"verify"`
	Rollback   string  `json:"rollback"`
}

// Manual: an action on a host without a ready recipe (or one that also needs a human decision).
type Manual struct {
	Action string `json:"action"`
	Host   string `json:"host"`
	Why    string `json:"why"`
}

// Route: how to reach the host — ssh user@address, through the jump chain if any.
func Route(org *config.Org, h *config.Host) string {
	jumps := org.Jumps()
	user, _ := org.Access()["user"].(string)
	var chain []string
	for cur := h.Jump; cur != ""; {
		j := jumps[cur]
		u, ok := j["user"].(string)
		if !ok {
			u = user
		}
		s := u + "@" + str(j["address"])
		if p, ok := num(j["port"]); ok && p != 22 {
			s += ":" + pyfmt.Str(p)
		}
		chain = append(chain, s)
		cur = str(j["jump"])
	}
	target := h.User + "@" + h.Address
	if h.Port != 22 {
		target += fmt.Sprintf(" -p %d", h.Port)
	}
	if len(chain) == 0 {
		return "ssh " + target
	}
	slices.Reverse(chain)
	return "ssh -J " + strings.Join(chain, ",") + " " + target
}

// StepsFor: the recipes for one action on one host, or nil and the message key of why it is not scriptable.
func StepsFor(a *report.Action, host string, v *report.View) ([]Recipe, string) {
	var osName string
	if f, ok := v.Facts[host]; ok && f.OS != nil {
		osName = *f.OS
	}
	fam := Family(osName)
	one := func(r Recipe) ([]Recipe, string) { return []Recipe{r}, "" }
	switch a.Cat {
	case "kernel":
		if a.Msg == "act.reboot" {
			return one(Reboot(fam))
		}
		return one(Kernel(fam))
	case "os":
		var pkgs []string
		for _, r := range v.Plan {
			if r.Host == host && r.Target == "os" && r.Fixed != "" && !r.Kernel && deref(r.FixState) != "vendor" {
				pkgs = append(pkgs, r.Pkg)
			}
		}
		if len(pkgs) == 0 {
			return nil, "manual.no_fixed"
		}
		return one(OSPackages(fam, pkgs))
	case "vendor":
		rows := VendorRows(v, host)
		if len(rows) == 0 {
			return nil, "manual.no_fixed"
		}
		pkgs := make([]string, len(rows))
		for i, r := range rows {
			pkgs[i] = r.Pkg
		}
		steps := []Recipe{VendorCheck(fam, pkgs), VendorUsers(fam, pkgs)}
		// one stop step per unit set, named by the packages that share it. Python iterates a set here (order
		// varies between runs when there are several); first appearance keeps it stable.
		var sets [][]string
		for _, p := range pkgs {
			if u := Mitigations[p]; len(u) > 0 && !slices.ContainsFunc(sets, func(s []string) bool { return slices.Equal(s, u) }) {
				sets = append(sets, u)
			}
		}
		for _, u := range sets {
			var what []string
			for _, p := range pkgs {
				if slices.Equal(Mitigations[p], u) {
					what = append(what, p)
				}
			}
			steps = append(steps, DisableUnits(u, strings.Join(what, " / ")))
		}
		return steps, ""
	case "cleanup":
		return one(OldKernels(fam))
	}
	switch a.Msg {
	case "ssh.password":
		return one(SSHHardening(fam, true, false))
	case "ssh.root":
		return one(SSHHardening(fam, false, true))
	case "health.ntp":
		return one(NTP(fam))
	case "net.close":
		return closePort(a, host, v)
	}
	switch a.Cat {
	case "image":
		return nil, "manual.image"
	case "eol":
		return nil, "manual.eol"
	}
	return nil, "manual.none"
}

// closePort: rpcbind on 111 is turned off; anything else gets a firewall rule, in DOCKER-USER when docker publishes
// the port (or no process is known: docker-proxy is not always visible).
func closePort(a *report.Action, host string, v *report.View) ([]Recipe, string) {
	port, ok := num(a.Args["port"])
	if !ok || port == 0 { // older actions: the port only in the title ("… :8080 …")
		t := a.Title[strings.LastIndex(a.Title, ":")+1:]
		p, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return nil, "manual.none" // Python fails on such a title; nothing to script either way
		}
		port = float64(p)
	}
	var socks []map[string]any
	exp, _ := v.Exposure[host].(map[string]any)
	listen, _ := exp["listen"].([]any)
	for _, x := range listen {
		m, _ := x.(map[string]any)
		if p, ok := num(m["port"]); ok && p == port && pyfmt.Truthy(m["public"]) {
			socks = append(socks, m)
		}
	}
	proc := func(m map[string]any) string { return str(m["process"]) }
	if port == 111 && slices.ContainsFunc(socks, func(m map[string]any) bool { return proc(m) == "rpcbind" || proc(m) == "systemd" }) {
		return []Recipe{Rpcbind()}, ""
	}
	proto := "tcp"
	if len(socks) > 0 {
		proto = str(socks[0]["proto"])
	}
	proto = strings.ReplaceAll(proto, "6", "")
	if strings.HasPrefix(proto, "udp") {
		proto = "udp"
	} else {
		proto = "tcp"
	}
	docker := slices.ContainsFunc(socks, func(m map[string]any) bool { return proc(m) == "docker-proxy" }) ||
		!slices.ContainsFunc(socks, func(m map[string]any) bool { return proc(m) != "" })
	return []Recipe{RestrictPort(int(port), proto, docker)}, ""
}

// VendorRows: the host's OS packages fixed in the advisory but not yet in its repositories.
func VendorRows(v *report.View, host string) []report.PlanRow {
	var out []report.PlanRow
	for _, r := range v.Plan {
		if r.Host == host && r.Target == "os" && deref(r.FixState) == "vendor" {
			out = append(out, r)
		}
	}
	return out
}

// ExceptionYAML: one exceptions: entry per package and host for findings with no fix in the repositories. id "*"
// covers all CVEs of the package; until_available ends it by itself once an update can be installed, review_by
// at the latest.
func ExceptionYAML(rows []report.PlanRow, owner, reviewBy string) string {
	rows = slices.Clone(rows)
	slices.SortStableFunc(rows, func(a, b report.PlanRow) int {
		if c := strings.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		return strings.Compare(a.Pkg, b.Pkg)
	})
	var out []string
	for _, r := range rows {
		out = append(out, fmt.Sprintf(`  - id: "*"                    # %d CVE, e.g. %s`, r.CVEs, strings.Join(r.CVETop[:min(3, len(r.CVETop))], ", ")),
			"    hosts: ["+r.Host+"]", "    package: "+r.Pkg,
			`    reason: "no fix in the host repositories yet (advisory: `+r.Fixed+`); see fix plan mitigations"`,
			`    owner: "`+owner+`"`, "    review_by: "+reviewBy, "    until_available: true")
	}
	return strings.Join(out, "\n")
}

// FixID: fix-<time>-<hash of the selection>; the backups of one plan live under it.
func FixID(ids []string, now time.Time) string {
	s := slices.Clone(ids)
	slices.Sort(s)
	sum := sha1.Sum([]byte(strings.Join(s, ",")))
	return "fix-" + now.Format("20060102-150405") + "-" + hex.EncodeToString(sum[:])[:6]
}

// BuildPlan: readable, step-by-step fix plan for the selected actions of one environment (in the view's order).
func BuildPlan(org *config.Org, env string, v *report.View, ids []string, lang string) *Plan {
	sel := map[string]bool{}
	for _, id := range ids {
		sel[id] = true
	}
	hosts := map[string]*config.Host{}
	for i := range org.Hosts {
		if org.Hosts[i].Env == env {
			hosts[org.Hosts[i].Name] = &org.Hosts[i]
		}
	}
	now := Now()
	p := &Plan{FixID: FixID(ids, now), Steps: []Step{}, Manual: []Manual{}}
	reviewBy := now.AddDate(0, 0, 14).Format(time.DateOnly)
	var accept []report.PlanRow
	for i := range v.Actions {
		a := &v.Actions[i]
		if !sel[a.ID] {
			continue
		}
		title := i18n.Render(a.Title, a.Msg, a.Args, lang)
		for _, h := range a.Hosts {
			hc := hosts[h]
			if hc == nil {
				continue
			}
			recipes, why := StepsFor(a, h, v)
			if len(recipes) == 0 {
				p.Manual = append(p.Manual, Manual{Action: title, Host: h, Why: i18n.T(why, lang, nil)})
				continue
			}
			if a.Cat == "vendor" {
				accept = append(accept, VendorRows(v, h)...)
				p.Manual = append(p.Manual, Manual{Action: title, Host: h,
					Why: i18n.T("fix.vendor.exception", lang, map[string]any{"org": org.ID, "date": reviewBy})})
			}
			route := Route(org, hc)
			if hc.AdminUser != "" { // fixes need an admin account; the audit user is read-only on purpose
				route = strings.ReplaceAll(route, hc.User+"@"+hc.Address, hc.AdminUser+"@"+hc.Address)
			}
			for _, r := range recipes {
				p.addStep(a, h, r, route, lang)
			}
		}
	}
	if len(accept) > 0 {
		p.ExceptionsYAML = "exceptions:\n" + ExceptionYAML(accept, owner(org), reviewBy)
	}
	return p
}

// owner of exception entries: the org's first named contact.
func owner(org *config.Org) string {
	o, _ := org.Data["org"].(map[string]any)
	cs, _ := o["contacts"].([]any)
	for _, c := range cs {
		m, _ := c.(map[string]any)
		if n := str(m["name"]); n != "" {
			return n
		}
	}
	return "owner"
}

func (p *Plan) addStep(a *report.Action, h string, r Recipe, route, lang string) {
	n := len(p.Steps) + 1
	backup := fmt.Sprintf("/var/backups/kanareika/%s/step%d", p.FixID, n)
	prelude := "B=" + backup + `; mkdir -p "$B"; chmod 700 "$B"` + "\n"
	p.Steps = append(p.Steps, Step{
		Step: n, Host: h, Priority: a.Priority, Action: i18n.Render(a.Title, a.Msg, a.Args, lang),
		Connect: route, RunAs: "root (sudo -i)", Reversible: r.Reversible,
		Note: i18n.T(r.Note, lang, r.NoteArgs), BackupDir: backup,
		Apply:    strings.TrimSpace(prelude + strings.TrimSpace(r.Apply)),
		Verify:   strings.TrimSpace(r.Verify),
		Rollback: strings.TrimSpace("B=" + backup + "\n" + strings.TrimSpace(r.Rollback)),
	})
}

var md = map[string]map[string]string{
	"en": {"title": "Fix steps", "connect": "Connect", "apply": "Apply (as root)", "verify": "Verify", "rollback": "Roll back",
		"irrev": "IRREVERSIBLE", "manual": "Manual (no ready recipe)", "order": "Do one host first, verify, then the rest. Backups: {dir} on each host."},
	"ru": {"title": "Шаги исправления", "connect": "Подключение", "apply": "Применить (под root)", "verify": "Проверить", "rollback": "Откатить",
		"irrev": "НЕОБРАТИМО", "manual": "Вручную (готового рецепта нет)", "order": "Сначала один хост, проверка, потом остальные. Резервные копии: {dir} на каждом хосте."},
	"zh": {"title": "修复步骤", "connect": "连接", "apply": "应用（以 root 身份）", "verify": "验证", "rollback": "回滚",
		"irrev": "不可逆", "manual": "手动（无现成方案）", "order": "先处理一台主机并验证，再处理其余主机。备份：每台主机上的 {dir}。"},
}

// RenderMarkdown: the plan as a section of a task (prompt) or a ticket; "" for an empty plan.
func RenderMarkdown(p *Plan, lang string) string {
	T := md[lang]
	if T == nil {
		T = md[i18n.Default]
	}
	if len(p.Steps) == 0 && len(p.Manual) == 0 {
		return ""
	}
	out := []string{"## " + T["title"], "", strings.ReplaceAll(T["order"], "{dir}", "/var/backups/kanareika/"+p.FixID+"/stepN")}
	for _, s := range p.Steps {
		head := fmt.Sprintf("### %d. [%s] %s — %s", s.Step, or(deref(s.Priority), "-"), s.Action, s.Host)
		if !s.Reversible {
			head += " (" + T["irrev"] + ")"
		}
		out = append(out, "", head, "_"+s.Note+"_", "", T["connect"]+": `"+s.Connect+"` → `sudo -i`", "",
			T["apply"]+":", "```bash", s.Apply, "```", T["verify"]+":", "```bash", s.Verify, "```",
			T["rollback"]+":", "```bash", s.Rollback, "```")
	}
	if len(p.Manual) > 0 {
		out = append(out, "", "### "+T["manual"])
		for _, m := range p.Manual {
			out = append(out, "- "+m.Action+" — "+m.Host+": "+m.Why)
		}
	}
	if p.ExceptionsYAML != "" {
		out = append(out, "", "```yaml", p.ExceptionsYAML, "```")
	}
	return strings.Join(out, "\n")
}

// --- small helpers for the loosely typed view data (JSON numbers may be float64 or json.Number) ---------------

func num(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	}
	return 0, false
}

func str(v any) string { s, _ := v.(string); return s }

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
