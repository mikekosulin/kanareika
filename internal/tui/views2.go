package tui

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// The analysis views the web page has as tabs: Changes, Access, Network, Health, Exceptions; and a run's errors and
// log (i in Runs).

func (m *Model) rundAccess() map[string]map[string]any {
	if m.rund == nil {
		return nil
	}
	return m.rund.Access
}

func (m *Model) rundExposure() map[string]map[string]any {
	if m.rund == nil {
		return nil
	}
	return m.rund.Exposure
}

func (m *Model) rundHealth() map[string]map[string]any {
	if m.rund == nil {
		return nil
	}
	return m.rund.Health
}

// sectionHosts: hosts a module wrote for, by name, filtered.
func (m *Model) sectionHosts(sec map[string]map[string]any) []string {
	var out []string
	for h := range sec {
		if m.match(h) {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// noSection: the module has not run for any host of this data.
func (m *Model) noSection(module string) []string {
	if m.rund == nil {
		return m.noData()
	}
	return []string{"", " " + sMuted.Render(m.t.F("Module {module} has not run yet.", "module", module))}
}

// --- Changes --------------------------------------------------------------------------------------------------------

type change struct {
	diffRow
	new bool
}

func (m *Model) changes() []change {
	if m.rund == nil || m.rund.New == nil {
		return nil
	}
	var out []change
	for _, set := range []struct {
		d   *diffSet
		new bool
	}{{m.rund.New, true}, {m.rund.Resolved, false}} {
		if set.d == nil {
			continue
		}
		for _, r := range set.d.Rows {
			if m.match(r.Host, r.Pkg, r.Target, strings.Join(r.IDs, " ")) {
				out = append(out, change{r, set.new})
			}
		}
	}
	return out
}

func (m *Model) changesView(list []change, w, h int) []string {
	if m.rund == nil {
		return m.noData()
	}
	if m.rund.New == nil {
		return []string{"", " " + sMuted.Render(m.t.T("No previous full run."))}
	}
	note := " " + sMuted.Render(m.t.F("Compared with the full run {run}.", "run", m.t.runShort(m.rund.Prev))+" "+m.t.T("Only hosts scanned in both.")) +
		"  " + sErr.Render(fmt.Sprintf("+%d", len(m.rund.New.Rows))) + sMuted.Render(fmt.Sprintf(" (%d CVE)", m.rund.New.Total))
	if m.rund.Resolved != nil {
		note += "  " + sOK.Render(fmt.Sprintf("−%d", len(m.rund.Resolved.Rows))) + sMuted.Render(fmt.Sprintf(" (%d CVE)", m.rund.Resolved.Total))
	}
	rows := make([][]string, 0, len(list))
	for _, c := range list {
		sign := sOK.Render("−")
		if c.new {
			sign = sErr.Render("+")
		}
		tags := ""
		if c.KEV {
			tags += sErr.Render("KEV ")
		}
		if c.RCE > 0 {
			tags += sErr.Render("RCE ")
		}
		rows = append(rows, []string{sign, prio(c.Priority), sText.Render(c.Host), tags + sBold.Render(c.Pkg), sMuted.Render(c.Target),
			compact(float64(c.Count))})
	}
	return append([]string{note}, m.table(viewCols[vChanges], rows, w, h-1)...)
}

// --- Access ---------------------------------------------------------------------------------------------------------

func (m *Model) accessView(hosts []string, w, h int) []string {
	A := m.rundAccess()
	if len(A) == 0 {
		return m.noSection("access")
	}
	root := map[string]string{"without-password": "key only", "prohibit-password": "key only", "forced-commands-only": "commands",
		"no": "no", "yes": "yes"}
	rows := make([][]string, 0, len(hosts))
	for _, name := range hosts {
		a := A[name]
		lg := obj(a["logins"])
		pw := sMuted.Render("?")
		if v, ok := a["password_auth"].(bool); ok {
			switch {
			case !v:
				pw = sOK.Render(m.t.T("off"))
			case len(arr(a["users_with_password"])) > 0:
				pw = sErr.Render(m.t.T("on"))
			default:
				pw = lipgloss.NewStyle().Foreground(cP["P3"]).Render(m.t.T("on"))
			}
		}
		r := str(obj(a["sshd"])["permitrootlogin"])
		rs := sText.Render(m.t.T(root[r]))
		if root[r] == "" {
			rs = sText.Render(r)
		}
		if r == "yes" {
			rs = sErr.Render(m.t.T("yes"))
		}
		logins, ips := 0.0, map[string]bool{}
		for _, x := range arr(lg["accepted"]) {
			logins += num(obj(x)["count"])
			ips[str(obj(x)["ip"])] = true
		}
		failed := ""
		if n := num(lg["failed_total"]); n > 0 {
			failed = sErr.Render(compact(n))
		}
		fips := ""
		if n := num(lg["failed_ips"]); n > 0 {
			fips = compact(n)
		}
		rows = append(rows, []string{sBold.Render(name), pw, rs, sErr.Render(joinAny(arr(a["users_with_password"]))),
			fmt.Sprint(len(arr(a["keys"]))), compact(logins), fmt.Sprint(len(ips)), failed, fips})
	}
	out := m.table(viewCols[vAccess], rows, w, min(len(rows)+1, max(h/2, 4)))

	// successful logins (newest first) and password guessing (by attempts) across the listed hosts
	type login struct{ host, user, ip, method, last string }
	var ls []login
	attackers := map[string]*struct {
		n     float64
		last  string
		users map[string]float64
		hosts map[string]bool
	}{}
	for _, name := range hosts {
		lg := obj(A[name]["logins"])
		for _, x := range arr(lg["accepted"]) {
			e := obj(x)
			ls = append(ls, login{name, str(e["user"]), str(e["ip"]), str(e["method"]), strings.Replace(str(e["last"]), "T", " ", 1)})
		}
		for _, x := range arr(lg["attackers"]) {
			e := obj(x)
			ip := str(e["ip"])
			a := attackers[ip]
			if a == nil {
				a = &struct {
					n     float64
					last  string
					users map[string]float64
					hosts map[string]bool
				}{users: map[string]float64{}, hosts: map[string]bool{}}
				attackers[ip] = a
			}
			a.n += num(e["n"])
			a.hosts[name] = true
			if l := str(e["last"]); l > a.last {
				a.last = l
			}
			for _, u := range arr(e["users"]) {
				if p := arr(u); len(p) > 1 {
					a.users[str(p[0])] += num(p[1])
				}
			}
		}
	}
	sort.SliceStable(ls, func(i, j int) bool { return ls[i].last > ls[j].last })
	left := h - len(out)
	if left > 3 {
		var rows [][]string
		for _, l := range ls {
			how := sMuted.Render(m.t.T("key"))
			if l.method == "password" {
				how = lipgloss.NewStyle().Foreground(cP["P3"]).Render(m.t.T("password"))
			}
			rows = append(rows, []string{sText.Render(l.host), sBold.Render(l.user), sText.Render(l.ip), how, sMuted.Render(l.last)})
		}
		out = append(out, "", " "+sTitle.Render(m.t.T("Successful logins")))
		if len(rows) == 0 {
			out = append(out, " "+sMuted.Render(m.t.T("No login data")))
		} else {
			out = append(out, m.grid([]col{{title: "host", width: 20}, {title: "who", width: 16}, {title: "from", width: 40},
				{title: "how", width: 10}, {title: "last", width: 16}}, rows, w, max((left-2)/2, 2), false)...)
		}
	}
	if left = h - len(out); left > 3 {
		ips := make([]string, 0, len(attackers))
		for ip := range attackers {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool { // most attempts first; by address within
			if a, b := attackers[ips[i]].n, attackers[ips[j]].n; a != b {
				return a > b
			}
			return ips[i] < ips[j]
		})
		var rows [][]string
		for _, ip := range ips {
			a := attackers[ip]
			users := make([]string, 0, len(a.users))
			for u := range a.users {
				users = append(users, u)
			}
			sort.Slice(users, func(i, j int) bool {
				if x, y := a.users[users[i]], a.users[users[j]]; x != y {
					return x > y
				}
				return users[i] < users[j]
			})
			hs := make([]string, 0, len(a.hosts))
			for h := range a.hosts {
				hs = append(hs, h)
			}
			sort.Strings(hs)
			rows = append(rows, []string{sErr.Render(ip), compact(a.n), sMuted.Render(strings.Replace(a.last, "T", " ", 1)),
				sText.Render(strings.Join(users, ",")), sMuted.Render(strings.Join(hs, ","))})
		}
		out = append(out, "", " "+sTitle.Render(m.t.T("Password guessing")))
		if len(rows) == 0 {
			out = append(out, " "+sMuted.Render(m.t.T("No attempts")))
		} else {
			out = append(out, m.grid([]col{{title: "address", width: 40}, {title: "attempts", width: 8, right: true}, {title: "last", width: 16, drop: 2},
				{title: "logins tried", min: 12}, {title: "hosts", width: 30, drop: 1}}, rows, w, left-2, false)...)
		}
	}
	return out
}

// --- Network --------------------------------------------------------------------------------------------------------

func (m *Model) fwCell(fw map[string]any) string {
	if fw == nil {
		return sMuted.Render("?")
	}
	if r, _ := fw["readable"].(bool); !r {
		return sMuted.Render(m.t.T("no access"))
	}
	var parts []string
	if str(fw["firewalld"]) == "running" {
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
		return sOK.Render("✓ ") + sText.Render(strings.Join(parts, " · "))
	}
	return sErr.Render(m.t.T("no filtering")) + sMuted.Render(" "+strings.Join(parts, " · "))
}

func (m *Model) networkView(hosts []string, w, h int) []string {
	E := m.rundExposure()
	if len(E) == 0 {
		return m.noSection("exposure")
	}
	rows := make([][]string, 0, len(hosts))
	for _, name := range hosts {
		e := E[name]
		unlisted := map[string]bool{}
		for _, u := range arr(e["unlisted_public"]) {
			unlisted[str(u)] = true
		}
		var pub []string
		for _, p := range arr(e["public"]) {
			if unlisted[str(p)] {
				pub = append(pub, sErr.Render(str(p)+"!"))
			} else {
				pub = append(pub, sText.Render(str(p)))
			}
		}
		ports := map[float64]bool{}
		for _, x := range arr(e["listen"]) {
			if b, _ := obj(x)["public"].(bool); b {
				ports[num(obj(x)["port"])] = true
			}
		}
		ps := make([]float64, 0, len(ports))
		for p := range ports {
			ps = append(ps, p)
		}
		sort.Float64s(ps)
		var pl []string
		for _, p := range ps {
			pl = append(pl, str(p))
		}
		rows = append(rows, []string{sBold.Render(name), strings.Join(pub, " "), lipgloss.NewStyle().Foreground(cP["P2"]).Render(strings.Join(pl, " ")),
			m.fwCell(obj(e["firewall"]))})
	}
	out := m.table(viewCols[vNetwork], rows, w, min(len(rows)+1, max(h/2, 4)))
	if left := h - len(out); left > 3 {
		var lr [][]string
		for _, name := range hosts {
			for _, x := range arr(E[name]["listen"]) {
				l := obj(x)
				public, _ := l["public"].(bool)
				if m.outsideOnly && !public {
					continue
				}
				local, _ := l["local_only"].(bool)
				acc := sMuted.Render(m.t.T("internal"))
				switch {
				case local:
					acc = sDim.Render(m.t.T("local"))
				case public:
					acc = lipgloss.NewStyle().Foreground(cP["P2"]).Render(m.t.T("outside"))
				}
				addr := str(l["addr"])
				if addr == "" {
					addr = "*"
				}
				lr = append(lr, []string{sText.Render(name), sBold.Render(str(l["port"])), sMuted.Render(str(l["proto"])), sText.Render(addr),
					sText.Render(str(l["process"])), acc})
			}
		}
		title := " " + sTitle.Render(m.t.T("Listening ports")) + sMuted.Render(fmt.Sprintf(" %d  ", len(lr))) + sKey.Render("<f>") + " " +
			sMuted.Render(m.t.T("outside only"))
		if m.outsideOnly {
			title += sBrand.Render(" ●")
		}
		out = append(out, "", title)
		out = append(out, m.grid([]col{{title: "host", width: 20}, {title: "port", width: 6, right: true}, {title: "proto", width: 5, drop: 2},
			{title: "address", width: 40}, {title: "process", width: 16, drop: 1}, {title: "access", width: 10}}, lr, w, left-2, false)...)
	}
	return out
}

// --- Health ---------------------------------------------------------------------------------------------------------

func (m *Model) healthView(hosts []string, w, h int) []string {
	H := m.rundHealth()
	if len(H) == 0 {
		return m.noSection("health")
	}
	pct := func(v float64) string {
		s := fmt.Sprintf("%.0f%%", v)
		switch { // only what needs attention is coloured
		case v >= 95:
			return sErr.Render(s)
		case v >= 85:
			return lipgloss.NewStyle().Foreground(cP["P3"]).Render(s)
		}
		return s
	}
	maxOf := func(l []any) map[string]any {
		var best map[string]any
		for _, x := range l {
			if best == nil || num(obj(x)["use"]) > num(best["use"]) {
				best = obj(x)
			}
		}
		return best
	}
	tzCount := map[string]int{}
	for _, x := range H {
		if tz := str(obj(x["time"])["timezone"]); tz != "" {
			tzCount[tz]++
		}
	}
	tzMain, best := "", 0
	for tz, n := range tzCount {
		if n > best || n == best && tz < tzMain {
			tzMain, best = tz, n
		}
	}
	rows := make([][]string, 0, len(hosts))
	for _, name := range hosts {
		x := H[name]
		disk, inode, mem, load, units, kern, journal, tz, tm := "", "", "", "", "", "", "", "", ""
		disks := arr(x["disks"])
		if disks == nil { // older runs: disk, used as a share
			for _, d := range arr(x["disk"]) {
				disks = append(disks, map[string]any{"mount": obj(d)["mount"], "use": num(obj(d)["used"]) * 100})
			}
		}
		if d := maxOf(disks); d != nil {
			disk = pct(num(d["use"])) + sDim.Render(" "+str(d["mount"]))
		}
		if d := maxOf(arr(x["inodes"])); d != nil {
			inode = pct(num(d["use"]))
		}
		if mm := obj(x["mem"]); mm != nil && num(mm["total_mb"]) > 0 {
			free := 100 * num(mm["available_mb"]) / num(mm["total_mb"])
			mem = fmt.Sprintf("%.0f%%", free)
			if free <= 10 {
				mem = lipgloss.NewStyle().Foreground(cP["P3"]).Render(mem)
			}
		}
		if ld := obj(x["load"]); ld != nil {
			load = str(ld["load15"]) + sDim.Render("/"+str(ld["cpus"]))
		} else if v, ok := x["load"].(float64); ok {
			load = str(v)
		}
		if u := arr(x["failed_units"]); len(u) > 0 {
			units = lipgloss.NewStyle().Foreground(cP["P3"]).Render(fmt.Sprint(len(u)))
		}
		var cls []string
		for k, c := range obj(obj(x["dmesg"])["classes"]) {
			name, _, _ := strings.Cut(m.t.cat(k), " (") // "OOM killer killed processes", without the explanation
			cls = append(cls, name+" "+str(obj(c)["count"]))
		}
		sort.Strings(cls)
		kern = lipgloss.NewStyle().Foreground(cP["P2"]).Render(strings.Join(cls, ", "))
		if j := obj(x["journal"]); j != nil {
			journal = str(j["errors_7d"])
		}
		t := obj(x["time"])
		if z := str(t["timezone"]); z != "" {
			tz = z
			if z != tzMain {
				tz = lipgloss.NewStyle().Foreground(cP["P3"]).Render(z + "!")
			}
		}
		if t != nil {
			off := ""
			if v, ok := t["offset_s"].(float64); ok {
				off = fmt.Sprintf("%.0f ms", v*1000)
				if v >= 1 || v <= -1 {
					off = fmt.Sprintf("%.1f s", v)
				}
			}
			switch {
			case str(t["synced"]) == "no" || abs(num(t["skew_s"])) > 30:
				tm = sErr.Render("✗ " + off)
			case abs(num(t["offset_s"])) > 1 || abs(num(t["skew_s"])) > 2:
				tm = lipgloss.NewStyle().Foreground(cP["P3"]).Render("! " + off)
			default:
				tm = sMuted.Render(off)
			}
		} else if s := str(x["ntp_synced"]); s != "" {
			tm = sMuted.Render(s)
		}
		rows = append(rows, []string{sBold.Render(name), disk, inode, mem, load, units, kern, journal, tz, tm})
	}
	return m.table(viewCols[vHealth], rows, w, h)
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// --- Exceptions -----------------------------------------------------------------------------------------------------

func (m *Model) exceptions() []map[string]any {
	if m.rund == nil {
		return nil
	}
	var out []map[string]any
	for _, e := range m.rund.Exceptions {
		if m.match(str(e["host"]), str(e["id"]), str(e["pkg"]), str(obj(e["exception"])["reason"])) {
			out = append(out, e)
		}
	}
	return out
}

func (m *Model) exceptionsView(list []map[string]any, w, h int) []string {
	if m.rund == nil {
		return m.noData()
	}
	var out []string
	if len(list) == 0 {
		out = append(out, "", " "+sMuted.Render(m.t.F("No exceptions. Accepted risks live in {section} of the organization file.", "section", "exceptions")))
	} else {
		rows := make([][]string, 0, len(list))
		for _, f := range list {
			ex := obj(f["exception"])
			st := sOK.Render("✓")
			if b, _ := ex["fix_available"].(bool); b {
				st = sErr.Render("✗")
			} else if b, _ := ex["expired"].(bool); b {
				st = sErr.Render("✗")
			}
			rows = append(rows, []string{st, sText.Render(str(f["host"])), sBold.Render(str(f["id"])), sText.Render(str(f["pkg"])),
				sMuted.Render(str(ex["review_by"])), sText.Render(str(ex["owner"])), sMuted.Render(str(ex["reason"]))})
		}
		out = m.table(viewCols[vExceptions], rows, w, min(len(rows)+1, max(h/2, 4)))
	}
	if bp := m.rund.Backported; len(bp) > 0 && h-len(out) > 4 {
		total := 0
		var rows [][]string
		for _, r := range bp {
			total += r.CVEs
			if m.match(r.Host, r.Pkg) {
				rows = append(rows, []string{sText.Render(r.Host), sBold.Render(r.Pkg), sMuted.Render(r.Installed), fmt.Sprint(r.CVEs),
					sMuted.Render(strings.Join(r.IDs, " "))})
			}
		}
		out = append(out, "", " "+sTitle.Render(m.t.T("Already fixed in the installed build"))+sMuted.Render(fmt.Sprintf(" %d CVE", total)))
		out = append(out, m.grid([]col{{title: "host", width: 20}, {title: "package", width: 24}, {title: "installed", width: 24, drop: 1},
			{title: "CVE", width: 4, right: true}, {title: "", min: 10, drop: 2}}, rows, w, h-len(out), false)...)
	}
	return out
}

// --- a run's errors and log ------------------------------------------------------------------------------------------

type runInfoView struct {
	id   string
	meta *runMeta
	log  []string
	off  int
}

type runInfoMsg struct {
	id   string
	meta *runMeta
	log  []string
}

func (m *Model) openRunInfo(id string) tea.Cmd {
	m.runInfo = &runInfoView{id: id}
	c, org, env := m.c, m.org, m.env
	q := "org=" + url.QueryEscape(org) + "&env=" + url.QueryEscape(env) + "&run=" + url.QueryEscape(id)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var rd runResp
		var lg struct {
			Lines []string `json:"lines"`
		}
		if err := c.Get(ctx, "/api/run?"+q, &rd); err != nil {
			return errMsg{err}
		}
		_ = c.Get(ctx, "/api/log?"+q, &lg) // no log is no error
		return runInfoMsg{id, &rd.Meta, lg.Lines}
	}
}

func (m *Model) runInfoKey(s string) {
	ri := m.runInfo
	switch s {
	case "up", "k":
		ri.off = max(ri.off-1, 0)
	case "down", "j":
		ri.off++
	case "pgup", "ctrl+b":
		ri.off = max(ri.off-m.page(), 0)
	case "pgdown", "ctrl+f", " ", "space":
		ri.off += m.page()
	case "home", "g":
		ri.off = 0
	case "end", "G":
		ri.off = 1 << 30
	case "esc", "q", "i", "enter":
		m.runInfo = nil
	}
}

func (m *Model) runInfoView(w, h int) []string {
	ri := m.runInfo
	if ri.meta == nil {
		return []string{" " + sMuted.Render(m.t.T("loading"))}
	}
	var out []string
	out = append(out, " "+sTitle.Render(m.t.T("Errors")))
	hosts := make([]string, 0, len(ri.meta.HostsFailed))
	for h := range ri.meta.HostsFailed {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		out = append(out, " "+sErr.Render("✗ ")+sBold.Render(fit(h, 20, false))+" "+sMuted.Render(m.t.T("host unreachable")+": ")+sText.Render(ri.meta.HostsFailed[h]))
	}
	hosts = hosts[:0]
	for h := range ri.meta.ModuleErrors {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		for _, e := range ri.meta.ModuleErrors[h] {
			out = append(out, " "+lipgloss.NewStyle().Foreground(cP["P3"]).Render("! ")+sBold.Render(fit(h, 20, false))+" "+sMuted.Render(m.t.T("module error")+": ")+sText.Render(e))
		}
	}
	if len(out) == 1 {
		out = append(out, " "+sOK.Render("✓ ")+sMuted.Render(m.t.T("No errors")))
	}
	out = append(out, "", " "+sTitle.Render(m.t.T("Log"))+" "+sDim.Render(strings.Repeat("─", max(w-ansi.StringWidth(m.t.T("Log"))-3, 0))))
	if len(ri.log) == 0 {
		out = append(out, " "+sMuted.Render(m.t.T("No log.")))
	}
	for _, l := range ri.log {
		out = append(out, " "+sText.Render(l))
	}
	ri.off = min(ri.off, max(len(out)-h, 0))
	return out[ri.off:]
}

// compact: 1234 as is, 12345 as 12.3k, 1234567 as 1.2M (the web page's short counts).
func compact(n float64) string {
	switch {
	case n >= 1e12:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", n/1e12), ".0") + "T"
	case n >= 1e9:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", n/1e9), ".0") + "G"
	case n >= 1e6:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", n/1e6), ".0") + "M"
	case n >= 1e4:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", n/1e3), ".0") + "k"
	}
	return strconv.FormatFloat(n, 'f', -1, 64)
}
