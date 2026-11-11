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

// The host card: everything a run knows about one host, as the web page's host view shows it.

// JSON helpers: the module outputs come as decoded JSON.
func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func arr(v any) []any          { a, _ := v.([]any); return a }
func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "yes"
		}
		return "no"
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}
func num(v any) float64 { f, _ := v.(float64); return f }

// hostCard: the lines of the card of host name, w cells wide.
func (m *Model) hostCard(name string, w int) []string {
	rd := m.rund
	var out []string
	section := func(title string) {
		out = append(out, "", " "+sTitle.Render(m.t.T(title))+" "+sDim.Render(strings.Repeat("─", max(w-ansi.StringWidth(m.t.T(title))-3, 0))))
	}
	kv := func(k, v string) {
		out = append(out, " "+sLabel.Render(fit(m.t.T(k), 20, false))+" "+v)
	}

	// a section shows its first lines and "+n more ↓"; the whole lists go last, after the summaries
	var tail []func()
	more := func(n, shown int) {
		if n > shown {
			out = append(out, " "+fit("", 20, false)+" "+sMuted.Render(m.t.F("+{n} more", "n", strconv.Itoa(n-shown))+" ↓"))
		}
	}

	// overview
	c := rd.Hosts[name]
	f := rd.Facts[name]
	os := f.OS
	if os == "" {
		os = "?"
	}
	out = append(out, " "+sBold.Render(name)+"  "+sText.Render(os))
	if len(f.Kernel) > 0 {
		kv("kernel", sText.Render(strings.Join(f.Kernel, ", ")))
	}
	var pc []string
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		pc = append(pc, prio(p)+" "+count(p, c[p], true))
	}
	kv("priorities", strings.Join(pc, "  ")+sMuted.Render(fmt.Sprintf("   %d CVE", c["cves"])))

	// to do on it
	var acts []action
	for _, a := range rd.Actions {
		for _, h := range a.Hosts {
			if h == name {
				acts = append(acts, a)
			}
		}
	}
	if len(acts) > 0 {
		section("ToDo")
		for _, a := range acts {
			out = append(out, " "+prio(a.Priority)+" "+sMuted.Render(fit(a.Due, 10, false))+" "+sText.Render(m.t.title(a)))
		}
	}

	// packages
	var pk []planRow
	for _, p := range rd.Plan {
		if p.Host == name {
			pk = append(pk, p)
		}
	}
	if len(pk) > 0 {
		pkgLine := func(p planRow) string {
			kev := ""
			if p.KEV {
				kev = " " + sErr.Render("KEV")
			}
			return fmt.Sprintf(" %s %s %s %s %s%s%s", prio(p.Priority), sBold.Render(fit(p.Pkg, 22, false)),
				sMuted.Render(p.Installed), sMuted.Render("->"), sOK.Render(p.Fixed), sMuted.Render(fmt.Sprintf("  %d CVE", p.CVEs)), kev)
		}
		section("Packages")
		for _, p := range pk[:min(len(pk), 8)] {
			out = append(out, pkgLine(p))
		}
		if len(pk) > 8 {
			out = append(out, " "+sMuted.Render(m.t.F("+{n} more", "n", strconv.Itoa(len(pk)-8))+" ↓"))
			tail = append(tail, func() {
				section("All packages")
				for _, p := range pk {
					out = append(out, pkgLine(p))
				}
			})
		}
	}

	// SSH and logins
	if a := rd.Access[name]; a != nil {
		section("SSH and logins")
		sshd := obj(a["sshd"])
		if p := str(sshd["port"]); p != "" {
			kv("port", sText.Render(p))
		}
		if v, ok := a["password_auth"].(bool); ok {
			s := sOK.Render(m.t.T("off"))
			if v {
				s = sErr.Render(m.t.T("on"))
			}
			if mu := arr(a["password_auth_match_users"]); len(mu) > 0 {
				s += sMuted.Render(" (Match: " + joinAny(mu) + ")")
			}
			kv("password login", s)
		}
		if r := str(sshd["permitrootlogin"]); r != "" {
			kv("root login", sText.Render(r))
		}
		if u := arr(a["users_with_password"]); len(u) > 0 {
			kv("users with password", sErr.Render(joinAny(u)))
		}
		if u := arr(a["login_users"]); len(u) > 0 {
			kv("login users", sText.Render(joinAny(u)))
		}
		if u := arr(a["uid0"]); len(u) > 1 || (len(u) == 1 && str(u[0]) != "root") {
			kv("root accounts", sErr.Render(joinAny(u)))
		}
		if keys := arr(a["keys"]); keys != nil {
			root := 0
			for _, k := range keys {
				if str(obj(k)["user"]) == "root" {
					root++
				}
			}
			down := ""
			if len(keys) > 0 {
				down = " ↓"
			}
			kv("authorized keys", sText.Render(fmt.Sprintf("%d", len(keys)))+sMuted.Render(fmt.Sprintf(" (root: %d)", root)+down))
			if len(keys) > 0 {
				// each key: whose, what kind, its fingerprint and comment (who it belongs to)
				tail = append(tail, func() {
					section("Authorized keys")
					for _, x := range keys {
						k := obj(x)
						fp := str(k["fp"])
						if _, after, ok := strings.Cut(fp, ":"); ok && len(after) > 12 {
							fp = after[:12] + "…"
						}
						opts := ""
						if o := str(k["options"]); o != "" {
							opts = sMuted.Render(" [" + o + "]")
						}
						out = append(out, " "+sText.Render(fit(str(k["user"]), 10, false))+" "+sMuted.Render(fit(str(k["type"]), 20, false))+
							" "+sMuted.Render(fp)+" "+sText.Render(str(k["comment"]))+opts)
					}
				})
			}
		}
		lg := obj(a["logins"])
		if p := arr(lg["period"]); len(p) == 2 {
			kv("login period", sMuted.Render(strings.Replace(str(p[0]), "T", " ", 1)+" — "+strings.Replace(str(p[1]), "T", " ", 1)))
		}
		accLine := func(label string, x any) string {
			e := obj(x)
			n := str(e["count"])
			if n == "" {
				n = str(e["n"])
			}
			last := strings.Replace(str(e["last"]), "T", " ", 1)
			return " " + sLabel.Render(fit(m.t.T(label), 20, false)) + " " + sText.Render(str(e["user"])) + sMuted.Render(" @ ") +
				sText.Render(str(e["ip"])) + sMuted.Render(" ×"+n+" "+str(e["method"])+" "+last)
		}
		acc := arr(lg["accepted"])
		for i, x := range acc[:min(len(acc), 5)] {
			label := ""
			if i == 0 {
				label = "logged in"
			}
			out = append(out, accLine(label, x))
		}
		if len(acc) > 5 {
			more(len(acc), 5)
			tail = append(tail, func() {
				section("Logins")
				for _, x := range acc {
					out = append(out, accLine("", x))
				}
			})
		}
		if ft := num(lg["failed_total"]); ft > 0 {
			s := sErr.Render(str(lg["failed_total"])) + sMuted.Render(fmt.Sprintf(" %s %s", str(lg["failed_ips"]), m.t.T("IPs")))
			if v := str(lg["failed_last"]); v != "" {
				s += sMuted.Render(", " + m.t.T("last attack") + " " + strings.Replace(v, "T", " ", 1))
			}
			kv("failed logins", s)
		}
		if n := num(lg["invalid_users"]); n > 0 {
			kv("unknown user names", sText.Render(str(lg["invalid_users"])))
		}
		if tu := arr(lg["failed_top_users"]); len(tu) > 0 {
			var us []string
			for _, x := range tu {
				if p := arr(x); len(p) == 2 {
					us = append(us, str(p[0])+sMuted.Render(" ×"+str(p[1])))
				}
			}
			kv("usernames tried", sText.Render(strings.Join(us, sMuted.Render(", "))))
		}
		attLine := func(label string, x any) string {
			e := obj(x)
			var users []string
			for _, u := range arr(e["users"]) {
				if p := arr(u); len(p) > 0 {
					users = append(users, str(p[0]))
				}
			}
			n := ""
			if v := str(e["n"]); v != "" {
				n = " ×" + v
			}
			when := strings.Replace(str(e["last"]), "T", " ", 1)
			return " " + sLabel.Render(fit(m.t.T(label), 20, false)) + " " + sErr.Render(fit(str(e["ip"]), 16, false)) + sMuted.Render(n+" "+
				when+" ") + sText.Render(strings.Join(users, ","))
		}
		att := arr(lg["attackers"])
		for i, x := range att[:min(len(att), 5)] {
			label := ""
			if i == 0 {
				label = "password guessing"
			}
			out = append(out, attLine(label, x))
		}
		if len(att) > 5 {
			more(len(att), 5)
			tail = append(tail, func() {
				section("Password guessing")
				for _, x := range att {
					out = append(out, attLine("", x))
				}
			})
		}
		if sessions := arr(a["last"]); len(sessions) > 0 {
			// the sessions as `last` lists them: who, from where, when, how long
			tail = append(tail, func() {
				section("Sessions")
				for _, x := range sessions {
					out = append(out, " "+sMuted.Render(strings.Join(strings.Fields(str(x)), " ")))
				}
			})
		}
		m.denied(&out, a)
	}

	// network
	if e := rd.Exposure[name]; e != nil {
		section("Network")
		unlisted := map[string]bool{}
		for _, u := range arr(e["unlisted_public"]) {
			unlisted[str(u)] = true
		}
		if pub := arr(e["public"]); len(pub) > 0 {
			var ips []string
			for _, p := range pub {
				s := sText.Render(str(p))
				if unlisted[str(p)] {
					s += sErr.Render(" (" + m.t.T("not in the config") + ")")
				}
				ips = append(ips, s)
			}
			kv("public IPs", strings.Join(ips, ", "))
		} else {
			kv("public IPs", sMuted.Render(m.t.T("none")))
		}
		ls := arr(e["listen"])
		sort.SliceStable(ls, func(i, j int) bool { return num(obj(ls[i])["port"]) < num(obj(ls[j])["port"]) })
		for i, x := range ls {
			l := obj(x)
			addr := str(l["addr"])
			if addr == "" {
				addr = "*"
			}
			pub := ""
			if b, _ := l["public"].(bool); b {
				pub = " " + sErr.Render(m.t.T("public"))
			}
			label := ""
			if i == 0 {
				label = "listening"
			}
			out = append(out, " "+sLabel.Render(fit(m.t.T(label), 20, false))+" "+sText.Render(fit(fmt.Sprintf("%s %s:%s", str(l["proto"]), addr, str(l["port"])), 26, false))+
				" "+sMuted.Render(str(l["process"]))+pub)
		}
		if fw := obj(e["firewall"]); fw != nil {
			var parts []string
			if b, ok := fw["has_input_filtering"].(bool); ok {
				if b {
					parts = append(parts, sOK.Render(m.t.T("inbound filtered")))
				} else {
					parts = append(parts, sErr.Render(m.t.T("no inbound filtering")))
				}
			}
			for _, k := range []string{"firewalld", "ufw_active", "iptables_input_policy"} {
				if v := str(fw[k]); v != "" {
					parts = append(parts, sMuted.Render(k+"="+v))
				}
			}
			if b, _ := fw["docker_rules"].(bool); b {
				parts = append(parts, sMuted.Render("docker"))
			}
			if r, ok := fw["readable"].(bool); ok && !r {
				parts = []string{sMuted.Render(m.t.T("not readable without root"))}
			}
			kv("firewall", strings.Join(parts, sMuted.Render(" · ")))
			if rules := m.fwRules[m.fwKey(name)]; rules != "" {
				out[len(out)-1] += sMuted.Render(" ↓")
				tail = append(tail, func() {
					section("Firewall rules")
					for _, l := range strings.Split(strings.TrimRight(rules, "\n"), "\n") {
						out = append(out, " "+sMuted.Render(l))
					}
				})
			}
		}
		m.denied(&out, e)
	}

	// health
	if hl := rd.Health[name]; hl != nil {
		section("Health")
		usage := func(label string, list []any, key string) {
			for i, x := range list {
				d := obj(x)
				use := num(d[key])
				if use == 0 {
					use = num(d["used"]) * 100
				}
				st := sText
				if use >= 90 {
					st = sErr
				} else if use >= 80 {
					st = lipgloss.NewStyle().Foreground(cP["P3"])
				}
				l := ""
				if i == 0 {
					l = label
				}
				out = append(out, " "+sLabel.Render(fit(m.t.T(l), 20, false))+" "+bar(use/100, 10)+" "+st.Render(fmt.Sprintf("%3.0f%%", use))+" "+sText.Render(str(d["mount"])))
			}
		}
		disks := arr(hl["disks"])
		if disks == nil {
			disks = arr(hl["disk"])
		}
		usage("disks", disks, "use")
		var hot []any // inodes: only the filling ones
		for _, x := range arr(hl["inodes"]) {
			if num(obj(x)["use"]) >= 50 {
				hot = append(hot, x)
			}
		}
		usage("inodes", hot, "use")
		if mem := obj(hl["mem"]); mem != nil {
			kv("memory", sText.Render(m.t.F("{avail} / {total} MB free", "avail", str(mem["available_mb"]), "total", str(mem["total_mb"]))))
		}
		if ld := obj(hl["load"]); ld != nil {
			kv("load", sText.Render(fmt.Sprintf("%s / %s", str(ld["load1"]), str(ld["load15"])))+sMuted.Render(fmt.Sprintf(" (1/15 min, %s CPU)", str(ld["cpus"]))))
		} else if v, ok := hl["load"].(float64); ok {
			kv("load", sText.Render(str(v)))
		}
		if u := arr(hl["failed_units"]); len(u) > 0 {
			kv("failed units", sErr.Render(joinAny(u)))
		}
		if r := arr(hl["readonly_mounts"]); len(r) > 0 {
			kv("read-only", sErr.Render(joinAny(r)))
		}
		if j := obj(hl["journal"]); j != nil && num(j["errors_7d"]) > 0 {
			s := sText.Render(str(j["errors_7d"])) + sMuted.Render(" / 7 "+m.t.T("days"))
			var top []string // who writes them
			for _, x := range arr(j["top"]) {
				if p := arr(x); len(p) == 2 {
					top = append(top, str(p[0])+" ×"+str(p[1]))
				}
			}
			if len(top) > 0 {
				s += sMuted.Render("  " + strings.Join(top, ", "))
			}
			kv("journal errors", s)
		}
		if t := obj(hl["time"]); t != nil {
			s := sText.Render(str(t["service"]))
			if v := str(t["synced"]); v != "" {
				s += sMuted.Render(", " + m.t.T("synchronized") + ": " + v)
			}
			if v := t["offset_s"]; v != nil {
				s += sMuted.Render(fmt.Sprintf(", %s %.3f s", m.t.T("offset"), num(v)))
			}
			if v := t["skew_s"]; v != nil && num(v) != 0 {
				s += sMuted.Render(fmt.Sprintf(", %s %.2f s", m.t.T("clock skew"), num(v)))
			}
			if z := str(t["timezone"]); z != "" {
				s += sMuted.Render(", " + m.t.T("time zone") + " " + z)
			}
			kv("time", s)
		}
		// the kernel log: what kinds of trouble, how often, the last line of each
		cls := obj(obj(hl["dmesg"])["classes"])
		keys := make([]string, 0, len(cls))
		for k := range cls {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			c := obj(cls[k])
			label := ""
			if i == 0 {
				label = "kernel log"
			}
			key := str(c["key"])
			if key == "" {
				key = k
			}
			name, _, _ := strings.Cut(m.t.cat(key), " (")
			out = append(out, " "+sLabel.Render(fit(m.t.T(label), 20, false))+" "+lipgloss.NewStyle().Foreground(cP["P2"]).Render(name)+
				sMuted.Render(" ×"+str(c["count"])+"  "+str(c["last"])))
		}
		if kernel := arr(obj(hl["dmesg"])["tail"]); len(kernel) > 0 {
			tail = append(tail, func() {
				section("Kernel log")
				for _, l := range kernel {
					out = append(out, " "+sMuted.Render(str(l)))
				}
			})
		}
		m.denied(&out, hl)
	}

	// other findings
	var other []map[string]any
	for _, o := range append(append([]map[string]any{}, rd.Other...), rd.Inventory...) {
		if str(o["host"]) == name {
			other = append(other, o)
		}
	}
	if len(other) > 0 {
		section("Other findings")
		for _, o := range other {
			p := str(o["priority"])
			title := m.t.msg(str(o["msg"]), obj(o["args"]), str(o["title"]))
			out = append(out, " "+prio(p)+" "+sText.Render(title)+sMuted.Render("  "+str(o["target"])))
		}
	}
	// accepted risks on it: what, whose, until when, why
	var exc []map[string]any
	for _, e := range rd.Exceptions {
		if str(e["host"]) == name {
			exc = append(exc, e)
		}
	}
	if len(exc) > 0 {
		section("Exceptions")
		for _, f := range exc {
			ex := obj(f["exception"])
			st := sOK.Render("✓")
			if b, _ := ex["fix_available"].(bool); b {
				st = sErr.Render("✗")
			} else if b, _ := ex["expired"].(bool); b {
				st = sErr.Render("✗")
			}
			out = append(out, " "+st+" "+sBold.Render(str(f["id"]))+" "+sText.Render(str(f["pkg"]))+sMuted.Render("  "+m.t.T("owner")+" ")+
				sText.Render(str(ex["owner"]))+sMuted.Render("  "+m.t.T("review by")+" "+str(ex["review_by"])))
			if r := str(ex["reason"]); r != "" {
				out = append(out, "   "+sMuted.Render(r))
			}
		}
	}
	for _, f := range tail {
		f()
	}
	return out
}

// fwMsg: a host's firewall rules, as its exposure file has them.
type fwMsg struct{ key, rules string }

// cardHost: the host whose card is on screen: opened on its own, or a host row's details in the tree.
func (m *Model) cardHost() string {
	if m.host != "" {
		return m.host
	}
	if m.isTree() {
		if n := m.curNode(); n != nil && n.Kind == "host" {
			return n.Label
		}
	}
	return ""
}

func (m *Model) fwKey(host string) string { return m.org + "/" + m.env + "/" + m.run + "/" + host }

// fetchFirewall: the rules of the firewall of the host on screen, when the run could read them; once per host.
func (m *Model) fetchFirewall() tea.Cmd {
	host := m.cardHost()
	if host == "" || m.rund == nil || m.pending["fw"] != "" {
		return nil
	}
	if r, ok := obj(m.rund.Exposure[host]["firewall"])["readable"].(bool); !ok || !r {
		return nil
	}
	k := m.fwKey(host)
	if _, ok := m.fwRules[k]; ok {
		return nil
	}
	m.pending["fw"] = k
	c := m.c
	q := "/api/hostfile?org=" + url.QueryEscape(m.org) + "&env=" + url.QueryEscape(m.env) + "&run=" + url.QueryEscape(m.run) +
		"&host=" + url.QueryEscape(host) + "&name=exposure"
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var d struct {
			Raw map[string]string `json:"firewall_raw"`
		}
		if err := c.Get(ctx, q, &d); err != nil {
			return fwMsg{k, ""} // none: the card says what it knows without them
		}
		names := make([]string, 0, len(d.Raw))
		for n, v := range d.Raw {
			if strings.TrimSpace(v) != "" {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			fmt.Fprintf(&b, "## %s\n%s\n", n, strings.TrimRight(d.Raw[n], "\n"))
		}
		return fwMsg{k, b.String()}
	}
}

// denied: what a module could not read without more rights.
func (m *Model) denied(out *[]string, sec map[string]any) {
	if d := arr(sec["denied"]); len(d) > 0 {
		var what []string
		for _, x := range d {
			key := str(x) // denied.shadow; older runs wrote the bare name
			if !strings.HasPrefix(key, "denied.") {
				key = "denied." + key
			}
			what = append(what, m.t.msg(key, nil, str(x)))
		}
		*out = append(*out, " "+sLabel.Render(fit(m.t.T("no access to"), 20, false))+" "+sMuted.Render(strings.Join(what, ", ")))
	}
}

func joinAny(l []any) string {
	s := make([]string, len(l))
	for i, x := range l {
		s[i] = str(x)
	}
	return strings.Join(s, ", ")
}
