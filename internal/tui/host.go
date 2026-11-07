package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

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
		section("Packages")
		for i, p := range pk {
			if i == 8 {
				out = append(out, " "+sMuted.Render(fmt.Sprintf("+%d %s", len(pk)-8, m.t.T("more")))+" "+sKey.Render("<4>"))
				break
			}
			kev := ""
			if p.KEV {
				kev = " " + sErr.Render("KEV")
			}
			out = append(out, fmt.Sprintf(" %s %s %s %s %s%s%s", prio(p.Priority), sBold.Render(fit(p.Pkg, 22, false)),
				sMuted.Render(p.Installed), sMuted.Render("->"), sOK.Render(p.Fixed), sMuted.Render(fmt.Sprintf("  %d CVE", p.CVEs)), kev))
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
		if keys := arr(a["keys"]); keys != nil {
			root := 0
			for _, k := range keys {
				if str(obj(k)["user"]) == "root" {
					root++
				}
			}
			kv("authorized keys", sText.Render(fmt.Sprintf("%d", len(keys)))+sMuted.Render(fmt.Sprintf(" (root: %d)", root)))
		}
		lg := obj(a["logins"])
		for i, x := range arr(lg["accepted"]) {
			if i == 5 {
				break
			}
			e := obj(x)
			n := str(e["count"])
			if n == "" {
				n = str(e["n"])
			}
			label := ""
			if i == 0 {
				label = "logged in"
			}
			last := strings.Replace(str(e["last"]), "T", " ", 1)
			out = append(out, " "+sLabel.Render(fit(m.t.T(label), 20, false))+" "+sText.Render(str(e["user"]))+sMuted.Render(" @ ")+
				sText.Render(str(e["ip"]))+sMuted.Render(" ×"+n+" "+str(e["method"])+" "+last))
		}
		if ft := num(lg["failed_total"]); ft > 0 {
			kv("failed logins", sErr.Render(str(lg["failed_total"]))+sMuted.Render(fmt.Sprintf(" %s %s", str(lg["failed_ips"]), m.t.T("IPs"))))
		}
		for i, x := range arr(lg["attackers"]) {
			if i == 5 {
				break
			}
			e := obj(x)
			var users []string
			for _, u := range arr(e["users"]) {
				if p := arr(u); len(p) > 0 {
					users = append(users, str(p[0]))
				}
			}
			label := ""
			if i == 0 {
				label = "password guessing"
			}
			n := ""
			if v := str(e["n"]); v != "" {
				n = " ×" + v
			}
			out = append(out, " "+sLabel.Render(fit(m.t.T(label), 20, false))+" "+sErr.Render(str(e["ip"]))+sMuted.Render(n+" "+
				strings.Join(users, ",")))
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
			kv("memory", sText.Render(fmt.Sprintf("%s / %s MB %s", str(mem["available_mb"]), str(mem["total_mb"]), m.t.T("free"))))
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
			kv("journal errors", sText.Render(str(j["errors_7d"]))+sMuted.Render(" / 7 "+m.t.T("days")))
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
			kv("time", s)
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
	return out
}

// denied: what a module could not read without more rights.
func (m *Model) denied(out *[]string, sec map[string]any) {
	if d := arr(sec["denied"]); len(d) > 0 {
		var what []string
		for _, x := range d {
			what = append(what, m.t.msg("denied."+str(x), nil, str(x)))
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
