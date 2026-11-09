// Package health: server health — kernel log errors, journal errors, failed units, disks, memory, load, time sync.
//
// Read-only. dmesg / journal may need root (or the host's privilege mode); without it the sections are reported as
// not readable instead of failing the module. It also holds what the other script-based checks share with it
// (Sections, Denied, Render, Quote).
package health

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/priv"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

const Script = `
export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"  # non-login SSH shells on RHEL 7 lack sbin
sec(){ printf '\n@@%s@@\n' "$1"; }
sec time; date -u +%s.%N; timedatectl show 2>/dev/null; timedatectl 2>/dev/null; readlink /etc/localtime 2>/dev/null; cat /etc/timezone 2>/dev/null; date +%Z%z
sec dmesg; @P:dmesg@
sec journal; @P:journal-errors@
sec failed_units; systemctl --failed --no-legend --plain 2>&1
sec df; df -PT -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null
sec dfi; df -Pi -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null
sec mem; free -m 2>/dev/null
sec load; cat /proc/loadavg; nproc 2>/dev/null
sec ro; awk '$4 ~ /(^|,)ro(,|$)/ && $2 ~ /^\/(boot|home|var|srv|opt|data)?$/ {print $2, $3}' /proc/mounts
sec ntp; timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown
sec timesvc; for s in chronyd chrony ntpd ntp systemd-timesyncd; do st=$(systemctl is-active $s 2>/dev/null); [ "$st" = active ] && echo "$s active"; done; command -v systemctl >/dev/null 2>&1 || for s in chronyd ntpd; do pgrep -x $s >/dev/null 2>&1 && echo "$s active"; done
sec chrony; chronyc -n tracking 2>/dev/null; chronyc -n sources 2>/dev/null | grep '^\^\*'
sec ntpq; ntpq -pn 2>/dev/null | tail -n +3
sec timesyncd; timedatectl timesync-status 2>/dev/null | head -n 20
`

// Now is the scanner's clock; the skew check compares the host's `date` with it. Tests pin it.
var Now = time.Now

type dmesgClass struct {
	id, severity, title string
	re                  *regexp.Regexp
}

// kernel log classes, in report order
var dmesgClasses = []dmesgClass{
	{"disk-io-error", "HIGH", "disk / filesystem I/O errors", pyfmt.Re(`I/O error|Buffer I/O error|blk_update_request|EXT4-fs error|XFS \(.*\): .*(error|corrupt)|Medium Error|` +
		`nvme.*(timeout|error)|ata\d+.*(failed|error)|end_request: I/O`)},
	{"hw-error", "HIGH", "hardware errors (MCE / EDAC)", pyfmt.Re(`Hardware Error|mce: |Machine check|EDAC .*(CE|UE)`)},
	{"oom", "MEDIUM", "OOM killer killed processes", pyfmt.Re(`Out of memory|oom-kill|Killed process \d+`)},
	{"hang", "MEDIUM", "hangs (soft lockup / hung task)", pyfmt.Re(`soft lockup|hard LOCKUP|hung_task|blocked for more than \d+ seconds`)},
	{"kernel-bug", "MEDIUM", "kernel errors (BUG / Call Trace)", pyfmt.Re(`kernel BUG|BUG: |general protection fault|Call Trace`)},
	{"conntrack-full", "MEDIUM", "conntrack table overflow", pyfmt.Re(`nf_conntrack: table full`)},
	{"segfault", "LOW", "process crashes (segfault)", pyfmt.Re(`segfault at`)},
}

// Denied: output of a privileged command that ran without the privilege it needs.
var Denied = regexp.MustCompile(`(?i)Operation not permitted|Permission denied|read kernel buffer failed|No journal files were opened|` +
	`not seeing messages from other users`)

// Render replaces @P:op@ placeholders with the host-specific privileged command.
func Render(script string, h config.Host) string { return priv.Render(script, h.Privilege) }

// Quote wraps s in single quotes for `sh -c` (not shlex: always quoted, as the modules always did).
func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }

var sectionRe = pyfmt.Re(`^@@(\w+)@@$`)

// Sections splits `sec name` output: name -> its text (stripped). A repeated section starts over.
func Sections(raw string) map[string]string {
	cur := ""
	parts := map[string][]string{}
	for _, line := range pyfmt.SplitLines(raw) {
		if m := sectionRe.FindStringSubmatch(pyfmt.Strip(line)); m != nil {
			cur = m[1]
			parts[cur] = []string{}
		} else if cur != "" {
			parts[cur] = append(parts[cur], line)
		}
	}
	out := make(map[string]string, len(parts))
	for k, v := range parts {
		out[k] = pyfmt.Strip(strings.Join(v, "\n"))
	}
	return out
}

// Detail of a finding as the Python modules built it: a message is kept whole, plain text is cut to 300 characters.
func newFinding(h config.Host, module, kind, id, severity string, title, detail i18n.Text) finding.Finding {
	max := 300
	if detail.Key != "" {
		max = 0
	}
	return check.New(h, module, kind, id, severity, title, detail, max)
}

// Finding of another script-based module (access, exposure): same construction as health's own.
func Finding(h config.Host, module, kind, id, severity string, title, detail i18n.Text) finding.Finding {
	return newFinding(h, module, kind, id, severity, title, detail)
}

func fnd(h config.Host, id, severity string, title, detail i18n.Text) finding.Finding {
	return newFinding(h, "health", finding.Health, id, severity, title, detail)
}

func target(key string, args map[string]any) i18n.Text { return i18n.Msg(key, args) }

type row struct {
	fs, mount string
	use       int
}

func df(text string) ([]row, []any, error) {
	var rows []row
	var js []any
	lines := pyfmt.SplitLines(text)
	if len(lines) > 0 {
		lines = lines[1:]
	}
	for _, line := range lines {
		p := pyfmt.Fields(line)
		if len(p) >= 6 && strings.HasSuffix(p[len(p)-2], "%") {
			u := strings.TrimRight(p[len(p)-2], "%")
			use := 0
			if u != "" {
				var err error
				if use, err = pyfmt.Int(u); err != nil {
					return nil, nil, err
				}
			}
			r := row{p[0], p[len(p)-1], use}
			rows = append(rows, r)
			js = append(js, pyfmt.O("fs", r.fs, "mount", r.mount, "use", r.use))
		}
	}
	return rows, js, nil
}

var (
	chronyRef     = pyfmt.Re(`Reference ID\s*:\s*\S+\s*\(([^)]+)\)`)
	chronyStratum = pyfmt.Re(`Stratum\s*:\s*(\d+)`)
	chronyOffset  = pyfmt.Re(`System time\s*:\s*([\d.]+) seconds (fast|slow)`)
	tsServer      = pyfmt.Re(`Server:\s*(\S+)`)
	tsOffset      = pyfmt.Re(`Offset:\s*([+-]?[\d.]+)(us|ms|s)`)
)

// timeInfo: time zone, which sync service runs, its source / stratum / offset, and the skew vs the scanner's clock.
type timeInfo struct {
	timezone, synced, service, source *string
	serviceActive                     bool
	stratum                           *int
	offset, skew                      *float64
}

func sp(s string) *string { return &s }

func (t timeInfo) obj() pyfmt.Obj {
	str := func(p *string) any {
		if p == nil {
			return nil
		}
		return *p
	}
	o := pyfmt.O("timezone", str(t.timezone), "synced", str(t.synced), "service", str(t.service), "service_active", t.serviceActive, "source", str(t.source), "stratum", nil, "offset_s", nil, "skew_s", nil)
	if t.stratum != nil {
		o.Set("stratum", *t.stratum)
	}
	if t.offset != nil {
		o.Set("offset_s", *t.offset)
	}
	if t.skew != nil {
		o.Set("skew_s", *t.skew)
	}
	return o
}

func parseTime(s map[string]string, scannerTS float64) (timeInfo, error) {
	var t timeInfo
	lines := pyfmt.SplitLines(s["time"])
	if len(lines) > 0 {
		// remote `date` minus our clock at the moment the command ran (SSH latency is ~sub-second)
		if v, err := pyfmt.Float(lines[0]); err == nil {
			sk := pyfmt.Round(v-scannerTS, 2)
			t.skew = &sk
		}
		lines = lines[1:]
	}
	for _, ln := range lines {
		l := pyfmt.Strip(ln)
		switch {
		case strings.HasPrefix(l, "Timezone="):
			t.timezone = sp(strings.SplitN(l, "=", 2)[1])
		case strings.HasPrefix(l, "NTPSynchronized="):
			t.synced = sp(strings.SplitN(l, "=", 2)[1])
		// classic `timedatectl` output (CentOS 7 / old systemd has no `show`)
		case (strings.HasPrefix(l, "NTP synchronized:") || strings.HasPrefix(l, "System clock synchronized:")) && t.synced == nil:
			t.synced = sp(pyfmt.Strip(strings.SplitN(l, ":", 2)[1]))
		case strings.HasPrefix(l, "Time zone:") && (t.timezone == nil || *t.timezone == ""):
			t.timezone = sp(pyfmt.Strip(strings.SplitN(strings.SplitN(l, ":", 2)[1], "(", 2)[0]))
		case strings.Contains(l, "zoneinfo/") && (t.timezone == nil || *t.timezone == ""):
			t.timezone = sp(strings.SplitN(l, "zoneinfo/", 2)[1])
		}
	}
	for _, ln := range pyfmt.SplitLines(s["timesvc"]) {
		if strings.HasSuffix(ln, " active") {
			t.service, t.serviceActive = sp(pyfmt.Fields(ln)[0]), true
			break
		}
	}
	ch := s["chrony"]
	if m := chronyRef.FindStringSubmatch(ch); m != nil {
		t.source = sp(m[1])
	}
	if m := chronyStratum.FindStringSubmatch(ch); m != nil {
		n, err := pyfmt.Int(m[1])
		if err != nil {
			return t, err
		}
		t.stratum = &n
	}
	if m := chronyOffset.FindStringSubmatch(ch); m != nil {
		v, err := pyfmt.Float(m[1])
		if err != nil {
			return t, err
		}
		if m[2] == "slow" {
			v *= -1
		}
		t.offset = &v
	}
	var peers []string
	for _, ln := range pyfmt.SplitLines(s["ntpq"]) {
		if pyfmt.Strip(ln) != "" {
			peers = append(peers, ln)
		}
	}
	sel := ""
	hasSel := false
	for _, ln := range peers {
		if strings.HasPrefix(ln, "*") {
			sel, hasSel = ln, true
			break
		}
	}
	if (t.source == nil || *t.source == "") && hasSel {
		p := pyfmt.Fields(sel[1:]) // remote refid st t when poll reach delay offset jitter
		if len(p) >= 9 {
			off, err := pyfmt.Float(p[8])
			if err != nil {
				return t, err
			}
			t.source = sp(p[0])
			t.stratum = nil
			if pyfmt.IsDigit(p[2]) {
				n, _ := pyfmt.Int(p[2])
				t.stratum = &n
			}
			off /= 1000
			t.offset = &off
		}
	}
	ntpd := t.service != nil && (*t.service == "ntpd" || *t.service == "ntp")
	unknown := t.synced == nil || *t.synced == "unknown"
	if ntpd && len(peers) > 0 && !hasSel && unknown {
		t.synced = sp("no") // ntpd runs but has no selected peer
	} else if ntpd && hasSel && unknown {
		t.synced = sp("yes")
	}
	ts := s["timesyncd"]
	if t.source == nil || *t.source == "" {
		if m := tsServer.FindStringSubmatch(ts); m != nil {
			t.source = sp(m[1])
			if m2 := tsOffset.FindStringSubmatch(ts); m2 != nil {
				v, err := pyfmt.Float(m2[1])
				if err != nil {
					return t, err
				}
				v /= map[string]float64{"us": 1e6, "ms": 1e3, "s": 1}[m2[2]]
				t.offset = &v
			}
		}
	}
	if t.synced == nil && t.serviceActive {
		t.synced = sp("unknown")
	}
	return t, nil
}

var journalIdent = pyfmt.Re(`^\S+ \S+ ([^\[:]+)`)

// Run is the module.
func Run(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, facts check.Facts) ([]finding.Finding, error) {
	ts := Now()
	scannerTS := float64(ts.UnixNano()) / 1e9
	raw, err := ctx.SSH.Run(ctx, h, "sh -c "+Quote(Render(Script, h)), 180*time.Second, false)
	if err != nil {
		return nil, err
	}
	f, data, err := analyze(h, raw, scannerTS)
	if err != nil {
		return nil, err
	}
	if err := pyfmt.WriteJSON(filepath.Join(out, "health.json"), data, false); err != nil {
		return nil, err
	}
	n := 0
	for _, x := range f {
		if x.Kind == finding.Health {
			n++
		}
	}
	denied := data.Get("denied").([]string)
	line := fmt.Sprintf("%s: health: %d issues", h.Name, n)
	if len(denied) > 0 {
		line += ", " + check.DeniedLog(denied)
	}
	ctx.Log("%s", line)
	return f, nil
}

func analyze(h config.Host, raw string, scannerTS float64) ([]finding.Finding, pyfmt.Obj, error) {
	s := Sections(raw)
	var f []finding.Finding
	denied := []string{}
	data := pyfmt.O("denied", nil)

	dm := s["dmesg"]
	if Denied.MatchString(pyfmt.Head(dm, 300)) {
		denied = append(denied, "denied.dmesg")
		dm = ""
	}
	dmLines := pyfmt.SplitLines(dm)
	classes := pyfmt.Obj{}
	for _, c := range dmesgClasses {
		var hits []string
		for _, ln := range dmLines {
			if c.re.MatchString(ln) {
				hits = append(hits, ln)
			}
		}
		if len(hits) > 0 {
			last := hits[len(hits)-1]
			classes = append(classes, pyfmt.KV{K: c.id, V: pyfmt.O("count", len(hits), "last", pyfmt.Head(last, 300), "title", c.title, "key", "dmesg."+c.id, "severity", c.severity)})
			f = append(f, fnd(h, "dmesg-"+c.id, c.severity,
				i18n.Msg("health.kernel_log", map[string]any{"what_key": "dmesg." + c.id, "what": c.title}),
				target("health.kernel_log.detail", map[string]any{"n": len(hits), "line": pyfmt.Head(last, 250)})))
		}
	}
	data = append(data, pyfmt.KV{K: "dmesg", V: pyfmt.O("classes", classes, "tail", nonNil(pyfmt.Last(dmLines, 40)))})

	jr := s["journal"]
	if Denied.MatchString(pyfmt.Head(jr, 300)) && len(pyfmt.SplitLines(jr)) < 3 {
		denied = append(denied, "denied.journal")
		jr = ""
	}
	idents := pyfmt.NewCounter()
	jrLines := pyfmt.SplitLines(jr)
	for _, ln := range jrLines {
		if m := journalIdent.FindStringSubmatch(ln); m != nil {
			idents.Add(m[1], 1)
		}
	}
	data = append(data, pyfmt.KV{K: "journal", V: pyfmt.O("errors_7d", idents.Total(), "top", idents.MostCommon(10), "tail", nonNil(pyfmt.Last(jrLines, 30)))})
	if idents.Total() >= 100 {
		var top []string
		for _, kv := range idents.MostCommon(3) {
			top = append(top, fmt.Sprintf("%s (%d)", kv[0], kv[1]))
		}
		f = append(f, fnd(h, "journal-errors", "LOW", i18n.Msg("health.journal", nil),
			target("health.journal.detail", map[string]any{"n": idents.Total(), "top": strings.Join(top, ", ")})))
	}

	units := []string{}
	for _, ln := range pyfmt.SplitLines(s["failed_units"]) {
		if pyfmt.Strip(ln) != "" && !strings.HasPrefix(ln, "0 ") {
			if u := pyfmt.Fields(ln)[0]; strings.Contains(u, ".") {
				units = append(units, u)
			}
		}
	}
	data = append(data, pyfmt.KV{K: "failed_units", V: units})
	for _, u := range units {
		f = append(f, fnd(h, "failed-unit", "MEDIUM", i18n.Msg("health.failed_unit", map[string]any{"unit": u}),
			i18n.Plain("systemd: failed")))
	}

	disks, disksJS, err := df(s["df"])
	if err != nil {
		return nil, nil, err
	}
	inodes, inodesJS, err := df(s["dfi"])
	if err != nil {
		return nil, nil, err
	}
	data = append(data, pyfmt.KV{K: "disks", V: disksJS}, pyfmt.KV{K: "inodes", V: inodesJS})
	for _, k := range []struct {
		kind string
		rows []row
	}{{"disk", disks}, {"inodes", inodes}} {
		key := "health.inodes"
		if k.kind == "disk" {
			key = "health.disk"
		}
		for _, r := range k.rows {
			args := map[string]any{"mount": r.mount, "use": r.use}
			if r.use >= 95 {
				f = append(f, fnd(h, k.kind+"-full", "HIGH", i18n.Msg(key, args), i18n.Plain(r.fs)))
			} else if r.use >= 85 {
				f = append(f, fnd(h, k.kind+"-high", "MEDIUM", i18n.Msg(key, args), i18n.Plain(r.fs)))
			}
		}
	}

	for _, ln := range pyfmt.SplitLines(s["mem"]) {
		p := pyfmt.Fields(ln)
		if len(p) >= 7 && p[0] == "Mem:" {
			total, err := pyfmt.Int(p[1])
			if err != nil {
				return nil, nil, err
			}
			avail, err := pyfmt.Int(p[6])
			if err != nil {
				return nil, nil, err
			}
			data.Set("mem", pyfmt.O("total_mb", total, "available_mb", avail))
			if total != 0 && float64(avail)/float64(total) < 0.05 {
				f = append(f, fnd(h, "mem-low", "MEDIUM", i18n.Msg("health.mem", nil),
					target("health.mem.detail", map[string]any{"avail": avail, "total": total})))
			}
		}
		if len(p) >= 3 && p[0] == "Swap:" {
			total, err := pyfmt.Int(p[1])
			if err != nil {
				return nil, nil, err
			}
			used, err := pyfmt.Int(p[2])
			if err != nil {
				return nil, nil, err
			}
			data.Set("swap", pyfmt.O("total_mb", total, "used_mb", used))
		}
	}

	if ld := pyfmt.Fields(s["load"]); len(ld) >= 6 {
		cpus := 1
		if pyfmt.IsDigit(ld[len(ld)-1]) {
			cpus, _ = pyfmt.Int(ld[len(ld)-1])
		}
		l1, err := pyfmt.Float(ld[0])
		if err != nil {
			return nil, nil, err
		}
		l15, err := pyfmt.Float(ld[2])
		if err != nil {
			return nil, nil, err
		}
		data.Set("load", pyfmt.O("load1", l1, "load15", l15, "cpus", cpus))
		if l15 > float64(cpus*2) {
			f = append(f, fnd(h, "load-high", "LOW", i18n.Msg("health.load", nil),
				target("health.load.detail", map[string]any{"load": ld[2], "cpus": cpus})))
		}
	}

	ro := []string{}
	for _, ln := range pyfmt.SplitLines(s["ro"]) {
		if pyfmt.Strip(ln) != "" {
			ro = append(ro, ln)
		}
	}
	data = append(data, pyfmt.KV{K: "readonly_mounts", V: ro})
	for _, ln := range ro {
		f = append(f, fnd(h, "fs-readonly", "HIGH", i18n.Msg("health.readonly", nil), i18n.Plain(ln)))
	}

	ntp, ok := s["ntp"]
	if !ok {
		ntp = "unknown"
	}
	ntpLines := pyfmt.SplitLines(pyfmt.Strip(ntp))
	ntpSynced := "unknown"
	if len(ntpLines) > 0 {
		ntpSynced = ntpLines[len(ntpLines)-1]
	}
	data = append(data, pyfmt.KV{K: "ntp_synced", V: ntpSynced})
	t, err := parseTime(s, scannerTS)
	if err != nil {
		return nil, nil, err
	}
	data = append(data, pyfmt.KV{K: "time", V: t.obj()})
	if (t.synced != nil && *t.synced == "no") || !t.serviceActive {
		svc := "-"
		if t.service != nil && *t.service != "" {
			svc = *t.service
		}
		var synced any
		if t.synced != nil {
			synced = *t.synced
		}
		f = append(f, fnd(h, "time-not-synced", "MEDIUM", i18n.Msg("health.ntp", nil),
			target("health.ntp.detail", map[string]any{"service": svc, "synced": synced})))
	} else if t.offset != nil && math.Abs(*t.offset) > 1 {
		f = append(f, fnd(h, "time-offset", "LOW", i18n.Msg("health.ntp_offset", nil),
			target("health.ntp_offset.detail", map[string]any{"offset": fmt.Sprintf("%.2f", *t.offset)})))
	}
	if t.skew != nil && math.Abs(*t.skew) > 30 {
		f = append(f, fnd(h, "time-skew", "HIGH", i18n.Msg("health.skew", map[string]any{"skew": fmt.Sprintf("%.0f", *t.skew)}),
			target("health.skew.detail", nil)))
	}

	data.Set("denied", denied)
	if len(denied) > 0 {
		title, why := check.Denied(h, denied)
		x := fnd(h, "health-limited", "INFO", title, why)
		x.Kind = finding.Inventory
		f = append(f, x)
	}
	return f, data, nil
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}
