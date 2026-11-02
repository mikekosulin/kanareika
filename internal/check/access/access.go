// Package access: who can log in and who did — effective sshd settings, accounts with passwords, authorized_keys,
// successful / failed SSH logins over the last 30 days.
//
// Read-only. Auth logs, /etc/shadow (only account NAMES with a password are taken, never hashes) and other users'
// authorized_keys need root or the host's privilege mode; otherwise they are reported as not readable.
package access

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/check/health"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
)

const Script = `
export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"  # non-login SSH shells on RHEL 7 lack sbin
sec(){ printf '\n@@%s@@\n' "$1"; }
sec sshd_t; @P:sshd-config@ | grep -Ei '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|pubkeyauthentication|authorizedkeysfile|usepam|permitemptypasswords|allowusers|allowgroups|denyusers|listenaddress|maxauthtries) |denied|not permitted|error'
sec sshd_files; cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -Ei '^\s*(Port|PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PubkeyAuthentication|AuthorizedKeysFile|UsePAM|PermitEmptyPasswords|AllowUsers|AllowGroups)\s'
sec passwd; awk -F: '{print $1":"$3":"$6":"$7}' /etc/passwd
sec sshd_users; for u in $(awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ && $1 ~ /^[a-z_][a-z0-9_.-]*$/ {print $1}' /etc/passwd | head -n 30); do echo "U:$u"; @P:sshd-config-user@ "$u"; done
sec shadow_pw; @P:password-users@ 2>&1
sec keys; @P:authorized-keys@
sec auth; @P:auth-log@
sec last; last -F -w -n 200 2>/dev/null | head -n 200
`

// Now is the scanner's local clock: syslog lines carry no year, it is taken from now (and December lines read in
// January belong to the previous year). Tests pin it.
var Now = time.Now

var (
	reAccepted = pyfmt.Re(`Accepted (\S+) for (\S+) from (\S+) port`)
	reFailed   = pyfmt.Re(`Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port`)
	reInvalid  = pyfmt.Re(`Invalid user (\S*) from (\S+?)(?: port \d+)?$`)
	reSSHDPid  = regexp.MustCompile(`sshd\[(\d+)\]`)
	reTSISO    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})`)
	reTSSyslog = pyfmt.Re(`^(\w{3}\s+\d+ \d{2}:\d{2}:\d{2})`)
	reNoLogin  = regexp.MustCompile(`(nologin|false|sync|shutdown|halt)$`)
	// what strptime("%Y %b %d %H:%M:%S") accepts of the syslog stamp: whitespace runs, a 1-31 day, valid h:m:s
	reStrptime = pyfmt.Re(`^(?i:(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec))\s+(3[01]|[12]\d|0[1-9]|[1-9])\s+(\d\d):(\d\d):(\d\d)$`)
)

var months = map[string]time.Month{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8,
	"sep": 9, "oct": 10, "nov": 11, "dec": 12}

// valid: the date exists (Python's datetime raises instead of normalizing Feb 30 into March).
func valid(y int, m time.Month, d, hh, mm, ss int) (time.Time, bool) {
	if hh > 23 || mm > 59 || ss > 59 {
		return time.Time{}, false
	}
	t := time.Date(y, m, d, hh, mm, ss, 0, time.UTC)
	return t, t.Day() == d && t.Month() == m
}

// stamp: ISO timestamp from journal (short-iso) or syslog ('Nov  1 20:50:21', no year) lines; "" when there is none.
// Times are compared as naive wall clock, like Python's datetime.now().
func stamp(line string, now time.Time) (string, error) {
	if m := reTSISO.FindStringSubmatch(line); m != nil {
		return m[1], nil
	}
	m := reTSSyslog.FindStringSubmatch(line)
	if m == nil {
		return "", nil
	}
	p := reStrptime.FindStringSubmatch(m[1])
	if p == nil {
		return "", nil
	}
	d, _ := strconv.Atoi(p[2])
	hh, _ := strconv.Atoi(p[3])
	mm, _ := strconv.Atoi(p[4])
	ss, _ := strconv.Atoi(p[5])
	mon := months[strings.ToLower(p[1])]
	n := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), time.UTC)
	t, ok := valid(n.Year(), mon, d, hh, mm, ss)
	if !ok {
		return "", nil
	}
	if t.After(n.Add(24 * time.Hour)) { // December lines read in January
		if t, ok = valid(n.Year()-1, mon, d, hh, mm, ss); !ok {
			return "", fmt.Errorf("day is out of range for month") // Python's replace(year=...) raised here
		}
	}
	return t.Format("2006-01-02T15:04:05"), nil
}

// settings: sshd keys in the order first seen (a Python dict).
type settings = pyfmt.Obj

func get(c settings, k string) (string, bool) {
	for _, kv := range c {
		if kv.K == k {
			return kv.V.(string), true
		}
	}
	return "", false
}

func val(c settings, k string) string { v, _ := get(c, k); return v }

// sshd: effective settings from `sshd -T` if readable, else from config files (first match wins).
func sshd(s map[string]string) (settings, string) {
	src := s["sshd_t"]
	cfg := settings{}
	if src != "" && !health.Denied.MatchString(src) && strings.Contains(strings.ToLower(src), "passwordauthentication") {
		for _, ln := range pyfmt.SplitLines(src) {
			k, v, _ := strings.Cut(pyfmt.Strip(ln), " ")
			cfg.SetDefault(strings.ToLower(k), strings.ToLower(pyfmt.Strip(v)))
		}
		return cfg, "sshd -T"
	}
	// without root, drop-ins in sshd_config.d are often unreadable, so an absent setting is UNKNOWN, not the OpenSSH
	// default: guessing "yes" here produced false alarms
	for _, ln := range pyfmt.SplitLines(s["sshd_files"]) {
		k, v, _ := strings.Cut(pyfmt.Strip(ln), " ")
		cfg.SetDefault(strings.ToLower(k), strings.ToLower(pyfmt.Strip(v)))
	}
	return cfg, "sshd_config (no sshd -T: not root) — partial"
}

// pwOn: password login is possible — PasswordAuthentication, or keyboard-interactive through PAM.
func pwOn(c settings) bool {
	if val(c, "passwordauthentication") == "yes" {
		return true
	}
	kbd, ok := get(c, "kbdinteractiveauthentication")
	if !ok {
		kbd = val(c, "challengeresponseauthentication")
	}
	return kbd == "yes" && val(c, "usepam") == "yes"
}

// perUserSSHD: 'U:<user>' followed by that user's `sshd -T -C` lines -> {user: settings}; users without output are
// skipped. Users in first-seen order.
func perUserSSHD(text string) ([]string, map[string]settings) {
	var order []string
	out := map[string]settings{}
	cur := ""
	for _, ln := range pyfmt.SplitLines(text) {
		if strings.HasPrefix(ln, "U:") {
			cur = pyfmt.Strip(ln[2:])
			continue
		}
		k, v, found := strings.Cut(pyfmt.Strip(ln), " ")
		if cur != "" && found && !health.Denied.MatchString(ln) {
			c, ok := out[cur]
			if !ok {
				order = append(order, cur)
			}
			c.Set(strings.ToLower(k), strings.ToLower(pyfmt.Strip(v)))
			out[cur] = c
		}
	}
	return order, out
}

func keyFP(blob string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || strings.ContainsAny(blob, "\r\n") { // validate=True: nothing outside the alphabet
		return "", false
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "="), true
}

// parseKey: an authorized_keys line — [options] type base64 [comment].
func parseKey(line string) (pyfmt.Obj, bool) {
	parts := pyfmt.Fields(line)
	for i, p := range parts {
		if (strings.HasPrefix(p, "ssh-") || strings.HasPrefix(p, "ecdsa-") || strings.HasPrefix(p, "sk-")) && i+1 < len(parts) {
			if fp, ok := keyFP(parts[i+1]); ok {
				return pyfmt.O("type", p, "fp", fp, "comment", pyfmt.Head(strings.Join(parts[i+2:], " "), 120), "options", pyfmt.Head(strings.Join(parts[:i], " "), 200)), true
			}
		}
	}
	return nil, false
}

type user struct {
	uid         int
	home, shell string
}

func loginShell(sh string) bool { return !reNoLogin.MatchString(sh) }

type accepted struct {
	user, ip, method string
	count            int
	first, last      string
}

type attacker struct {
	ip          string
	n           int
	first, last string
	users       *pyfmt.Counter
}

func fnd(h config.Host, kind, id, severity string, title, detail i18n.Text) finding.Finding {
	return health.Finding(h, "access", kind, id, severity, title, detail)
}

func msg(key string, args map[string]any) i18n.Text { return i18n.Msg(key, args) }

// Run is the module.
func Run(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, facts check.Facts) ([]finding.Finding, error) {
	raw, err := ctx.SSH.Run(ctx, h, "sh -c "+health.Quote(health.Render(Script, h)), 300*time.Second, false)
	if err != nil {
		return nil, err
	}
	f, data, summary, err := analyze(h, raw, Now())
	if err != nil {
		return nil, err
	}
	if err := pyfmt.WriteJSON(filepath.Join(out, "access.json"), data, false); err != nil {
		return nil, err
	}
	ctx.Log("%s", h.Name+": access: "+summary)
	return f, nil
}

func analyze(h config.Host, raw string, now time.Time) ([]finding.Finding, pyfmt.Obj, string, error) {
	privileged := h.Privilege != "none" || h.User == "root"
	s := health.Sections(raw)
	var f []finding.Finding
	denied := []string{}

	sshdCfg, sshdSrc := sshd(s)
	// accounts
	users := map[string]user{}
	var userOrder []string
	for _, ln := range pyfmt.SplitLines(s["passwd"]) {
		p := strings.Split(ln, ":")
		if len(p) == 4 {
			uid := -1
			if pyfmt.IsDigit(p[1]) {
				uid, _ = pyfmt.Int(p[1])
			}
			if _, ok := users[p[0]]; !ok {
				userOrder = append(userOrder, p[0])
			}
			users[p[0]] = user{uid, p[2], p[3]}
		}
	}
	shadow := s["shadow_pw"]
	var withPW []string // nil: unknown
	if health.Denied.MatchString(shadow) || (!strings.Contains(shadow, "PW:") && pyfmt.Strip(shadow) != "") {
		denied = append(denied, "denied.shadow")
	} else {
		withPW = []string{}
		for _, ln := range pyfmt.SplitLines(shadow) {
			if strings.HasPrefix(ln, "PW:") {
				withPW = append(withPW, ln[3:])
			}
		}
		sort.Strings(withPW)
	}
	uid0 := []string{}
	loginUsers := []string{}
	for _, u := range userOrder {
		if users[u].uid == 0 {
			uid0 = append(uid0, u)
		}
		if loginShell(users[u].shell) {
			loginUsers = append(loginUsers, u)
		}
	}
	sort.Strings(uid0)
	sort.Strings(loginUsers)

	// keys
	keys := []pyfmt.Obj{}
	var unreadable []string
	for _, ln := range pyfmt.SplitLines(s["keys"]) {
		if strings.HasPrefix(ln, "K:") {
			p := strings.SplitN(ln, ":", 4)
			if len(p) < 4 {
				return nil, nil, "", fmt.Errorf("authorized-keys: malformed line %q", pyfmt.Head(ln, 80))
			}
			rest := p[3]
			if pyfmt.Strip(rest) != "" && !strings.HasPrefix(pyfmt.LStrip(rest), "#") {
				if k, ok := parseKey(rest); ok {
					keys = append(keys, append(pyfmt.O("user", p[1], "file", p[2]), k...))
				}
			}
		} else if strings.HasPrefix(ln, "U:") {
			unreadable = append(unreadable, ln[2:])
		}
	}
	if len(unreadable) > 0 || !privileged {
		denied = append(denied, "denied.keys")
	}

	// logins
	authRaw := s["auth"]
	auth := strings.ReplaceAll(authRaw, "@@auth-readable@@", "")
	if !privileged || !strings.Contains(authRaw, "@@auth-readable@@") {
		denied = append(denied, "denied.authlog")
	}
	acc := map[[3]string]*accepted{}
	var accOrder []*accepted
	failedIP, failedUser, invalidUsers := pyfmt.NewCounter(), pyfmt.NewCounter(), pyfmt.NewCounter()
	attackers := map[string]*attacker{}
	var attOrder []*attacker
	failedDaily, acceptedDaily := pyfmt.NewCounter(), pyfmt.NewCounter()
	attack := func(ip, u, ts string) {
		a, ok := attackers[ip]
		if !ok {
			a = &attacker{ip: ip, first: ts, last: ts, users: pyfmt.NewCounter()}
			attackers[ip] = a
			attOrder = append(attOrder, a)
		}
		a.n++
		if ts != "" {
			a.last = ts
		}
		a.users.Add(u, 1)
		if ts != "" {
			failedDaily.Add(ts[:10], 1)
		}
	}
	var firstTS, lastTS *string
	lines := pyfmt.SplitLines(auth)
	// an sshd session that logged "Failed ... for invalid user" is counted there; old OpenSSH (5.x) logs only
	// "Invalid user X from IP" when the probe never gets to a password — that is an attempt too
	failedPids := map[string]bool{}
	for _, ln := range lines {
		if reFailed.MatchString(ln) {
			if m := reSSHDPid.FindStringSubmatch(ln); m != nil {
				failedPids[m[1]] = true
			}
		}
	}
	for _, ln := range lines {
		ts, err := stamp(ln, now)
		if err != nil {
			return nil, nil, "", err
		}
		if ts != "" {
			if firstTS == nil || *firstTS == "" {
				firstTS = &ts
			}
			lastTS = &ts
		}
		if m := reAccepted.FindStringSubmatch(ln); m != nil {
			k := [3]string{m[2], m[3], m[1]}
			a, ok := acc[k]
			if !ok {
				a = &accepted{user: k[0], ip: k[1], method: k[2], first: ts, last: ts}
				acc[k] = a
				accOrder = append(accOrder, a)
			}
			a.count++
			a.last = ts
			if ts != "" {
				acceptedDaily.Add(ts[:10], 1)
			}
		} else if m := reFailed.FindStringSubmatch(ln); m != nil {
			failedIP.Add(m[3], 1)
			failedUser.Add(m[2], 1)
			attack(m[3], m[2], ts)
		} else if m := reInvalid.FindStringSubmatch(ln); m != nil {
			invalidUsers.Add(m[1], 1)
			if pid := reSSHDPid.FindStringSubmatch(ln); pid != nil && !failedPids[pid[1]] {
				failedIP.Add(m[2], 1)
				failedUser.Add(m[1], 1)
				attack(m[2], m[1], ts)
			}
		}
	}

	var pwAuth *bool // nil: unknown
	if _, ok := get(sshdCfg, "passwordauthentication"); !ok {
		denied = append(denied, "denied.sshd")
	} else {
		v := pwOn(sshdCfg)
		pwAuth = &v
	}
	var loginPWUsers []string
	for _, u := range withPW {
		if loginShell(users[u].shell) {
			loginPWUsers = append(loginPWUsers, u)
		}
	}
	// per user, as sshd decides for a connection from outside: Match blocks can turn passwords on for some users
	perOrder, perUser := perUserSSHD(s["sshd_users"])
	matchPWUsers := []string{}
	if pwAuth != nil && !*pwAuth {
		for _, u := range perOrder {
			if pwOn(perUser[u]) {
				matchPWUsers = append(matchPWUsers, u)
			}
		}
		sort.Strings(matchPWUsers)
	}

	sortedAcc := append([]*accepted(nil), accOrder...)
	sort.SliceStable(sortedAcc, func(i, j int) bool { return sortedAcc[i].last > sortedAcc[j].last })
	accJS := []any{}
	for _, a := range sortedAcc {
		accJS = append(accJS, pyfmt.O("user", a.user, "ip", a.ip, "method", a.method, "count", a.count, "first", a.first, "last", a.last))
	}
	var failedLast any
	for _, a := range attOrder {
		if a.last != "" && (failedLast == nil || a.last > failedLast.(string)) {
			failedLast = a.last
		}
	}
	sortedAtt := append([]*attacker(nil), attOrder...)
	sort.SliceStable(sortedAtt, func(i, j int) bool { return sortedAtt[i].n > sortedAtt[j].n })
	attJS := []any{}
	for _, a := range sortedAtt[:min(len(sortedAtt), 200)] {
		attJS = append(attJS, pyfmt.O("ip", a.ip, "n", a.n, "first", a.first, "last", a.last, "users", a.users.MostCommon(5)))
	}
	str := func(p *string) any {
		if p == nil {
			return nil
		}
		return *p
	}
	var pwAuthJS, withPWJS any
	if pwAuth != nil {
		pwAuthJS = *pwAuth
	}
	if withPW != nil {
		withPWJS = withPW
	}
	last := pyfmt.SplitLines(s["last"])
	if last == nil {
		last = []string{}
	}
	data := pyfmt.O("sshd", sshdCfg, "sshd_source", sshdSrc, "password_auth", pwAuthJS, "password_auth_match_users", matchPWUsers, "users_with_password", withPWJS, "login_users", loginUsers, "uid0", uid0, "keys", keys, "logins", pyfmt.O("period", []any{str(firstTS), str(lastTS)}, "accepted", accJS, "failed_total", failedIP.Total(), "failed_ips", failedIP.Len(), "failed_top_ips", failedIP.MostCommon(15), "failed_top_users", failedUser.MostCommon(15), "invalid_users", invalidUsers.Total(), "failed_last", failedLast, "failed_daily", sortedCounts(failedDaily), "accepted_daily", sortedCounts(acceptedDaily), "attackers", attJS), "last", last[:min(len(last), 50)], "denied", denied)

	// findings
	exp1 := h.Exposure == 1
	sev := func(cond bool, a, b string) string {
		if cond {
			return a
		}
		return b
	}
	if pwAuth != nil && *pwAuth {
		switch {
		case withPW == nil:
			f = append(f, fnd(h, finding.Misconfig, "ssh-password-auth", sev(exp1, "MEDIUM", "LOW"),
				msg("ssh.password", nil), msg("ssh.password.unknown", nil)))
		case len(loginPWUsers) > 0:
			f = append(f, fnd(h, finding.Misconfig, "ssh-password-auth", sev(exp1, "HIGH", "MEDIUM"),
				msg("ssh.password", nil), msg("ssh.password.users", map[string]any{"users": strings.Join(loginPWUsers, ", ")})))
		default:
			f = append(f, fnd(h, finding.Misconfig, "ssh-password-auth", "LOW",
				msg("ssh.password", nil), msg("ssh.password.none", nil)))
		}
	}
	if len(matchPWUsers) > 0 {
		f = append(f, fnd(h, finding.Misconfig, "ssh-password-auth", sev(exp1, "HIGH", "MEDIUM"),
			msg("ssh.password", nil), msg("ssh.password.match", map[string]any{"users": strings.Join(matchPWUsers, ", ")})))
	}
	if val(sshdCfg, "permitrootlogin") == "yes" && sshdSrc == "sshd -T" {
		f = append(f, fnd(h, finding.Misconfig, "ssh-root-login", sev(exp1 && pwAuth != nil && *pwAuth, "HIGH", "MEDIUM"),
			msg("ssh.root", nil), i18n.Plain("PermitRootLogin yes → prohibit-password")))
	}
	if val(sshdCfg, "permitemptypasswords") == "yes" {
		f = append(f, fnd(h, finding.Misconfig, "ssh-empty-passwords", "CRITICAL", msg("ssh.empty", nil),
			i18n.Plain("PermitEmptyPasswords yes")))
	}
	var extraUID0 []string
	for _, u := range uid0 {
		if u != "root" {
			extraUID0 = append(extraUID0, u)
		}
	}
	if len(extraUID0) > 0 {
		f = append(f, fnd(h, finding.Misconfig, "uid0-accounts", "HIGH", msg("ssh.uid0", nil),
			i18n.Plain(strings.Join(extraUID0, ", "))))
	}
	var pwLogins []*accepted
	for _, a := range accOrder {
		if a.method == "password" || a.method == "keyboard-interactive/pam" {
			pwLogins = append(pwLogins, a)
		}
	}
	if len(pwLogins) > 0 {
		n := 0
		var who []string
		for i, a := range pwLogins {
			n += a.count
			if i < 5 {
				who = append(who, a.user+"@"+a.ip)
			}
		}
		f = append(f, fnd(h, finding.Misconfig, "ssh-password-logins", "MEDIUM",
			msg("ssh.pw_logins", map[string]any{"n": n}), i18n.Plain(strings.Join(who, ", "))))
	}
	if failedIP.Total() >= 1000 {
		// with password auth off this is background noise: keep it visible, but as info, not a to-do
		off := pwAuth != nil && !*pwAuth
		var top []string
		for _, kv := range failedIP.MostCommon(3) {
			top = append(top, fmt.Sprintf("%s (%d)", kv[0], kv[1]))
		}
		f = append(f, fnd(h, sev(off, finding.Inventory, finding.Exposure), "ssh-bruteforce", sev(off, "INFO", "LOW"),
			msg("ssh.bruteforce", map[string]any{"n": failedIP.Total(), "ips": failedIP.Len()}),
			i18n.Plain(strings.Join(top, ", "))))
	}
	root := 0
	for _, k := range keys {
		if k.Get("user") == "root" {
			root++
		}
	}
	kf := fnd(h, finding.Inventory, "ssh-keys", "INFO", msg("ssh.keys", map[string]any{"n": len(keys), "root": root}),
		i18n.Plain(""))
	kf.Pkg, kf.Installed = "authorized_keys", fmt.Sprint(len(keys))
	f = append(f, kf)
	if len(denied) > 0 {
		f = append(f, fnd(h, finding.Inventory, "access-limited", "INFO",
			msg("health.limited", map[string]any{"what": strings.Join(denied, ", ")}), i18n.Plain("")))
	}

	logins := 0
	for _, a := range accOrder {
		logins += a.count
	}
	summary := fmt.Sprintf("%d keys, %d logins, %d failed", len(keys), logins, failedIP.Total())
	if len(denied) > 0 {
		summary += "; no access to " + strings.Join(denied, ", ")
	}
	return f, data, summary, nil
}

// sortedCounts: dict(sorted(counter.items())).
func sortedCounts(c *pyfmt.Counter) pyfmt.Obj {
	keys := append([]string(nil), c.Keys()...)
	sort.Strings(keys)
	o := pyfmt.Obj{}
	for _, k := range keys {
		o = append(o, pyfmt.KV{K: k, V: c.Get(k)})
	}
	return o
}
