// Package onboard is the first-run setup the TUI and the web page share: an organization file from a few answers
// (checked by the same loader as `kanareika validate` before anything is written), then an SSH check of every
// host, then the first scan (started as any other).
package onboard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/mikekosulin/kanareika/internal/config"
)

// Request: the answers of the setup form.
type Request struct {
	ID        string   `json:"id"`              // org id: a-z, 0-9, '-', '_'
	Name      string   `json:"name"`            // organization name
	User      string   `json:"user"`            // SSH user on the servers
	Privilege string   `json:"privilege"`       // none (default), sudo
	Key       string   `json:"key"`             // a private key file on this machine; "": the ssh-agent
	Port      int      `json:"port"`            // SSH port, 0: 22
	Hosts     string   `json:"hosts"`           // one per line: "address" or "name address", address may carry :port
	Env       string   `json:"env"`             // environment, "": production
	Internet  bool     `json:"internet"`        // the servers are reachable from the internet (raises priorities)
	Front     []string `json:"front,omitempty"` // only these groups face the internet (overrides Internet)
	Jump      string   `json:"jump,omitempty"`  // a jump host for all of them: [user@]host[:port]
	Consent   string   `json:"consent"`         // where the permission to audit is documented
	Confirmed bool     `json:"confirmed"`       // "I am allowed to audit these servers"
}

// Host: one parsed line of Request.Hosts.
type Host struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Group   string `json:"group,omitempty"` // "": servers
	Env     string `json:"env,omitempty"`   // "": the form's environment
	User    string `json:"user,omitempty"`  // "": the form's SSH user
	Jump    string `json:"jump,omitempty"`  // a jump host: another pasted host's name, or [user@]host[:port]
	Line    int    `json:"line,omitempty"`  // the pasted line it came from (1-based)
	// From: "ssh-config" when the address, user, port or jump came from the local ~/.ssh/config (a pasted alias)
	From string `json:"from,omitempty"`
}

var (
	slugRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	nameBad = regexp.MustCompile(`[^a-z0-9_-]+`)
)

// slug: a host name from an address or a DNS name ("web-01.example.com" -> "web-01", "192.0.2.11" -> "192-0-2-11").
func slug(s string) string {
	s = strings.ToLower(strings.Trim(s, "[]"))
	if net.ParseIP(s) == nil {
		s, _, _ = strings.Cut(s, ".")
	}
	s = strings.Trim(nameBad.ReplaceAllString(s, "-"), "-_")
	if s == "" || !slugRE.MatchString(s) {
		return ""
	}
	return s
}

// ParseHosts: the hosts of the form, one per line, in any of these shapes (comments # and blank lines skipped):
//
//	192.0.2.11                      an address (name made from it)
//	web-01 192.0.2.11:2222          a name and an address
//	web-01,192.0.2.11,web,staging   CSV: name, address, group, environment
//	[web]                           an Ansible INI inventory: groups, then
//	web-01 ansible_host=192.0.2.11 ansible_port=2222 ansible_user=deploy
//
// Errors say which line.
func ParseHosts(text string) ([]Host, []string) {
	// pasted ~/.ssh/config blocks (a Host line and the indented or keyword lines after it) are read as such; the
	// other lines one by one, so a mixed paste keeps both
	cfg, rest := splitSSHConfig(text)
	var out []Host
	var errs []string
	seen := map[string]bool{}
	for _, c := range ParseSSHConfig(cfg) {
		h := Host{Name: slug(c.Alias), Address: cmpOr(c.HostName, c.Alias), User: c.User, Jump: c.Jump, Line: hostLine(text, c.Alias)}
		if c.Port != 0 && c.Port != 22 {
			h.Address = net.JoinHostPort(strings.Trim(h.Address, "[]"), strconv.Itoa(c.Port))
		}
		switch {
		case h.Name == "":
			errs = append(errs, fmt.Sprintf("Host %q: not a usable host name, skipped", c.Alias))
		case h.Jump != "" && !jumpRE.MatchString(h.Jump):
			errs = append(errs, fmt.Sprintf("Host %q: jump host %q: [user@]host[:port], skipped", c.Alias, h.Jump))
		case seen[h.Name]:
			errs = append(errs, fmt.Sprintf("Host %q twice, the second skipped", c.Alias))
		default:
			seen[h.Name] = true
			out = append(out, h)
		}
	}
	text = rest
	group, skip := "", false // the current INI section; :vars / :children sections are skipped
	for i, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec := strings.Trim(line, "[]")
			skip = strings.Contains(sec, ":")
			group = strings.ToLower(nameBad.ReplaceAllString(strings.ToLower(sec), "-"))
			continue
		}
		if skip {
			continue
		}
		var h Host
		if c, ok := sshCommand(line); ok { // ssh [-p port] [-l user] [-J jump] [user@]host
			if c.Name == "" {
				errs = append(errs, fmt.Sprintf("line %d: %q: no host in the ssh command", i+1, line))
				continue
			}
			c.Group = group
			h = c
		} else if f := strings.Fields(line); len(f) <= 2 && strings.Contains(f[len(f)-1], "@") { // [name] user@host[:port]
			u, addr, _ := strings.Cut(f[len(f)-1], "@")
			h = Host{Name: slug(hostOnly(addr)), Address: addr, User: u, Group: group}
			if len(f) == 2 {
				h.Name = strings.ToLower(f[0])
			}
		}
		switch f := strings.Fields(line); {
		case h.Name != "":
		case strings.Contains(line, ","): // CSV
			c := strings.Split(line, ",")
			for j := range c {
				c[j] = strings.TrimSpace(c[j])
			}
			for len(c) > 1 && c[len(c)-1] == "" { // trailing commas
				c = c[:len(c)-1]
			}
			if len(c) == 1 { // "address," is just an address
				c = []string{"", c[0]}
			}
			if strings.EqualFold(c[0], "name") && len(c) > 1 && strings.EqualFold(c[1], "address") {
				continue // the header line of a spreadsheet export
			}
			if c[1] == "" {
				errs = append(errs, fmt.Sprintf("line %d: %q: CSV is name,address[,group[,env]]", i+1, line))
				continue
			}
			h = Host{Name: strings.ToLower(c[0]), Address: c[1]}
			if len(c) > 2 {
				h.Group = strings.ToLower(c[2])
			}
			if len(c) > 3 {
				h.Env = strings.ToLower(c[3])
			}
			if h.Name == "" {
				h.Name = slug(hostOnly(h.Address))
			}
		case len(f) >= 2 && strings.Contains(f[1], "="): // Ansible host line
			h = Host{Name: strings.ToLower(f[0]), Address: f[0], Group: group}
			port := ""
			for _, kv := range f[1:] {
				k, v, _ := strings.Cut(kv, "=")
				switch k {
				case "ansible_host":
					h.Address = v
				case "ansible_port":
					port = v
				case "ansible_user":
					h.User = v
				}
			}
			if port != "" {
				h.Address = net.JoinHostPort(strings.Trim(h.Address, "[]"), port)
			}
			if !slugRE.MatchString(h.Name) {
				h.Name = slug(hostOnly(h.Name))
			}
		case len(f) == 1:
			h = Host{Name: slug(hostOnly(f[0])), Address: f[0], Group: group}
		case len(f) == 2:
			h = Host{Name: strings.ToLower(f[0]), Address: f[1], Group: group}
		default:
			errs = append(errs, fmt.Sprintf("line %d: %q: write `address`, `name address`, CSV or an Ansible inventory line", i+1, line))
			continue
		}
		if !slugRE.MatchString(h.Name) {
			errs = append(errs, fmt.Sprintf("line %d: %q: not a usable host name (a-z, 0-9, '-', '_')", i+1, h.Name))
			continue
		}
		if h.Group != "" && !slugRE.MatchString(h.Group) {
			errs = append(errs, fmt.Sprintf("line %d: group %q: a-z, 0-9, '-', '_'", i+1, h.Group))
			continue
		}
		if h.Jump != "" && !jumpRE.MatchString(h.Jump) {
			errs = append(errs, fmt.Sprintf("line %d: jump host %q: [user@]host[:port]", i+1, h.Jump))
			continue
		}
		if h.Env != "" && !slugRE.MatchString(h.Env) {
			errs = append(errs, fmt.Sprintf("line %d: environment %q: a-z, 0-9, '-', '_'", i+1, h.Env))
			continue
		}
		if _, port, err := net.SplitHostPort(h.Address); err == nil {
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				errs = append(errs, fmt.Sprintf("line %d: %q: the port must be 1-65535", i+1, h.Address))
				continue
			}
		}
		if badIPv4(hostOnly(h.Address)) {
			errs = append(errs, fmt.Sprintf("line %d: %q: not an IP address", i+1, hostOnly(h.Address)))
			continue
		}
		if seen[h.Name] {
			errs = append(errs, fmt.Sprintf("line %d: host %q twice", i+1, h.Name))
			continue
		}
		seen[h.Name] = true
		h.Line = i + 1
		out = append(out, h)
	}
	resolveAliases(out, LocalSSHConfig())
	if len(out) == 0 && len(errs) == 0 {
		errs = append(errs, "no hosts: one per line, an address or `name address`")
	}
	return out, errs
}

var (
	sshHostRE = regexp.MustCompile(`(?i)^host\s+\S`)
	sshKeyRE  = regexp.MustCompile(`(?i)^(hostname|user|port|proxyjump|identityfile|identitiesonly|forwardagent|` +
		`serveraliveinterval|serveralivecountmax|stricthostkeychecking|userknownhostsfile|localforward|remoteforward|` +
		`dynamicforward|proxycommand|controlmaster|controlpath|controlpersist|compression|loglevel|addkeystoagent|` +
		`usekeychain|pubkeyauthentication|passwordauthentication|preferredauthentications|requesttty|sendenv|setenv|` +
		`hostkeyalias|certificatefile|connecttimeout)(\s|=)`)
)

// splitSSHConfig: the Host blocks of a paste (a `Host x` line and the keyword lines after it) and everything else.
func splitSSHConfig(text string) (cfg, rest string) {
	var c, r []string
	in := false
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		switch {
		case sshHostRE.MatchString(trim):
			in = true
			c = append(c, trim)
		case in && trim == "":
			c = append(c, "")
		case in && (sshKeyRE.MatchString(trim) || strings.HasPrefix(trim, "#")):
			c = append(c, trim)
		default:
			in = false
			r = append(r, line)
			continue
		}
		r = append(r, "") // the rest keeps its line numbers
	}
	return strings.Join(c, "\n"), strings.Join(r, "\n")
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// sshCommand: a pasted `ssh ...` command line as a host; ok is false when the line is not one.
func sshCommand(line string) (Host, bool) {
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "ssh" {
		return Host{}, false
	}
	var h Host
	port := ""
	for i := 1; i < len(f); i++ {
		a := f[i]
		takes := func() string {
			if len(a) > 2 { // -p2222
				return a[2:]
			}
			if i+1 < len(f) {
				i++
				return f[i]
			}
			return ""
		}
		switch {
		case strings.HasPrefix(a, "-p"):
			port = takes()
		case strings.HasPrefix(a, "-l"):
			h.User = takes()
		case strings.HasPrefix(a, "-J"):
			h.Jump = takes()
		case strings.HasPrefix(a, "-i"), strings.HasPrefix(a, "-o"), strings.HasPrefix(a, "-F"), strings.HasPrefix(a, "-L"),
			strings.HasPrefix(a, "-R"), strings.HasPrefix(a, "-D"), strings.HasPrefix(a, "-b"), strings.HasPrefix(a, "-c"),
			strings.HasPrefix(a, "-E"), strings.HasPrefix(a, "-m"), strings.HasPrefix(a, "-S"), strings.HasPrefix(a, "-W"),
			strings.HasPrefix(a, "-w"):
			takes() // options with a value kanareika does not need
		case strings.HasPrefix(a, "-"):
			// flags without a value (-A, -t, -v, ...)
		case h.Address == "":
			if u, host, ok := strings.Cut(a, "@"); ok {
				h.User, a = u, host
			}
			h.Address = a
		default:
			i = len(f) // the remote command
		}
	}
	if h.Address == "" {
		return h, true
	}
	if port != "" && port != "22" {
		h.Address = net.JoinHostPort(strings.Trim(h.Address, "[]"), port)
	}
	h.Name = slug(hostOnly(h.Address))
	return h, true
}

// hostOnly: the host of "host:port" / "[v6]:port" / "user@host".
func hostOnly(s string) string {
	if _, h, ok := strings.Cut(s, "@"); ok {
		s = h
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

func quote(s string) string { return strconv.Quote(s) }

// ys: s as one YAML scalar: plain when YAML reads it back as the same string, else quoted ("[2001:db8::1]:2222"
// plain is a flow sequence, "yes" a bool, "a: b" a mapping).
func ys(s string) string {
	b, err := yaml.Marshal(s)
	if out := strings.TrimSuffix(string(b), "\n"); err == nil && !strings.ContainsAny(out, "\n\r") {
		return out
	}
	return strconv.Quote(s)
}

// Render: the org file for r, commented like the template. keyRef: the key under secrets/ ("" = ssh-agent).
func Render(r Request, hosts []Host, keyRef string, today time.Time) []byte {
	env := r.Env
	if env == "" {
		env = "production"
	}
	priv := r.Privilege
	if priv == "" {
		priv = "none"
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# Created by kanareika's first-run setup on %s. Edit freely; every key: docs/org-file.md
# One file = one organization. The scanner never connects to anything not listed here.

org:
  id: %s
  name: %s

consent:                         # no scan without a valid consent
  document: %s
  signed: %s
  valid_until: %s        # scans refuse to run after this date
  external_scan: false           # network scans from the outside (the external section) stay off

access:
  user: %s
  privilege: %s                   # none: read what the user can | sudo: root-only reads with sudo -n
`, today.Format(time.DateOnly), ys(r.ID), quote(r.Name), quote(r.Consent), today.Format(time.DateOnly),
		today.AddDate(1, 0, 0).Format(time.DateOnly), ys(r.User), ys(priv))
	if keyRef != "" {
		fmt.Fprintf(&b, "  key: %s\n", ys(keyRef))
	} else {
		b.WriteString("  # key: <ORG_ID>/id_ed25519   # a key in secrets/; without it the ssh-agent is used\n")
	}
	b.WriteString("  host_key_checking: accept-new  # new hosts' keys are learned once, a changed key is refused\n")
	if r.Port != 0 && r.Port != 22 {
		fmt.Fprintf(&b, "  port: %d\n", r.Port)
	}
	if r.Jump != "" {
		ju, jh, ok := strings.Cut(r.Jump, "@")
		if !ok {
			ju, jh = "", r.Jump
		}
		b.WriteString("  jumps:                         # reached first, the servers through it\n    bastion:\n")
		fmt.Fprintf(&b, "      address: %s\n", ys(jh))
		if ju != "" {
			fmt.Fprintf(&b, "      user: %s\n", ys(ju))
		}
	}
	// jump hosts named by hosts: another pasted host (by name) or an address of their own
	jumpName := map[string]string{}
	var jumpOrder []string
	byName := map[string]Host{}
	for _, h := range hosts {
		byName[h.Name] = h
	}
	for _, h := range hosts {
		if h.Jump == "" || jumpName[h.Jump] != "" {
			continue
		}
		n := slug(hostOnly(h.Jump))
		if j, ok := byName[strings.ToLower(h.Jump)]; ok {
			n = j.Name
		}
		jumpName[h.Jump] = n
		jumpOrder = append(jumpOrder, h.Jump)
	}
	if len(jumpOrder) > 0 {
		if r.Jump == "" {
			b.WriteString("  jumps:                         # reached first, the servers through them\n")
		}
		for _, raw := range jumpOrder {
			addr, user := raw, ""
			if j, ok := byName[strings.ToLower(raw)]; ok {
				addr, user = j.Address, j.User
			} else if u, a, ok := strings.Cut(raw, "@"); ok {
				user, addr = u, a
			}
			fmt.Fprintf(&b, "    %s:\n      address: %s\n", ys(jumpName[raw]), ys(addr))
			if user != "" {
				fmt.Fprintf(&b, "      user: %s\n", ys(user))
			}
		}
	}
	type key struct{ group, env string }
	var order []key
	byGroup := map[key][]Host{}
	for _, h := range hosts {
		k := key{h.Group, h.Env}
		if k.group == "" {
			k.group = Ungrouped
		}
		if k.env == "" {
			k.env = env
		}
		if byGroup[k] == nil {
			order = append(order, k)
		}
		byGroup[k] = append(byGroup[k], h)
	}
	names := map[string]int{}
	for _, k := range order {
		names[k.group]++
	}
	b.WriteString("\ngroups:\n")
	for _, k := range order {
		name := k.group
		if names[k.group] > 1 { // the same group in two environments: two groups
			name = k.group + "-" + k.env
		}
		role, exposure := "internal", 3
		if r.Internet && len(r.Front) == 0 || slices.Contains(r.Front, k.group) {
			role, exposure = "front", 1
		}
		fmt.Fprintf(&b, "  %s:\n    role: %s\n    env: %s\n    exposure: %d                  # 1 internet-facing, 2 neighbours, 3 internal\n", ys(name), role, ys(k.env), exposure)
		if r.Jump != "" {
			b.WriteString("    jump: bastion\n")
		}
		b.WriteString("    hosts:\n")
		for _, h := range byGroup[k] {
			fmt.Fprintf(&b, "      %s:\n        address: %s\n", ys(h.Name), ys(h.Address))
			if h.User != "" && h.User != r.User {
				fmt.Fprintf(&b, "        user: %s\n", ys(h.User))
			}
			if h.Jump != "" {
				fmt.Fprintf(&b, "        jump: %s\n", ys(jumpName[h.Jump]))
			}
		}
	}
	return []byte(b.String())
}

// check: what the form must have before a file is written.
func (r Request) check() []string {
	var errs []string
	if !slugRE.MatchString(r.ID) {
		errs = append(errs, "organization id: a-z, 0-9, '-', '_', starting with a letter or digit")
	}
	if strings.TrimSpace(r.Name) == "" {
		errs = append(errs, "organization name is empty")
	}
	if !regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`).MatchString(r.User) {
		errs = append(errs, "SSH user: a login name like audit")
	}
	if r.Privilege != "" && r.Privilege != "none" && r.Privilege != "sudo" {
		errs = append(errs, "privilege: none or sudo")
	}
	if r.Port < 0 || r.Port > 65535 {
		errs = append(errs, "SSH port: 1-65535")
	}
	if r.Env != "" && !slugRE.MatchString(r.Env) {
		errs = append(errs, "environment: a-z, 0-9, '-', '_'")
	}
	if strings.TrimSpace(r.Consent) == "" {
		errs = append(errs, "say where the permission to audit is documented (a contract, a ticket, an e-mail)")
	}
	if r.Jump != "" && !jumpRE.MatchString(r.Jump) {
		errs = append(errs, "jump host: [user@]host[:port]")
	}
	if !r.Confirmed {
		errs = append(errs, "confirm that you are allowed to audit these servers")
	}
	return append(errs, r.controlChars()...)
}

// jumpRE: a jump host as the form takes it, [user@]host[:port] (an IPv6 address in brackets).
var jumpRE = regexp.MustCompile(`^([a-z_][a-z0-9_.-]*@)?[A-Za-z0-9.\-:\[\]]+$`)

// controlChars: the fields with control characters (a newline in a name would start a new YAML key); the hosts
// list may have line breaks and tabs, nothing else.
func (r Request) controlChars() []string {
	bad := func(s string, allow string) bool {
		return strings.IndexFunc(s, func(c rune) bool { return unicode.IsControl(c) && !strings.ContainsRune(allow, c) }) >= 0
	}
	var errs []string
	for _, f := range []struct{ name, v string }{{"organization id", r.ID}, {"organization name", r.Name}, {"SSH user", r.User},
		{"privilege", r.Privilege}, {"key", r.Key}, {"environment", r.Env}, {"jump host", r.Jump}, {"permission", r.Consent},
		{"front groups", strings.Join(r.Front, " ")}} {
		if bad(f.v, "") {
			errs = append(errs, f.name+": control characters")
		}
	}
	if bad(r.Hosts, "\n\r\t") {
		errs = append(errs, "hosts: control characters")
	}
	return errs
}

// keyFile: the private key file r.Key names, read only from ~/.ssh or the secrets directory. Every refusal reads the
// same, so the form cannot tell a missing file from one that is not a key (no probing of the machine's files).
func keyFile(p config.Paths, key string) (string, []byte, error) {
	refused := fmt.Errorf("key %s: not a private key file in ~/.ssh or %s", key, p.Secrets)
	k := key
	if strings.HasPrefix(k, "~/") {
		home, err := homeDir()
		if err != nil {
			return "", nil, refused
		}
		k = filepath.Join(home, k[2:])
	}
	k, err := filepath.EvalSymlinks(k)
	if err != nil {
		return "", nil, refused
	}
	if k, err = filepath.Abs(k); err != nil {
		return "", nil, refused
	}
	var roots []string
	if home, err := homeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".ssh"))
	}
	if p.Secrets != "" {
		roots = append(roots, p.Secrets)
	}
	inside := false
	for _, root := range roots {
		if r, err := filepath.EvalSymlinks(root); err == nil {
			root = r
		}
		if r, err := filepath.Abs(root); err == nil {
			root = r
		}
		if rel, err := filepath.Rel(root, k); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			inside = true
		}
	}
	if !inside {
		return "", nil, refused
	}
	b, err := os.ReadFile(k)
	if err != nil || !strings.Contains(string(b), "PRIVATE KEY") {
		return "", nil, refused
	}
	return k, b, nil
}

// ErrExists: an org with this id is already there.
var ErrExists = errors.New("an organization with this id exists")

// Create writes orgs/<id>.yml (and copies the key into secrets/<id>/ when one is given), after the loader accepted
// it. Nothing is written when anything is wrong; the problems come back as a list. Lines of the hosts list it could
// not use are skipped, not fatal: they come back in Created.Skipped.
func Create(p config.Paths, r Request, today time.Time) (string, []string, error) {
	path, _, errs, err := CreateWithSkipped(p, r, today)
	return path, errs, err
}

// CreateWithSkipped: Create, and the host lines it skipped.
func CreateWithSkipped(p config.Paths, r Request, today time.Time) (string, []string, []string, error) {
	r.ID = strings.TrimSpace(strings.ToLower(r.ID))
	errs := r.check()
	hosts, skipped := ParseHosts(r.Hosts)
	if len(hosts) == 0 {
		errs = append(errs, "no usable hosts: one per line, an address, user@host, an ssh command or ssh config")
		errs = append(errs, skipped...)
	}
	var key []byte
	if r.Key != "" {
		if k, b, err := keyFile(p, r.Key); err != nil {
			errs = append(errs, err.Error())
		} else {
			key, r.Key = b, k
		}
	}
	if len(errs) > 0 {
		return "", nil, errs, nil
	}
	path := filepath.Join(p.Orgs, r.ID+".yml")
	if _, err := os.Stat(path); err == nil {
		return "", nil, nil, fmt.Errorf("%w: %s", ErrExists, path)
	}
	keyRef := ""
	if key != nil {
		keyRef = r.ID + "/" + filepath.Base(r.Key)
	}
	body := Render(r, hosts, keyRef, today)
	// the loader judges the file where it will live: a scratch copy of the working directory's layout
	tmp, err := os.MkdirTemp("", "kanareika-setup-")
	if err != nil {
		return "", nil, nil, err
	}
	defer os.RemoveAll(tmp)
	tp := config.PathsAt(tmp)
	tp.Policy = p.Policy
	for _, d := range []string{tp.Orgs, tp.Secrets} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", nil, nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(tp.Orgs, r.ID+".yml"), body, 0o600); err != nil {
		return "", nil, nil, err
	}
	l, err := config.NewLoader(tp)
	if err != nil {
		return "", nil, nil, err
	}
	if _, lerrs := l.LoadOrg(filepath.Join(tp.Orgs, r.ID+".yml")); len(lerrs) > 0 {
		return "", nil, lerrs, nil
	}
	for _, d := range []string{p.Orgs, p.Reports} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", nil, nil, err
		}
	}
	if err := os.MkdirAll(filepath.Join(p.Secrets, r.ID), 0o700); err != nil {
		return "", nil, nil, err
	}
	if key != nil {
		if err := os.WriteFile(filepath.Join(p.Secrets, keyRef), key, 0o600); err != nil {
			return "", nil, nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return "", nil, nil, fmt.Errorf("%w: %s", ErrExists, path)
	} else if err != nil {
		return "", nil, nil, err
	}
	_, err = f.Write(body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return path, skippedOK(hosts, skipped), nil, err
}

func skippedOK(hosts []Host, skipped []string) []string {
	if len(hosts) == 0 || skipped == nil {
		return []string{}
	}
	return skipped
}

// Result: one host of an access check.
type Result struct {
	Host    string `json:"host"`
	Address string `json:"address"`
	OK      bool   `json:"ok"`
	System  string `json:"system,omitempty"` // uname -sr of a host that answered
	Error   string `json:"error,omitempty"`
	Hint    string `json:"hint,omitempty"` // what to do about the error
}

// Runner: what Check needs from an SSH connection (sshx.OrgSSH).
type Runner interface {
	Run(ctx context.Context, h config.Host, command string, timeout time.Duration, check bool) (string, error)
	io.Closer
}

// hint: the usual cause of an SSH error, in plain words.
// Hint: what to do about an SSH error, in plain words ("" when there is nothing better than the error itself).
func Hint(msg string) string { return hint(msg) }

func hint(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "passphrase"), strings.Contains(m, "private key"):
		return "the SSH key file can't be read (a passphrase, or not a private key): load it with ssh-add and log in through the ssh-agent"
	case strings.Contains(m, "no ssh-agent"), strings.Contains(m, "ssh_auth_sock"):
		return "no SSH key to log in with: no ssh-agent is running here. Run ssh-add in a terminal, then check again"
	case strings.Contains(m, "unable to authenticate"), strings.Contains(m, "permission denied"), strings.Contains(m, "no supported methods"):
		return "the server refused the login: is the public key in ~<user>/.ssh/authorized_keys, and is the key loaded (ssh-add -l) or set in the org file?"
	case strings.Contains(m, "timeout"), strings.Contains(m, "timed out"), strings.Contains(m, "i/o timeout"):
		return "no answer: a firewall, a wrong address or port, or a jump host is needed"
	case strings.Contains(m, "connection refused"):
		return "nothing listens on that port: is sshd running, is the port right?"
	case strings.Contains(m, "no such host"):
		return "the name does not resolve: use the IP address or fix DNS"
	case strings.Contains(m, "host key"):
		return "the host key changed since it was learned: if the server was reinstalled, remove its line from reports/<org>/known_hosts"
	}
	return ""
}

// Check logs in to the hosts of env (only to those named in only, when given), in parallel, and runs
// `uname -sr`: nothing is changed on the servers.
func Check(ctx context.Context, o *config.Org, env string, conn Runner, only ...string) []Result {
	var hosts []config.Host
	for _, h := range o.Hosts {
		if h.Env == env && (len(only) == 0 || slices.Contains(only, h.Name)) {
			hosts = append(hosts, h)
		}
	}
	out := make([]Result, len(hosts))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := Result{Host: h.Name, Address: h.Address}
			sys, err := conn.Run(ctx, h, "uname -sr", 20*time.Second, true)
			if err != nil {
				r.Error = err.Error()
				r.Hint = hint(r.Error)
			} else {
				r.OK, r.System = true, strings.TrimSpace(sys)
			}
			out[i] = r
		}()
	}
	wg.Wait()
	slices.SortStableFunc(out, func(a, b Result) int { return strings.Compare(a.Host, b.Host) })
	return out
}

// badIPv4: looks like an IPv4 address (digits and dots only) but is not one: 10.0.0.300, 10.0.0, 1.2.3.4.5. Such a
// "name" would only fail later as a DNS lookup.
func badIPv4(host string) bool {
	if host == "" || strings.Trim(host, "0123456789.") != "" || !strings.Contains(host, ".") {
		return false
	}
	return net.ParseIP(host) == nil
}

// LocalSSHConfig: the Host entries of this machine's ~/.ssh/config, which a pasted alias resolves against (kanareika
// does not read ssh config when it connects, so the alias is written out in the org file). Tests replace it.
var LocalSSHConfig = func() []SSHHost {
	home, err := homeDir()
	if err != nil {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return nil
	}
	return ParseSSHConfig(string(b))
}

// resolveAliases: a pasted bare alias of ~/.ssh/config (`nas`, `deploy@nas`) becomes what `ssh nas` would use:
// its HostName, Port, User (unless the line names one) and ProxyJump. The name stays the alias.
func resolveAliases(hosts []Host, cfg []SSHHost) {
	by := map[string]SSHHost{}
	for _, c := range cfg {
		by[strings.ToLower(c.Alias)] = c
	}
	for i := range hosts {
		h := &hosts[i]
		c, ok := by[strings.ToLower(h.Address)] // no port given: with one, the line means a real address
		if !ok || c.HostName == "" && c.User == "" && c.Port == 0 && c.Jump == "" {
			continue
		}
		h.Address = cmpOr(c.HostName, c.Alias)
		if c.Port != 0 && c.Port != 22 {
			h.Address = net.JoinHostPort(strings.Trim(h.Address, "[]"), strconv.Itoa(c.Port))
		}
		if h.User == "" {
			h.User = c.User
		}
		if h.Jump == "" {
			h.Jump = c.Jump
		}
		h.From = "ssh-config"
	}
	// a jump named by its alias (ProxyJump bastion) is written out the same way, unless it is a pasted host
	pasted := map[string]bool{}
	for _, h := range hosts {
		pasted[h.Name] = true
	}
	for i := range hosts {
		h := &hosts[i]
		if j, ok := by[strings.ToLower(h.Jump)]; ok && !pasted[strings.ToLower(h.Jump)] && j.HostName != "" {
			addr := j.HostName
			if j.Port != 0 && j.Port != 22 {
				addr = net.JoinHostPort(strings.Trim(addr, "[]"), strconv.Itoa(j.Port))
			}
			if j.User != "" {
				addr = j.User + "@" + addr
			}
			h.Jump = addr
		}
	}
}

// hostLine: the line of text where `Host alias` stands (0: not found).
func hostLine(text, alias string) int {
	for i, l := range strings.Split(text, "\n") {
		if f := strings.Fields(l); len(f) > 1 && strings.EqualFold(f[0], "host") && slices.Contains(f[1:], alias) {
			return i + 1
		}
	}
	return 0
}
