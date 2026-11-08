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

	"github.com/mikekosulin/kanareika/internal/config"
)

// Request: the answers of the setup form.
type Request struct {
	ID        string `json:"id"`        // org id: a-z, 0-9, '-', '_'
	Name      string `json:"name"`      // organization name
	User      string `json:"user"`      // SSH user on the servers
	Privilege string `json:"privilege"` // none (default), sudo
	Key       string `json:"key"`       // a private key file on this machine; "": the ssh-agent
	Port      int    `json:"port"`      // SSH port, 0: 22
	Hosts     string `json:"hosts"`     // one per line: "address" or "name address", address may carry :port
	Env       string `json:"env"`       // environment, "": production
	Internet  bool   `json:"internet"`  // the servers are reachable from the internet (raises priorities)
	Consent   string `json:"consent"`   // where the permission to audit is documented
	Confirmed bool   `json:"confirmed"` // "I am allowed to audit these servers"
}

// Host: one parsed line of Request.Hosts.
type Host struct {
	Name    string `json:"name"`
	Address string `json:"address"`
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

// ParseHosts: the hosts of the form, one per line; comments (#) and blank lines skipped. Errors say which line.
func ParseHosts(text string) ([]Host, []string) {
	var out []Host
	var errs []string
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' || r == ';' })
		var h Host
		switch len(f) {
		case 0:
			continue
		case 1:
			h = Host{Address: f[0]}
			host := f[0]
			if hp, _, err := net.SplitHostPort(f[0]); err == nil {
				host = hp
			}
			h.Name = slug(host)
		case 2:
			h = Host{Name: strings.ToLower(f[0]), Address: f[1]}
		default:
			errs = append(errs, fmt.Sprintf("line %d: %q: write `address` or `name address`", i+1, strings.TrimSpace(line)))
			continue
		}
		if !slugRE.MatchString(h.Name) {
			errs = append(errs, fmt.Sprintf("line %d: %q is not a usable host name (a-z, 0-9, '-', '_')", i+1, h.Name))
			continue
		}
		if seen[h.Name] {
			errs = append(errs, fmt.Sprintf("line %d: host %q twice", i+1, h.Name))
			continue
		}
		seen[h.Name] = true
		out = append(out, h)
	}
	if len(out) == 0 && len(errs) == 0 {
		errs = append(errs, "no hosts: one per line, an address or `name address`")
	}
	return out, errs
}

func quote(s string) string { return strconv.Quote(s) }

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
	role, exposure := "internal", 3
	if r.Internet {
		role, exposure = "front", 1
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
`, today.Format(time.DateOnly), r.ID, quote(r.Name), quote(r.Consent), today.Format(time.DateOnly),
		today.AddDate(1, 0, 0).Format(time.DateOnly), r.User, priv)
	if keyRef != "" {
		fmt.Fprintf(&b, "  key: %s\n", keyRef)
	} else {
		b.WriteString("  # key: <ORG_ID>/id_ed25519   # a key in secrets/; without it the ssh-agent is used\n")
	}
	b.WriteString("  host_key_checking: accept-new  # new hosts' keys are learned once, a changed key is refused\n")
	if r.Port != 0 && r.Port != 22 {
		fmt.Fprintf(&b, "  port: %d\n", r.Port)
	}
	fmt.Fprintf(&b, `
groups:
  servers:
    role: %s
    env: %s
    exposure: %d                  # 1 internet-facing, 2 neighbours, 3 internal
    hosts:
`, role, env, exposure)
	for _, h := range hosts {
		fmt.Fprintf(&b, "      %s:\n        address: %s\n", h.Name, h.Address)
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
	if !r.Confirmed {
		errs = append(errs, "confirm that you are allowed to audit these servers")
	}
	return errs
}

// ErrExists: an org with this id is already there.
var ErrExists = errors.New("an organization with this id exists")

// Create writes orgs/<id>.yml (and copies the key into secrets/<id>/ when one is given), after the loader accepted
// it. Nothing is written when anything is wrong; the problems come back as a list.
func Create(p config.Paths, r Request, today time.Time) (string, []string, error) {
	r.ID = strings.TrimSpace(strings.ToLower(r.ID))
	errs := r.check()
	hosts, herrs := ParseHosts(r.Hosts)
	errs = append(errs, herrs...)
	var key []byte
	if r.Key != "" {
		k := r.Key
		if strings.HasPrefix(k, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				k = filepath.Join(home, k[2:])
			}
		}
		b, err := os.ReadFile(k)
		switch {
		case err != nil:
			errs = append(errs, fmt.Sprintf("key %s: %v", r.Key, err))
		case !strings.Contains(string(b), "PRIVATE KEY"):
			errs = append(errs, fmt.Sprintf("key %s: not a private key file", r.Key))
		default:
			key, r.Key = b, k
		}
	}
	if len(errs) > 0 {
		return "", errs, nil
	}
	path := filepath.Join(p.Orgs, r.ID+".yml")
	if _, err := os.Stat(path); err == nil {
		return "", nil, fmt.Errorf("%w: %s", ErrExists, path)
	}
	keyRef := ""
	if key != nil {
		keyRef = r.ID + "/" + filepath.Base(r.Key)
	}
	body := Render(r, hosts, keyRef, today)
	// the loader judges the file where it will live: a scratch copy of the working directory's layout
	tmp, err := os.MkdirTemp("", "kanareika-setup-")
	if err != nil {
		return "", nil, err
	}
	defer os.RemoveAll(tmp)
	tp := config.PathsAt(tmp)
	tp.Policy = p.Policy
	for _, d := range []string{tp.Orgs, tp.Secrets} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(tp.Orgs, r.ID+".yml"), body, 0o600); err != nil {
		return "", nil, err
	}
	l, err := config.NewLoader(tp)
	if err != nil {
		return "", nil, err
	}
	if _, lerrs := l.LoadOrg(filepath.Join(tp.Orgs, r.ID+".yml")); len(lerrs) > 0 {
		return "", lerrs, nil
	}
	for _, d := range []string{p.Orgs, p.Reports} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", nil, err
		}
	}
	if err := os.MkdirAll(filepath.Join(p.Secrets, r.ID), 0o700); err != nil {
		return "", nil, err
	}
	if key != nil {
		if err := os.WriteFile(filepath.Join(p.Secrets, keyRef), key, 0o600); err != nil {
			return "", nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return "", nil, fmt.Errorf("%w: %s", ErrExists, path)
	} else if err != nil {
		return "", nil, err
	}
	_, err = f.Write(body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return path, nil, err
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
func hint(msg string) string {
	m := strings.ToLower(msg)
	switch {
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

// Check logs in to every host of env (in parallel) and runs `uname -sr`: nothing is changed on the servers.
func Check(ctx context.Context, o *config.Org, env string, conn Runner) []Result {
	var hosts []config.Host
	for _, h := range o.Hosts {
		if h.Env == env {
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
