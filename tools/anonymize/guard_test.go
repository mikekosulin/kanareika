package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
)

// The guard keeps real data out of the repository and out of the binary.
//
// Every file that is or could be committed (tracked, or new and not ignored) is checked:
//   - nothing from the local, never committed orgs/*.yml: org ids and names, host names, addresses, jump hosts,
//     external targets, the consent document. Those files exist only on the auditor's machine, so the check runs
//     there (where leaks are made) and the list of real names is never written anywhere;
//   - nothing from KANAREIKA_DENYLIST (a local file, one forbidden string per line), for names not in orgs/;
//   - in data files (testdata, assets embedded into the binary, docs, examples): only fake addresses and e-mails —
//     whatever stands where an address stands must be in a range nobody owns or that tools/anonymize maps to.
//
// Captures that must stay real go to testdata/local/ (git-ignored) and are never seen here.

// internalOnly: files of the internal GitLab mirror that are never published (the GitHub repository has none of
// them); they may name the organization's own CI runners.
var internalOnly = []string{".gitlab-ci.yml"}

var (
	allowedNets = []netip.Prefix{
		netip.MustParsePrefix("10.77.0.0/16"), netip.MustParsePrefix("100.21.0.0/16"), // tools/anonymize
		netip.MustParsePrefix("2a10:77::/32"), netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), // RFC 5737
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("172.16.0.0/12"), // docker networks
		netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("0.0.0.0/32"), netip.MustParsePrefix("::/128"), netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("ff00::/8"),
	}
	// an address context, as tools/anonymize uses: version numbers like 4.16.1.3 never stand here
	addrCtx = regexp.MustCompile(`(?:from |"ip": ?"|ip=|inet6? |addr(?:ess)?"?: ?"?|@|[Ll]ocal [Aa]ddress:? |to |src |dst |via |rhost=|Peer |HostName |\[)$`)
)

const root = "../.."

// candidates: repository-relative paths of what is or could be committed; nil without git.
func candidates(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output()
	if err != nil {
		return nil
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, filepath.FromSlash(f))
		}
	}
	return files
}

// walked: the same without git (a source tarball): every file but hidden, local, generated and data directories.
func walked(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p != root && (strings.HasPrefix(d.Name(), ".") || slices.Contains([]string{"vendor",
			"node_modules", "local", "reports", "secrets", "orgs", "dist"}, d.Name())) {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// dataFile: content that ends up as data (fixtures, the embedded assets, docs and examples), where every address
// and e-mail must be a fake one. Source code may name real public things (8.8.8.8 as "the Internet").
func dataFile(rel string) bool {
	s := filepath.ToSlash(rel)
	return strings.Contains(s, "testdata/") || strings.HasPrefix(s, "assets/") || strings.HasPrefix(s, "docs/") ||
		strings.HasPrefix(s, "orgs/_") || strings.HasSuffix(s, ".md")
}

func load(p string) ([]byte, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(p, ".gz") {
		if r, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
			if x, err := io.ReadAll(r); err == nil {
				return x, nil
			}
		}
	}
	return b, nil
}

func TestNoRealData(t *testing.T) {
	files := candidates(t)
	if files == nil {
		files = walked(t)
	}
	if len(files) == 0 {
		t.Fatal("no files found: run from the repository")
	}
	deny := words(append(denylist(t), realNames(t)...))
	data := 0
	for _, rel := range files {
		p := filepath.Join(root, rel)
		if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() {
			continue // deleted in the work tree, or a link
		}
		b, err := load(p)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if deny != nil && !slices.Contains(internalOnly, filepath.ToSlash(rel)) && deny.MatchString(s) {
			t.Errorf("%s: contains a real name or address from orgs/ or the denylist", rel)
		}
		if dataFile(rel) {
			data++
			if problem := checkData(s); problem != "" {
				t.Errorf("%s: %s (run tools/anonymize)", rel, problem)
			}
		}
	}
	if data == 0 {
		t.Fatal("no data files found")
	}
}

// checkData: the first address or e-mail in s that is not a fake one, "" when all are.
func checkData(s string) string {
	for _, loc := range ipv4.FindAllStringIndex(s, -1) {
		if !addrCtx.MatchString(s[max(0, loc[0]-24):loc[0]]) {
			continue
		}
		a, err := netip.ParseAddr(s[loc[0]:loc[1]])
		if err != nil {
			continue
		}
		if !slices.ContainsFunc(allowedNets, func(p netip.Prefix) bool { return p.Contains(a) }) {
			return "address " + a.String() + " is not a fake one"
		}
	}
	for _, loc := range email.FindAllStringIndex(s, -1) {
		if loc[0] > 0 && s[loc[0]-1] == '/' { // package ids (pkg:deb/x/name@version), not e-mails
			continue
		}
		if loc[1] < len(s) && strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_+~", rune(s[loc[1]])) {
			continue
		}
		low := strings.ToLower(s[loc[0]:loc[1]])
		if !strings.HasSuffix(low, "@example.com") && !strings.HasSuffix(low, "@example.org") &&
			!strings.HasSuffix(low, ".example") {
			return "e-mail " + s[loc[0]:loc[1]] + " is not a fake one"
		}
	}
	return ""
}

// words: one case-insensitive regexp for all of ws, each matching only as a whole name ("acme" does not match
// "acmesoft"); nil for none.
func words(ws []string) *regexp.Regexp {
	if len(ws) == 0 {
		return nil
	}
	q := make([]string, len(ws))
	for i, w := range ws {
		q[i] = regexp.QuoteMeta(w)
	}
	return regexp.MustCompile(`(?i)(?:^|[^a-z0-9_-])(?:` + strings.Join(q, "|") + `)(?:$|[^a-z0-9_-])`)
}

func denylist(t *testing.T) []string {
	path := os.Getenv("KANAREIKA_DENYLIST")
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("KANAREIKA_DENYLIST: %v", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if w := strings.TrimSpace(sc.Text()); w != "" && !strings.HasPrefix(w, "#") {
			out = append(out, w)
		}
	}
	return out
}

// realNames: what identifies the real organizations of this machine's orgs/ (none in CI or a fresh clone).
// Names the committed example and template use (app-01, audit, ...) are generic and left out; so are words of
// fewer than 3 characters, which match too much to tell anything.
func realNames(t *testing.T) []string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(root, "orgs", "*.yml"))
	var real []string
	for _, f := range files {
		if !strings.HasPrefix(filepath.Base(f), "_") {
			real = append(real, f)
		}
	}
	if len(real) == 0 {
		return nil
	}
	l, err := config.NewLoader(config.PathsAt(root))
	if err != nil {
		t.Logf("orgs/ not readable, real names not checked: %v", err)
		return nil
	}
	orgs, _ := l.LoadAll()
	generic := ""
	for _, f := range []string{"orgs/_example.yml", "assets/templates/org.yml"} {
		b, _ := os.ReadFile(filepath.Join(root, f))
		generic += strings.ToLower(string(b))
	}
	seen := map[string]bool{}
	var out []string
	add := func(w string) {
		w = strings.TrimSpace(w)
		lw := strings.ToLower(w)
		if len(w) < 3 || seen[lw] || words([]string{w}).MatchString(generic) {
			return
		}
		if a, err := netip.ParseAddr(w); err == nil && slices.ContainsFunc(allowedNets, func(p netip.Prefix) bool { return p.Contains(a) }) {
			return
		}
		seen[lw] = true
		out = append(out, w)
	}
	for _, o := range orgs {
		if strings.HasPrefix(o.ID, "_") {
			continue
		}
		add(o.ID)
		add(o.Name())
		if d, ok := o.Consent()["document"].(string); ok {
			add(d)
		}
		for _, h := range o.Hosts {
			add(h.Name)
			add(h.Address)
		}
		for name, j := range o.Jumps() {
			add(name)
			if a, ok := j["address"].(string); ok {
				add(a)
			}
		}
		for _, env := range o.Envs() {
			for _, e := range o.External(env) {
				add(e)
			}
		}
	}
	t.Logf("checked against %d real names and addresses from %d org files", len(out), len(real))
	return out
}

// TestEmbedsOnlyAssets: what goes into the binary comes from assets/ only, from directories made for it. A new
// //go:embed anywhere else (say, of orgs/ or reports/) fails here before it can ship real data.
func TestEmbedsOnlyAssets(t *testing.T) {
	allowed := []string{"policy/", "schemas/", "locales/", "web/", "templates/"}
	directive := regexp.MustCompile(`(?m)^\s*//go:embed\s+(.+)$`)
	found := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range directive.FindAllStringSubmatch(string(b), -1) {
			rel, _ := filepath.Rel(root, p)
			if filepath.ToSlash(rel) != "assets/assets.go" {
				if !strings.HasSuffix(rel, "_test.go") {
					t.Errorf("%s: //go:embed outside assets/assets.go", rel)
				}
				continue
			}
			for _, pat := range strings.Fields(m[1]) {
				found++
				if !slices.ContainsFunc(allowed, func(a string) bool { return strings.HasPrefix(pat, a) }) {
					t.Errorf("assets/assets.go: //go:embed %s is outside %v", pat, allowed)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no //go:embed found in assets/assets.go")
	}
}

// TestGuardCatches: the guard itself, on synthetic leaks.
func TestGuardCatches(t *testing.T) {
	for in, want := range map[string]string{
		`"ip": "8.8.4.4"`:                      "address 8.8.4.4",
		`from 192.0.2.7 port 22`:               "",
		`Accepted publickey from 100.21.3.4`:   "",
		`version 4.16.1.3`:                     "", // not where an address stands
		`ops@realcorp.io wrote`:                "e-mail ops@realcorp.io",
		`ops@example.com, a@b.example`:         "",
		`pkg:deb/ubuntu/libc6@2.35-0ubuntu3.8`: "",
	} {
		if got := checkData(in); want == "" && got != "" || want != "" && !strings.HasPrefix(got, want) {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	re := words([]string{"acme", "web-07", "203.0.113.9"})
	for in, want := range map[string]bool{"org: acme\n": true, "ACME Corp": true, "acmesoft": false, "my-acme": false,
		"host web-07.": true, "web-070": false, "addr 203.0.113.9": true, "203.0.113.90": false} {
		if re.MatchString(in) != want {
			t.Errorf("%q: %v", in, !want)
		}
	}
	if words(nil) != nil {
		t.Fatal("empty")
	}
	for f, want := range map[string]bool{"internal/x/testdata/a.json": true, "assets/locales/ru.json": true,
		"docs/org-file.md": true, "orgs/_example.yml": true, "README.md": true, "internal/x/x.go": false} {
		if dataFile(f) != want {
			t.Errorf("%s: %v", f, !want)
		}
	}
}
