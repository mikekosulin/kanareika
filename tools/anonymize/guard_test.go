package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTestdataIsAnonymized (the whole repository) keeps data captured from real hosts out of the repository. Every committed testdata file
// (incl. .gz) may only contain fake addresses and e-mails: whatever stands where an address stands must be in a
// range nobody owns or that tools/anonymize maps to. A list of real names cannot live here (it would be the leak),
// so a local denylist can be added: KANAREIKA_DENYLIST=<file with one forbidden string per line>.
// Captures that must stay real go to testdata/local/ (git-ignored) and are skipped.
func TestTestdataIsAnonymized(t *testing.T) {
	allowed := []netip.Prefix{
		netip.MustParsePrefix("10.77.0.0/16"), netip.MustParsePrefix("100.21.0.0/16"), // tools/anonymize
		netip.MustParsePrefix("2a10:77::/32"), netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), // RFC 5737
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("172.16.0.0/12"), // docker networks
		netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("0.0.0.0/32"), netip.MustParsePrefix("::/128"), netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("ff00::/8"),
	}
	ipv4 := regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
	// an address context, as tools/anonymize uses: version numbers like 4.16.1.3 never stand here
	ctx := regexp.MustCompile(`(?:from |"ip": ?"|ip=|inet6? |addr(?:ess)?"?: ?"?|@|[Ll]ocal [Aa]ddress:? |to |src |dst |via |rhost=|Peer |HostName |\[)$`)
	email := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	deny := denylist(t)

	files := 0
	err := filepath.WalkDir("../..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// only the project's own test data: not hidden dirs (.git, and .go — the module cache CI keeps in the
		// project dir), not third-party code, not local captures or data
		if d.IsDir() && p != "../.." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "vendor" ||
			d.Name() == "node_modules" || d.Name() == "local" || d.Name() == "reports" || d.Name() == "secrets" ||
			d.Name() == "orgs" || d.Name() == "dist") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.Contains(p, "testdata"+string(filepath.Separator)) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".gz") {
			if r, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
				if x, err := io.ReadAll(r); err == nil {
					b = x
				}
			}
		}
		files++
		s := string(b)
		for _, loc := range ipv4.FindAllStringIndex(s, -1) {
			if !ctx.MatchString(s[max(0, loc[0]-24):loc[0]]) {
				continue
			}
			a, err := netip.ParseAddr(s[loc[0]:loc[1]])
			if err != nil {
				continue
			}
			ok := false
			for _, pf := range allowed {
				ok = ok || pf.Contains(a)
			}
			if !ok {
				t.Errorf("%s: address %s is not a fake one (run tools/anonymize)", p, a)
				return nil
			}
		}
		for _, loc := range email.FindAllStringIndex(s, -1) {
			if loc[0] > 0 && s[loc[0]-1] == '/' { // package ids (pkg:deb/x/name@version), not e-mails
				continue
			}
			if loc[1] < len(s) && strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_+~", rune(s[loc[1]])) {
				continue
			}
			e := s[loc[0]:loc[1]]
			low := strings.ToLower(e)
			if !strings.HasSuffix(low, "@example.com") && !strings.HasSuffix(low, "@example.org") &&
				!strings.HasSuffix(low, ".example") {
				t.Errorf("%s: e-mail %s is not a fake one (run tools/anonymize)", p, e)
				return nil
			}
		}
		low := strings.ToLower(s)
		for _, w := range deny {
			if strings.Contains(low, w) {
				t.Errorf("%s: contains a denylisted string", p)
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("no testdata found: run from the repository root")
	}
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
		if w := strings.ToLower(strings.TrimSpace(sc.Text())); w != "" && !strings.HasPrefix(w, "#") {
			out = append(out, w)
		}
	}
	return out
}
