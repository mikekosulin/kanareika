// Command anonymize rewrites test data captured from real hosts so it can be committed: addresses, e-mails, SSH
// keys and fingerprints, MAC addresses and the names of the organizations, hosts and people from orgs/*.yml are
// replaced consistently across every file (including .gz), keeping what tests depend on (private stays private,
// public stays public, the same address maps to the same fake one everywhere).
//
//	go run ./tools/anonymize [-dry-run] [-orgs orgs] [-extra word,...] <dir>...
//
// Real names come from the local orgs/ (never committed); the mapping is printed to stderr for review.
// Afterwards `go test ./...` runs the testdata guard, which fails on anything that still looks real.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/mikekosulin/kanareika/internal/config"
)

type mapper struct {
	ips    map[string]string // real address -> fake
	words  [][2]string       // case-insensitive literal replacements, longest first
	emails map[string]string
	keys   map[string]string // base64 blob -> fake blob
	fps    map[string]string
	macs   map[string]string
	nPriv  int
	nPub   int
	nPub6  int
}

var (
	ipv4    = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
	ipv6    = regexp.MustCompile(`(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}`) // a whole run; v6Spans checks it
	email   = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	sshKey  = regexp.MustCompile(`(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|sk-[a-z0-9@.-]+) (AAAA[0-9A-Za-z+/]+=*)`)
	fprint  = regexp.MustCompile(`SHA256:[0-9A-Za-z+/]{43}`)
	mac     = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b`)
	ipCtx   = regexp.MustCompile(`(?:from |"ip": ?"|ip=|inet6? |addr(?:ess)?"?: ?"?|@|[Ll]ocal [Aa]ddress:? |to |src |dst |via |rhost=|Peer |HostName |\[|pts/\d+ +|tty\d* +)$`)
	cidr    = regexp.MustCompile(`^/\d{1,2}\b`)
	docNets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}
)

// Fakes are recognizable, so a second run leaves them alone: link-local addresses start with fakeLinkLocal, MACs
// with 02:00: (locally administered), fingerprints with SHA256:anon. SSH keys are the exception: a public key has
// no room for a mark, so a rerun swaps fake keys for new fake ones (harmless, but a diff).
const (
	fakeLinkLocal = "fe80::a0a0:"
	fakeMAC       = "02:00:"
	fakeFP        = "SHA256:anon"
)

// fake ranges: private -> 10.77.0.0/16, public -> 100.21.0.0/16 (global, so "public" logic still triggers),
// public v6 -> 2a10:77::/32
func (m *mapper) fakeIP(real string) {
	if _, ok := m.ips[real]; ok {
		return
	}
	a, err := netip.ParseAddr(real)
	if err != nil || keep(a) {
		return
	}
	var f string
	switch {
	case a.Is4() && a.IsPrivate():
		m.nPriv++
		f = fmt.Sprintf("10.77.%d.%d", m.nPriv/250, m.nPriv%250+1)
	case a.Is4():
		m.nPub++
		f = fmt.Sprintf("100.21.%d.%d", m.nPub/250, m.nPub%250+1)
	case a.IsLinkLocalUnicast(): // fe80::<MAC-derived>
		h := sha256.Sum256([]byte(real))
		f = fmt.Sprintf("%s%x:%x", fakeLinkLocal, uint16(h[0])<<8|uint16(h[1]), uint16(h[2])<<8|uint16(h[3]))
	default:
		m.nPub6++
		f = fmt.Sprintf("2a10:77::%x", m.nPub6)
	}
	m.ips[real] = f
}

// keep: addresses that identify nothing (loopback, unspecified, broadcast, multicast, docker default bridges,
// documentation ranges already used by synthetic data).
func keep(a netip.Addr) bool {
	if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a == netip.MustParseAddr("255.255.255.255") {
		return true
	}
	if a.Is4() && netip.MustParsePrefix("172.16.0.0/12").Contains(a) { // docker networks
		return true
	}
	switch a.String() { // bases of the private blocks (10.0.0.0/8 …): generic, and recipes use them
	case "10.0.0.0", "192.168.0.0", "172.16.0.0", "100.64.0.0", "169.254.0.0", "fe80::":
		return true
	}
	if a.Is4() && netip.MustParsePrefix("10.77.0.0/16").Contains(a) || netip.MustParsePrefix("100.21.0.0/16").Contains(a) ||
		netip.MustParsePrefix("2a10:77::/32").Contains(a) || strings.HasPrefix(a.String(), fakeLinkLocal) {
		return true // already fake
	}
	for _, p := range docNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (m *mapper) fakeKey(kind, blob string) string {
	if f, ok := m.keys[blob]; ok {
		return f
	}
	var pub ssh.PublicKey
	switch {
	case kind == "ssh-ed25519" || kind == "ssh-dss" || strings.HasPrefix(kind, "sk-"): // written back as ssh-ed25519
		p, _, _ := ed25519.GenerateKey(rand.Reader)
		pub, _ = ssh.NewPublicKey(p)
	case kind == "ssh-rsa":
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		pub, _ = ssh.NewPublicKey(&k.PublicKey)
	default:
		curve := map[string]elliptic.Curve{"ecdsa-sha2-nistp256": elliptic.P256(), "ecdsa-sha2-nistp384": elliptic.P384(),
			"ecdsa-sha2-nistp521": elliptic.P521()}[kind]
		k, _ := ecdsa.GenerateKey(curve, rand.Reader)
		pub, _ = ssh.NewPublicKey(&k.PublicKey)
	}
	f := base64.StdEncoding.EncodeToString(pub.Marshal())
	m.keys[blob] = f
	return f
}

func randomish(seed string, n int) string {
	h := sha256.Sum256([]byte("anon:" + seed))
	return base64.RawStdEncoding.EncodeToString(h[:])[:n]
}

func (m *mapper) rewrite(s string) string {
	// 1. keys and fingerprints first (their base64 must not be touched by word replacement)
	s = sshKey.ReplaceAllStringFunc(s, func(x string) string {
		g := sshKey.FindStringSubmatch(x)
		kind := g[1]
		if kind == "ssh-dss" || strings.HasPrefix(kind, "sk-") {
			kind = "ssh-ed25519"
		}
		return kind + " " + m.fakeKey(g[1], g[2])
	})
	s = fprint.ReplaceAllStringFunc(s, func(x string) string {
		if strings.HasPrefix(x, fakeFP) {
			return x
		}
		if f, ok := m.fps[x]; ok {
			return f
		}
		f := fakeFP + randomish(x, 43-len(fakeFP)+len("SHA256:"))
		m.fps[x] = f
		return f
	})
	s = mac.ReplaceAllStringFunc(s, func(x string) string {
		if strings.EqualFold(x, "00:00:00:00:00:00") || strings.EqualFold(x, "ff:ff:ff:ff:ff:ff") || strings.HasPrefix(strings.ToLower(x), fakeMAC) {
			return x
		}
		if f, ok := m.macs[strings.ToLower(x)]; ok {
			return f
		}
		h := sha256.Sum256([]byte(x))
		f := fmt.Sprintf(fakeMAC+"%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3])
		m.macs[strings.ToLower(x)] = f
		return f
	})
	// 2. e-mails
	s = replaceEmails(s, func(x string) string {
		low := strings.ToLower(x)
		if strings.HasSuffix(low, "@example.com") || strings.HasSuffix(low, "@example.org") || strings.HasSuffix(low, ".example") {
			return x
		}
		if f, ok := m.emails[low]; ok {
			return f
		}
		f := fmt.Sprintf("user%d@example.com", len(m.emails)+1)
		m.emails[low] = f
		return f
	})
	// 3. addresses seen as addresses anywhere
	s = ipv4.ReplaceAllStringFunc(s, func(x string) string {
		if f, ok := m.ips[x]; ok {
			return f
		}
		return x
	})
	var b strings.Builder
	last := 0
	for _, loc := range v6Spans(s) {
		x := strings.ToLower(s[loc[0]:loc[1]])
		f, ok := m.ips[x]
		if !ok { // ss writes address:port without brackets: fe80::1:123
			if addr, port, cut := portSuffix(x); cut {
				if f, ok = m.ips[addr]; ok {
					f += ":" + port
				}
			}
		}
		if ok {
			b.WriteString(s[last:loc[0]])
			b.WriteString(f)
			last = loc[1]
		}
	}
	b.WriteString(s[last:])
	s = b.String()
	// 4. names: organizations, hosts, people, domains
	for _, w := range m.words {
		s = replaceFold(s, w[0], w[1])
	}
	return s
}

// replaceEmails: like ReplaceAllStringFunc over e-mails, but package ids (pkg:deb/x/lshw@02.19.git,
// openssl@3.0.7-27.el9) are not e-mails: skip matches right after '/' or followed by more name characters.
func replaceEmails(s string, f func(string) string) string {
	var b strings.Builder
	last := 0
	for _, loc := range email.FindAllStringIndex(s, -1) {
		if loc[0] > 0 && (s[loc[0]-1] == '/' || s[loc[0]-1] == '\\') { // pkg:…/name@ver, JSON \u003c escapes
			continue
		}
		if loc[1] < len(s) && strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_+~", rune(s[loc[1]])) {
			continue
		}
		b.WriteString(s[last:loc[0]])
		b.WriteString(f(s[loc[0]:loc[1]]))
		last = loc[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

func replaceFold(s, old, repl string) string {
	if old == "" {
		return s
	}
	return replaceWord(s, old, repl, strings.HasSuffix(old, "-"))
}

// replaceWord: case-insensitive, whole words only ("несколько" does not contain the word "ско").
func replaceWord(s, old, repl string, prefix bool) string {
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(old))
	var b strings.Builder
	last := 0
	for _, loc := range re.FindAllStringIndex(s, -1) {
		before, _ := utf8.DecodeLastRuneInString(s[:loc[0]])
		after, _ := utf8.DecodeRuneInString(s[loc[1]:])
		if loc[0] > 0 && (unicode.IsLetter(before) || unicode.IsDigit(before)) {
			continue
		}
		if !prefix && loc[1] < len(s) && (unicode.IsLetter(after) || unicode.IsDigit(after)) {
			continue
		}
		b.WriteString(s[last:loc[0]])
		b.WriteString(repl)
		last = loc[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// collect: addresses that appear in an address context anywhere, or as a CIDR network (versions like 4.16.1.3
// never do).
func (m *mapper) collect(s string) {
	for _, loc := range ipv4.FindAllStringIndex(s, -1) {
		x := s[loc[0]:loc[1]]
		a, err := netip.ParseAddr(x)
		if err != nil || keep(a) {
			continue
		}
		if ipCtx.MatchString(s[max(0, loc[0]-24):loc[0]]) || cidr.MatchString(s[loc[1]:min(len(s), loc[1]+4)]) {
			m.fakeIP(x)
		}
	}
	var cands []string
	for _, loc := range v6Spans(s) {
		cands = append(cands, strings.ToLower(s[loc[0]:loc[1]]))
	}
	for _, x := range cands {
		if strings.HasPrefix(x, "::") { // ::1:25 in ss output is [::1]:25; real addresses don't start with ::
			continue
		}
		if addr, _, cut := portSuffix(x); cut && slices.Contains(cands, addr) {
			continue // the same address with a port after it (ss)
		}
		if a, _ := netip.ParseAddr(x); !keep(a) && (a.IsGlobalUnicast() || a.IsLinkLocalUnicast()) {
			m.fakeIP(x)
		}
	}
}

// portSuffix: fe80::1:123 -> fe80::1, 123 when the last group is all decimal digits.
func portSuffix(x string) (addr, port string, ok bool) {
	i := strings.LastIndexByte(x, ':')
	if i <= 0 || i == len(x)-1 || strings.Trim(x[i+1:], "0123456789") != "" || x[i-1] == ':' {
		return "", "", false
	}
	return x[:i], x[i+1:], true
}

// v6Spans: IPv6 addresses in s, whole (fe80::5054:ff:fe12:3456, not its first half) and not inside a longer word
// (times like 12:34:56 and MACs are no addresses).
func v6Spans(s string) [][2]int {
	var out [][2]int
	for _, loc := range ipv6.FindAllStringIndex(s, -1) {
		if loc[0] > 0 {
			if r, _ := utf8.DecodeLastRuneInString(s[:loc[0]]); unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' {
				continue
			}
		}
		if a, err := netip.ParseAddr(s[loc[0]:loc[1]]); err == nil && a.Is6() && !a.Is4In6() {
			out = append(out, [2]int{loc[0], loc[1]})
		}
	}
	return out
}

func read(path string) (string, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	gz := strings.HasSuffix(path, ".gz")
	if gz {
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return "", false, nil
		}
		if b, err = io.ReadAll(r); err != nil {
			return "", false, nil
		}
	}
	if !utf8.Valid(b) || strings.HasSuffix(path, ".tar") || bytes.HasPrefix(b[min(257, len(b)):], []byte("ustar")) {
		return "", false, nil // binary or tar (headers carry sizes and checksums): reported, rewrite by hand
	}
	return string(b), true, nil
}

func write(path, s string) error {
	if !strings.HasSuffix(path, ".gz") {
		return os.WriteFile(path, []byte(s), 0o644)
	}
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, 6)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// exit: os.Exit, swapped by the test of main.
var exit = os.Exit

func main() { exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, stderr io.Writer) int {
	fl := flag.NewFlagSet("anonymize", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dry := fl.Bool("dry-run", false, "show what would change, write nothing")
	orgsDir := fl.String("orgs", "orgs", "where the real org files are (names to replace come from them)")
	extra := fl.String("extra", "", "more words to replace, comma separated (word or word=replacement)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	m := &mapper{ips: map[string]string{}, emails: map[string]string{}, keys: map[string]string{},
		fps: map[string]string{}, macs: map[string]string{}}

	words := map[string]string{}
	l, err := config.NewLoader(config.PathsAt(filepath.Dir(filepath.Clean(*orgsDir))))
	if err == nil {
		orgs, _ := l.LoadAll()
		for i, o := range orgs {
			alias := fmt.Sprintf("org%d", i+1)
			words[o.ID] = alias
			if n := o.Name(); n != "" {
				words[n] = "Example Org"
			}
			for j, h := range o.Hosts {
				words[h.Name] = fmt.Sprintf("host-%02d", j+1)
				m.fakeIP(h.Address)
			}
			for _, j := range o.Jumps() {
				if a, ok := j["address"].(string); ok {
					m.fakeIP(a)
				}
			}
			for _, env := range o.Envs() {
				for _, e := range o.External(env) {
					m.fakeIP(e)
				}
			}
		}
	}
	for _, w := range strings.Split(*extra, ",") {
		if w = strings.TrimSpace(w); w == "" {
			continue
		}
		k, v, ok := strings.Cut(w, "=")
		if !ok {
			v = "redacted"
		}
		words[k] = v
	}
	for k, v := range words {
		m.words = append(m.words, [2]string{k, v})
	}
	sort.Slice(m.words, func(i, j int) bool { return len(m.words[i][0]) > len(m.words[j][0]) })

	var files []string
	for _, root := range fl.Args() {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "local" {
				return filepath.SkipDir // local captures stay real and uncommitted
			}
			if !d.IsDir() && strings.Contains(p, string(filepath.Separator)+"testdata"+string(filepath.Separator)) {
				files = append(files, p)
			}
			return nil
		})
	}
	texts := map[string]string{}
	for _, f := range files {
		s, ok, err := read(f)
		if err != nil {
			fmt.Fprintln(stderr, f, err)
			return 1
		}
		if !ok {
			fmt.Fprintln(stderr, "skipped (binary):", f)
			continue
		}
		texts[f] = s
		m.collect(s)
	}
	// a second pass: any other address in the same /24 as a real one is real too (networks, gateways, neighbours)
	nets := map[netip.Prefix]bool{}
	for real := range m.ips {
		if a, err := netip.ParseAddr(real); err == nil && a.Is4() {
			p, _ := a.Prefix(24)
			nets[p] = true
		}
	}
	for _, s := range texts {
		for _, x := range ipv4.FindAllString(s, -1) {
			if a, err := netip.ParseAddr(x); err == nil && !keep(a) {
				if p, _ := a.Prefix(24); nets[p] {
					m.fakeIP(x)
				}
			}
		}
	}
	changed := 0
	for _, f := range files {
		s, ok := texts[f]
		if !ok {
			continue
		}
		out := m.rewrite(s)
		if out == s {
			continue
		}
		changed++
		if !*dry {
			if err := write(f, out); err != nil {
				fmt.Fprintln(stderr, f, err)
				return 1
			}
		}
	}
	fmt.Fprintf(stderr, "files: %d, changed: %d; addresses %d, e-mails %d, ssh keys %d, fingerprints %d, MACs %d, names %d\n",
		len(files), changed, len(m.ips), len(m.emails), len(m.keys), len(m.fps), len(m.macs), len(m.words))
	return 0
}
