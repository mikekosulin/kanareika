// Package network: the org-level external port scan, from the scanner. Only targets listed in orgs/<org>.yml
// `external`, only with consent.external_scan: true (the orchestrator checks consent).
//
// Open ports are found by a plain TCP connect scan in Go (nmap's top 1000 ports or checks.network_external.ports),
// so the scanner needs no nmap and no raw sockets. When nmap is installed it is run afterwards on the open ports
// only (`nmap -sT -sV -Pn --open`) for service names and versions; without it the findings carry no service.
package network

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/finding"
)

// Timing: what an nmap -T template means for the connect scan.
type Timing struct {
	Timeout time.Duration // per connection attempt
	Workers int           // connections in flight
	Delay   time.Duration // between probes of one worker (polite / sneaky / paranoid)
	Retries int           // extra attempts after a timeout (no answer: maybe a dropped SYN)
}

// Timings follow nmap's templates: T0-T2 serialize with nmap's scan delays, T3-T5 trade timeout for speed.
var Timings = map[string]Timing{
	"T0": {Timeout: 5 * time.Second, Workers: 1, Delay: 5 * time.Minute, Retries: 1},
	"T1": {Timeout: 5 * time.Second, Workers: 1, Delay: 15 * time.Second, Retries: 1},
	"T2": {Timeout: 3 * time.Second, Workers: 1, Delay: 400 * time.Millisecond, Retries: 1},
	"T3": {Timeout: 2 * time.Second, Workers: 100, Retries: 1},
	"T4": {Timeout: 1250 * time.Millisecond, Workers: 300, Retries: 1},
	"T5": {Timeout: 300 * time.Millisecond, Workers: 500},
}

// MaxAddresses a CIDR target may expand to; nmap would scan a /8 too, but for days.
const MaxAddresses = 65536

var safe = regexp.MustCompile(`^[A-Za-z0-9.:/_-]+$`)

// Target: the host part of an external entry (a URL's hostname), refused when it could be read as an option.
func Target(value string) (string, error) {
	v := value
	if strings.Contains(value, "://") {
		v = ""
		if u, err := url.Parse(value); err == nil {
			v = strings.ToLower(u.Hostname())
		}
	}
	if v == "" || !safe.MatchString(v) || strings.HasPrefix(v, "-") {
		return "", fmt.Errorf("invalid external target: %q", value)
	}
	return v, nil
}

// ParsePorts: an nmap -p list of TCP ports ("22,80,8000-8100", "-1024", "60000-", "T:443"); sorted, unique.
func ParsePorts(spec string) ([]int, error) {
	set := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		p := strings.TrimSpace(part)
		p = strings.TrimPrefix(p, "T:")
		if p == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(p, "-")
		a, b := 1, 65535
		var err error
		if lo != "" {
			if a, err = port(lo); err != nil {
				return nil, fmt.Errorf("ports %q: %w", spec, err)
			}
		}
		if !isRange {
			b = a
		} else if hi != "" {
			if b, err = port(hi); err != nil {
				return nil, fmt.Errorf("ports %q: %w", spec, err)
			}
		}
		if a > b {
			return nil, fmt.Errorf("ports %q: bad range %s", spec, p)
		}
		for n := a; n <= b; n++ {
			set[n] = true
		}
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("ports %q: no TCP ports", spec)
	}
	out := make([]int, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Ints(out)
	return out, nil
}

func port(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("bad port %q (only TCP port numbers are supported)", s)
	}
	return n, nil
}

// TopPorts: nmap's default list (--top-ports 1000).
func TopPorts() []int {
	p, err := ParsePorts(topPorts)
	if err != nil {
		panic(err)
	}
	return p
}

// Resolver resolves a hostname target; tests replace it. nmap scans the first IPv4 address of a name.
var Resolver = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
}

// Addresses of one target: an address, every address of a CIDR (as nmap: network and broadcast included), or the
// first address of a hostname.
func Addresses(ctx context.Context, t string) ([]netip.Addr, error) {
	if p, err := netip.ParsePrefix(t); err == nil {
		p = p.Masked()
		if bits := p.Addr().BitLen() - p.Bits(); bits > 16 {
			return nil, fmt.Errorf("%s: more than %d addresses", t, MaxAddresses)
		}
		var out []netip.Addr
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			out = append(out, a)
		}
		return out, nil
	}
	if a, err := netip.ParseAddr(t); err == nil {
		return []netip.Addr{a}, nil
	}
	addrs, err := Resolver(ctx, t)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s: no IPv4 address", t)
	}
	return addrs[:1], nil
}

// Scan: open TCP ports per address (sorted), by full connect. A refused connection is closed, no answer within the
// timeout (after the retries) is filtered; both are left out.
func Scan(ctx context.Context, addrs []netip.Addr, ports []int, t Timing) map[netip.Addr][]int {
	if t.Workers < 1 {
		t.Workers = 1
	}
	type job struct {
		a netip.Addr
		p int
	}
	jobs := make(chan job)
	var mu sync.Mutex
	open := map[netip.Addr][]int{}
	var wg sync.WaitGroup
	for range t.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first := true
			for j := range jobs {
				if t.Delay > 0 && !first {
					select {
					case <-ctx.Done():
					case <-time.After(t.Delay):
					}
				}
				first = false
				if probe(ctx, j.a, j.p, t) {
					mu.Lock()
					open[j.a] = append(open[j.a], j.p)
					mu.Unlock()
				}
			}
		}()
	}
feed:
	for _, a := range addrs {
		for _, p := range ports {
			select {
			case jobs <- job{a, p}:
			case <-ctx.Done():
				break feed
			}
		}
	}
	close(jobs)
	wg.Wait()
	for a := range open {
		sort.Ints(open[a])
	}
	return open
}

func probe(ctx context.Context, a netip.Addr, p int, t Timing) bool {
	d := net.Dialer{Timeout: t.Timeout}
	for try := 0; try <= t.Retries; try++ {
		if ctx.Err() != nil {
			return false
		}
		c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(a, uint16(p)).String())
		if err == nil {
			c.Close()
			return true
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			return false // refused / unreachable: an answer, no point retrying
		}
	}
	return false
}

// service: what nmap -sV said about one port.
type service struct{ name, product string }

type nmapRun struct {
	Hosts []struct {
		Address []struct {
			Addr string `xml:"addr,attr"`
		} `xml:"address"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service *struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
				Version string `xml:"version,attr"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

// LookNmap finds nmap; tests replace it.
var LookNmap = func() (string, error) { return exec.LookPath("nmap") }

// services runs nmap -sV on the open ports only and returns addr -> port -> service. The XML is kept next to the
// run as the Python module kept it.
func services(ctx context.Context, nmap, xmlPath, timing string, open map[netip.Addr][]int) (map[string]map[int]service, error) {
	set := map[int]bool{}
	var addrs []netip.Addr
	for a, ps := range open {
		addrs = append(addrs, a)
		for _, p := range ps {
			set[p] = true
		}
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	var ports []string
	for p := range set {
		ports = append(ports, strconv.Itoa(p))
	}
	sort.Slice(ports, func(i, j int) bool { a, _ := strconv.Atoi(ports[i]); b, _ := strconv.Atoi(ports[j]); return a < b })
	args := []string{"-sT", "-sV", "-Pn", "--open", "-" + timing, "-p", strings.Join(ports, ","), "-oX", xmlPath}
	if len(addrs) > 0 && addrs[0].Is6() && !addrs[0].Is4In6() {
		args = append(args, "-6")
	}
	args = append(args, "--")
	for _, a := range addrs {
		args = append(args, a.String())
	}
	cctx, cancel := context.WithTimeout(ctx, time.Hour)
	defer cancel()
	cmd := exec.CommandContext(cctx, nmap, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		s := strings.TrimSpace(stderr.String())
		if len(s) > 300 {
			s = s[len(s)-300:]
		}
		return nil, fmt.Errorf("%w: %s", err, s)
	}
	b, err := os.ReadFile(xmlPath)
	if err != nil {
		return nil, err
	}
	var run nmapRun
	if err := xml.Unmarshal(b, &run); err != nil {
		return nil, err
	}
	out := map[string]map[int]service{}
	for _, h := range run.Hosts {
		if len(h.Address) == 0 {
			continue
		}
		addr := h.Address[0].Addr
		for _, p := range h.Ports {
			if p.State.State != "open" || p.Protocol != "tcp" || p.Service == nil {
				continue
			}
			var prod []string
			for _, s := range []string{p.Service.Product, p.Service.Version} {
				if s != "" {
					prod = append(prod, s)
				}
			}
			if out[addr] == nil {
				out[addr] = map[int]service{}
			}
			out[addr][p.PortID] = service{p.Service.Name, strings.Join(prod, " ")}
		}
	}
	return out, nil
}

// RunExternal scans the external targets of env. cfg: ports (nmap -p syntax), timing (T2/T3/T4, default T3).
func RunExternal(ctx *check.Ctx, cfg map[string]any, env string) ([]finding.Finding, error) {
	set := map[string]bool{}
	for _, v := range ctx.Org.External(env) {
		t, err := Target(v)
		if err != nil {
			return nil, err
		}
		set[t] = true
	}
	if len(set) == 0 {
		return nil, nil
	}
	targets := make([]string, 0, len(set))
	for t := range set {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	out := filepath.Join(ctx.RunDir, "external")
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	ports := TopPorts()
	if spec := fmt.Sprint(cfg["ports"]); cfg["ports"] != nil && spec != "" {
		var err error
		if ports, err = ParsePorts(spec); err != nil {
			return nil, err
		}
	}
	timing, _ := cfg["timing"].(string)
	if timing == "" {
		timing = "T3"
	}
	tm, ok := Timings[timing]
	if !ok { // nmap refused it for every target; the run went on without findings
		ctx.Log("external: unknown timing %q", timing)
		return nil, nil
	}
	nmap, nmapErr := LookNmap()
	var findings []finding.Finding
	for _, t := range targets {
		addrs, err := Addresses(ctx, t)
		if err != nil {
			ctx.Log("external %s: %v", t, err)
			continue
		}
		open := Scan(ctx, addrs, ports, tm)
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		var svc map[string]map[int]service
		if len(open) > 0 && nmapErr == nil {
			xmlPath := filepath.Join(out, "nmap-"+strings.ReplaceAll(t, "/", "_")+".xml")
			if svc, err = services(ctx, nmap, xmlPath, timing, open); err != nil {
				ctx.Log("external %s: nmap failed: %v", t, err) // ports stay, without service names
			}
		}
		for _, a := range addrs {
			addr := a.String()
			for _, p := range open[a] {
				s := svc[addr][p]
				findings = append(findings, finding.Finding{
					Org: ctx.Org.ID, Host: "external:" + t, Group: "external", Exposure: 1, Module: "network_external",
					Kind: finding.Exposure, ID: fmt.Sprintf("open-port-tcp-%d", p), Pkg: s.name, Installed: s.product,
					Severity: "INFO", Title: strings.TrimSpace(fmt.Sprintf("open %d/tcp %s %s", p, s.name, s.product)),
					Target: addr,
				})
			}
		}
		ctx.Log("external %s: done", t)
	}
	return findings, nil
}
