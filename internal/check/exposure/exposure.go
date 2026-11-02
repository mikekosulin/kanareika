// Package exposure: what the host exposes — addresses (incl. public IPs missing from the org file), listening
// sockets with their processes, and the firewall as configured (firewalld / nftables / iptables / ufw).
//
// Read-only: only list/show commands. Process names on sockets and firewall rules need root or the host's
// privilege mode.
package exposure

import (
	"fmt"
	"math/bits"
	"net/netip"
	"net/url"
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
sec addrs; ip -o addr show 2>/dev/null | awk '{print $2, $3, $4}'
sec routes; ip route show default 2>/dev/null
sec listen; @P:sockets@ || ss -Hltnu 2>/dev/null
@P:firewall@
`

// Sensitive: services that should normally never listen on a public address.
var Sensitive = map[int]string{
	22: "ssh", 2375: "docker API (no TLS)", 2376: "docker API", 2377: "swarm manager", 7946: "swarm gossip",
	3306: "mysql", 5432: "postgres", 6379: "redis", 27017: "mongodb", 9200: "elasticsearch", 11211: "memcached",
	5672: "rabbitmq", 15672: "rabbitmq UI", 9092: "kafka", 2181: "zookeeper", 8086: "influxdb", 9090: "prometheus",
	9100: "node_exporter", 8080: "http-alt", 3000: "grafana/app", 10250: "kubelet", 6443: "k8s API", 8500: "consul",
	9000: "portainer/minio", 9443: "portainer", 4369: "erlang epmd", 8428: "victoriametrics", 3100: "loki",
	111: "rpcbind", 4789: "VXLAN (Docker Swarm overlay)", 2049: "NFS", 445: "SMB", 139: "NetBIOS", 25: "SMTP",
	5900: "VNC", 3389: "RDP", 8429: "vmagent", 9093: "alertmanager", 4040: "pyroscope", 3200: "tempo",
	24007: "glusterfs", 49152: "glusterfs brick", 6380: "redis", 9644: "redpanda admin", 8081: "schema registry",
	8082: "redpanda proxy", 33145: "redpanda rpc", 8108: "typesense", 5222: "xmpp", 5269: "xmpp s2s",
}

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// Python 3.13 ipaddress: not globally reachable blocks (IANA special registries) and their exceptions.
var (
	private4 = prefixes("0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
		"192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"240.0.0.0/4", "255.255.255.255/32")
	private4Except = prefixes("192.0.0.9/32", "192.0.0.10/32")
	private6       = prefixes("::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10")
	private6Except = prefixes("2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48", "2001:20::/28",
		"2001:30::/28")
	shared = netip.MustParsePrefix("100.64.0.0/10")
)

func in(a netip.Addr, nets []netip.Prefix) bool {
	for _, n := range nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// isGlobal: ipaddress.ip_address(a).is_global (IPv4-mapped IPv6 follows the IPv4 address).
func isGlobal(a netip.Addr) bool {
	a = a.WithZone("")
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Is4() {
		return !shared.Contains(a) && !(in(a, private4) && !in(a, private4Except))
	}
	return !(in(a, private6) && !in(a, private6Except))
}

// IsPublic: a globally reachable address (CGNAT 100.64/10 is not).
func IsPublic(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return isGlobal(a) && !(a.Is4() && shared.Contains(a))
}

// knownNets: addresses / networks the org file lists (hosts, jumps, external targets); hostnames are left out.
func knownNets(o *config.Org) []netip.Prefix {
	if o == nil {
		return nil
	}
	var vals []string
	for _, h := range o.Hosts {
		vals = append(vals, h.Address)
	}
	for _, j := range o.Jumps() {
		s, _ := j["address"].(string)
		vals = append(vals, s)
	}
	for _, env := range o.Envs() {
		vals = append(vals, o.External(env)...)
	}
	var out []netip.Prefix
	for _, v := range vals {
		if p, ok := network(v); ok {
			out = append(out, p)
		}
	}
	return out
}

// network: ipaddress.ip_network(v, strict=False) of an address, CIDR or URL host.
func network(value string) (netip.Prefix, bool) {
	v := pyfmt.Strip(value)
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			v = u.Hostname()
		}
	}
	addr, bits, hasBits := strings.Cut(v, "/")
	a, err := netip.ParseAddr(addr)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	n := a.BitLen()
	if hasBits {
		if m, err := netip.ParseAddr(bits); err == nil && a.Is4() && m.Is4() { // 10.0.0.0/255.0.0.0
			ones, ok := maskLen(m)
			if !ok {
				return netip.Prefix{}, false
			}
			n = ones
		} else if !pyfmt.IsDigit(bits) {
			return netip.Prefix{}, false
		} else if n, err = strconv.Atoi(bits); err != nil || n > a.BitLen() {
			return netip.Prefix{}, false
		}
	}
	return netip.PrefixFrom(a, n).Masked(), true
}

// maskLen: prefix length of a netmask (255.255.255.0) or, as ipaddress also accepts, a hostmask (0.0.0.255).
func maskLen(m netip.Addr) (int, bool) {
	b := m.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	for _, x := range []uint32{v, ^v} {
		ones := bits.LeadingZeros32(^x)
		if x<<ones == 0 || ones == 32 {
			return ones, true
		}
	}
	return 0, false
}

type sock struct {
	proto, addr string
	port        int
	process     string
	public      bool
	localOnly   bool
}

var reProc = regexp.MustCompile(`users:\(\("([^"]+)"`)

func listen(text string) []*sock {
	var out []*sock
	seen := map[[3]string]bool{}
	for _, ln := range pyfmt.SplitLines(text) {
		p := pyfmt.Fields(ln)
		if len(p) < 5 {
			continue
		}
		proto, local := p[0], p[4]
		addr, port := "", local
		if i := strings.LastIndex(local, ":"); i >= 0 {
			addr, port = local[:i], local[i+1:]
		}
		addr = strings.Split(strings.Trim(addr, "[]"), "%")[0]
		proc := ""
		if m := reProc.FindStringSubmatch(ln); m != nil {
			proc = m[1]
		}
		if pyfmt.IsDigit(port) {
			n, _ := pyfmt.Int(port)
			// dedupe (v4/v6 duplicates of the same socket stay; same addr:port:proto collapses)
			k := [3]string{proto, addr, strconv.Itoa(n)}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, &sock{proto: proto, addr: addr, port: n, process: proc})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.port != b.port {
			return a.port < b.port
		}
		if a.proto != b.proto {
			return a.proto < b.proto
		}
		return a.addr < b.addr
	})
	return out
}

func ok(text string) bool {
	return pyfmt.Strip(text) != "" && !health.Denied.MatchString(pyfmt.Head(text, 300)) &&
		!strings.Contains(pyfmt.Head(text, 200), "command not found") && !strings.Contains(pyfmt.Head(text, 80), "not found")
}

func fnd(h config.Host, kind, id, severity string, title, detail i18n.Text) finding.Finding {
	return health.Finding(h, "exposure", kind, id, severity, title, detail)
}

var (
	reInputPolicy = pyfmt.Re(`(?m)^-P INPUT (\w+)`)
	reInputRule   = regexp.MustCompile(`(?m)^-A INPUT`)
)

// Run is the module.
func Run(ctx *check.Ctx, h config.Host, cfg map[string]any, out string, facts check.Facts) ([]finding.Finding, error) {
	raw, err := ctx.SSH.Run(ctx, h, "sh -c "+health.Quote(health.Render(Script, h)), 180*time.Second, false)
	if err != nil {
		return nil, err
	}
	f, data, summary := analyze(h, ctx.Org, raw)
	if err := pyfmt.WriteJSON(filepath.Join(out, "exposure.json"), data, false); err != nil {
		return nil, err
	}
	ctx.Log("%s", h.Name+": exposure: "+summary)
	return f, nil
}

func analyze(h config.Host, org *config.Org, raw string) ([]finding.Finding, pyfmt.Obj, string) {
	s := health.Sections(raw)
	var f []finding.Finding

	// addresses
	type address struct {
		iface, ip string
		public    bool
	}
	var addrs []address
	for _, ln := range pyfmt.SplitLines(s["addrs"]) {
		p := pyfmt.Fields(ln)
		if len(p) == 3 && (p[1] == "inet" || p[1] == "inet6") {
			ip := strings.SplitN(p[2], "/", 2)[0]
			addrs = append(addrs, address{p[0], ip, IsPublic(ip)})
		}
	}
	known := knownNets(org)
	var public, unlisted []address
	for _, a := range addrs {
		if a.public {
			public = append(public, a)
		}
	}
	for _, a := range public {
		if a.ip == h.Address {
			continue
		}
		ip := netip.MustParseAddr(a.ip).WithZone("")
		listed := false
		for _, n := range known {
			if n.Addr().Is4() == ip.Is4() && n.Contains(ip) {
				listed = true
				break
			}
		}
		if !listed {
			unlisted = append(unlisted, a)
		}
	}
	for _, a := range unlisted {
		f = append(f, fnd(h, finding.Exposure, "public-ip-unlisted", "HIGH",
			i18n.Msg("net.unlisted_ip", map[string]any{"ip": a.ip}),
			i18n.Msg("net.unlisted_ip.detail", map[string]any{"iface": a.iface})))
	}

	// listening sockets
	socks := listen(s["listen"])
	wildcard := map[string]bool{"0.0.0.0": true, "*": true, "::": true, "": true}
	// behind NAT the interface has a private IP, but if we reach the host by a public address (1:1 NAT / floating
	// IP), whatever listens on 0.0.0.0 is reachable from the internet
	hasPublic := len(public) > 0 || IsPublic(h.Address)
	var exposed []*sock
	for _, r := range socks {
		r.public = wildcard[r.addr] && hasPublic || IsPublic(r.addr)
		r.localOnly = strings.HasPrefix(r.addr, "127.") || r.addr == "::1"
		if r.public {
			exposed = append(exposed, r)
		}
	}
	for _, r := range exposed {
		if name, ok := Sensitive[r.port]; ok && name != "" && r.port != 22 {
			sev := "MEDIUM"
			if h.Exposure == 1 {
				sev = "HIGH"
			}
			a := r.addr
			if a == "" {
				a = "*"
			}
			f = append(f, fnd(h, finding.Exposure, fmt.Sprintf("listen-public-%d", r.port), sev,
				i18n.Msg("net.close", map[string]any{"service": name, "port": r.port}),
				i18n.Plain(pyfmt.Strip(fmt.Sprintf("%s %s:%d %s", r.proto, a, r.port, r.process)))))
		}
	}

	// firewall: nil = not seen; firewalld may also be "not running"
	fw := map[string]*string{}
	state := s["firewalld_state"]
	if strings.Contains(state, "running") { // also matches "not running": kept as the Python module had it
		v := s["firewalld"]
		fw["firewalld"] = &v
	} else if strings.Contains(state, "not running") {
		v := "not running"
		fw["firewalld"] = &v
	}
	for _, k := range []string{"nft", "iptables", "ufw"} {
		if ok(s[k]) {
			v := s[k]
			fw[k] = &v
		}
	}
	val := func(k string) string {
		if p := fw[k]; p != nil {
			return *p
		}
		return ""
	}
	ipt := val("iptables")
	var inputPolicy *string
	if m := reInputPolicy.FindStringSubmatch(ipt); m != nil {
		inputPolicy = &m[1]
	}
	dockerChains := strings.Contains(ipt, "DOCKER")
	fwd := val("firewalld")
	anyRules := reInputRule.MatchString(ipt) || strings.Contains(val("nft"), "hook input") ||
		(fwd != "" && fwd != "not running") || strings.Contains(val("ufw"), "Status: active")
	readable := false
	for _, k := range []string{"firewalld", "nft", "iptables", "ufw"} {
		if v := val(k); v != "" && v != "not running" {
			readable = true
		}
	}
	var fwState any
	if p := fw["firewalld"]; p != nil {
		fwState = "running"
		if *p == "not running" {
			fwState = "not running"
		}
	}
	var policyJS, filtering any
	if inputPolicy != nil {
		policyJS = *inputPolicy
	}
	if readable {
		filtering = anyRules
	}
	summary := pyfmt.O("readable", readable, "firewalld", fwState, "ufw_active", strings.Contains(val("ufw"), "Status: active"),
		"iptables_input_policy", policyJS, "docker_rules", dockerChains, "has_input_filtering", filtering)
	if readable && hasPublic && !anyRules && (inputPolicy == nil || *inputPolicy == "ACCEPT") {
		sev := "MEDIUM"
		if h.Exposure == 1 {
			sev = "HIGH"
		}
		pol := "n/a"
		if inputPolicy != nil && *inputPolicy != "" {
			pol = *inputPolicy
		}
		f = append(f, fnd(h, finding.Exposure, "no-firewall", sev, i18n.Msg("net.no_firewall", nil),
			i18n.Plain("iptables INPUT policy: "+pol)))
	}
	if dockerChains && len(exposed) > 0 && fwState == "running" {
		var ports []string
		for _, r := range exposed {
			if r.process == "docker-proxy" || r.process == "" {
				ports = append(ports, strconv.Itoa(r.port))
			}
		}
		f = append(f, fnd(h, finding.Exposure, "docker-bypasses-firewall", "LOW", i18n.Msg("net.docker_bypass", nil),
			i18n.Plain(pyfmt.Head(strings.Join(ports, ", "), 200))))
	}
	denied := []string{}
	if !readable {
		denied = append(denied, "denied.firewall")
	}
	anyProc := false
	for _, r := range socks {
		if r.process != "" {
			anyProc = true
		}
	}
	if len(socks) > 0 && !anyProc {
		denied = append(denied, "denied.procs")
	}
	if len(denied) > 0 {
		f = append(f, fnd(h, finding.Inventory, "exposure-limited", "INFO",
			i18n.Msg("health.limited", map[string]any{"what": strings.Join(denied, ", ")}), i18n.Plain("")))
	}

	addrJS, publicJS, unlistedJS, listenJS := []any{}, []string{}, []string{}, []any{}
	for _, a := range addrs {
		addrJS = append(addrJS, pyfmt.O("iface", a.iface, "ip", a.ip, "public", a.public))
	}
	for _, a := range public {
		publicJS = append(publicJS, a.ip)
	}
	for _, a := range unlisted {
		unlistedJS = append(unlistedJS, a.ip)
	}
	for _, r := range socks {
		listenJS = append(listenJS, pyfmt.O("proto", r.proto, "addr", r.addr, "port", r.port, "process", r.process,
			"public", r.public, "local_only", r.localOnly))
	}
	rawFW := pyfmt.Obj{}
	for _, k := range []string{"firewalld", "nft", "iptables", "ufw"} {
		var v any
		if p := fw[k]; p != nil {
			v = pyfmt.Head(*p, 20000)
		}
		rawFW = append(rawFW, pyfmt.KV{K: k, V: v})
	}
	data := pyfmt.O("addresses", addrJS, "public", publicJS, "unlisted_public", unlistedJS,
		"default_route", pyfmt.Strip(s["routes"]), "listen", listenJS, "firewall", summary, "firewall_raw", rawFW,
		"denied", denied)
	pub := strings.Join(publicJS, ", ")
	if pub == "" {
		pub = "none"
	}
	line := fmt.Sprintf("%d listening, %d on public addresses, public IPs: %s", len(socks), len(exposed), pub)
	if len(denied) > 0 {
		line += "; no access to " + strings.Join(denied, ", ")
	}
	return f, data, line
}
