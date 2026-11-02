// Package ipinfo answers "where is this IP and is it one of ours" for the dashboard, offline: DB-IP Lite
// (country/city, ASN) from the feeds directory, and our hosts, jumps and external targets from the org configs.
// Nothing leaves the machine: the dashboard shows peers from firewall rules and connection lists.
package ipinfo

import (
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/priority"
)

// MaxIPs: one request looks up at most this many addresses (the dashboard sends a page's peers at once).
const MaxIPs = 1000

var (
	mu      sync.Mutex
	readers = map[string]*maxminddb.Reader{} // kind -> reader; nil: the file is missing or unreadable
	opened  = map[string]bool{}
)

// reader opens dbip-<kind>.mmdb once; a missing database is remembered too, until Reload (feeds update).
func reader(kind string) *maxminddb.Reader {
	mu.Lock()
	defer mu.Unlock()
	if !opened[kind] {
		r, err := maxminddb.Open(filepath.Join(priority.FeedsDir(), "dbip-"+kind+".mmdb"))
		if err != nil {
			r = nil
		}
		readers[kind], opened[kind] = r, true
	}
	return readers[kind]
}

// Reload forgets the open databases, so the next lookup sees freshly downloaded files. Readers in use by a
// concurrent lookup are not closed (they are memory-mapped; the GC releases them).
func Reload() {
	mu.Lock()
	defer mu.Unlock()
	readers, opened = map[string]*maxminddb.Reader{}, map[string]bool{}
}

type ourNet struct {
	p     netip.Prefix
	label string
}

// ours: exact addresses (hosts win over jumps) and external target networks of every org.
func ours(orgs []*config.Org) (map[string]string, []ourNet) {
	addrs := map[string]string{}
	var nets []ourNet
	for _, o := range orgs {
		for _, h := range o.Hosts {
			addrs[h.Address] = o.ID + "/" + h.Name
		}
		jumps := o.Jumps()
		names := make([]string, 0, len(jumps))
		for n := range jumps {
			names = append(names, n)
		}
		sort.Strings(names) // Python keeps file order; it only matters when two jumps share an address
		for _, n := range names {
			a, _ := jumps[n]["address"].(string)
			if _, ok := addrs[a]; !ok {
				addrs[a] = o.ID + "/jump " + n
			}
		}
		for _, env := range o.Envs() {
			for _, t := range o.External(env) {
				if p, ok := parseNetwork(t); ok {
					nets = append(nets, ourNet{p, o.ID + "/external"})
				}
			}
		}
	}
	return addrs, nets
}

// parseNetwork is Python's ip_network(t, strict=False): an address, addr/len or addr/netmask; host bits are
// dropped. DNS names are not networks.
func parseNetwork(t string) (netip.Prefix, bool) {
	addr, bits, hasBits := strings.Cut(t, "/")
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.WithZone("") // prefixes carry no zone; Python keeps it, but only link-local addresses have one
	n := a.BitLen()
	if hasBits {
		if n = maskBits(a, bits); n < 0 {
			return netip.Prefix{}, false
		}
	}
	p, err := a.Prefix(n)
	return p, err == nil
}

// maskBits: a prefix length in decimal, or (IPv4) a netmask / hostmask; -1 when invalid.
func maskBits(a netip.Addr, s string) int {
	if s != "" && strings.Trim(s, "0123456789") == "" {
		n, err := strconv.Atoi(s)
		if err != nil || n > a.BitLen() {
			return -1
		}
		return n
	}
	if !a.Is4() {
		return -1
	}
	m, err := netip.ParseAddr(s)
	if err != nil || !m.Is4() {
		return -1
	}
	b := m.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	for _, x := range []uint32{v, ^v} { // netmask 255.255.255.0 or hostmask 0.0.0.255
		ones := 0
		for ones < 32 && x&(1<<(31-ones)) != 0 {
			ones++
		}
		if ones == 32 || x<<ones == 0 {
			return ones
		}
	}
	return -1
}

// Lookup: ip -> {ours?, scope (private | special) or cc/country/city/asn/org}, plus "_db": {"available"}.
// Unparseable entries are left out; at most MaxIPs are looked up.
func Lookup(ips []string, orgs []*config.Org) map[string]any {
	addrs, nets := ours(orgs)
	city, asn := reader("city"), reader("asn")
	out := map[string]any{}
	if len(ips) > MaxIPs {
		ips = ips[:MaxIPs]
	}
	for _, ip := range ips {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		bare := a.WithZone("")
		info := map[string]any{}
		if label, ok := addrs[ip]; ok {
			info["ours"] = label
		} else {
			for _, n := range nets {
				if n.p.Contains(bare) {
					info["ours"] = n.label
					break
				}
			}
		}
		if !IsGlobal(bare) {
			if IsPrivate(bare) {
				info["scope"] = "private"
			} else {
				info["scope"] = "special"
			}
		} else {
			if city != nil {
				var r cityRecord
				_ = city.Lookup(bare).Decode(&r)
				info["cc"], info["country"], info["city"] = r.Country.ISOCode, r.Country.Names.name(), r.City.Names.name()
			}
			if asn != nil {
				var r asnRecord
				_ = asn.Lookup(bare).Decode(&r)
				info["asn"], info["org"] = r.Number, r.Org
			}
		}
		out[ip] = info
	}
	out["_db"] = map[string]bool{"available": city != nil || asn != nil}
	return out
}

type names map[string]string

// name: Russian first (the team reads Russian), English otherwise.
func (n names) name() string {
	if s := n["ru"]; s != "" {
		return s
	}
	return n["en"]
}

type cityRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
		Names   names  `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names names `maxminddb:"names"`
	} `maxminddb:"city"`
}

type asnRecord struct {
	Number *uint32 `maxminddb:"autonomous_system_number"` // nil (null) when the database has no record
	Org    string  `maxminddb:"autonomous_system_organization"`
}
