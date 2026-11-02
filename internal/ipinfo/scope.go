package ipinfo

import "net/netip"

// The special-purpose tables of Python 3.13's ipaddress (IANA registries), so "private" / "special" / public
// come out as the Python dashboard showed them. Go's netip.IsPrivate covers only RFC 1918 / ULA.
var (
	private4 = prefixes("0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
		"192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"240.0.0.0/4", "255.255.255.255/32")
	private4Except = prefixes("192.0.0.9/32", "192.0.0.10/32")
	shared4        = netip.MustParsePrefix("100.64.0.0/10") // carrier-grade NAT: neither private nor global
	private6       = prefixes("::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10")
	private6Except = prefixes("2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48", "2001:20::/28",
		"2001:30::/28")
)

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsPrivate is Python's ip_address(a).is_private; IPv4-mapped IPv6 addresses follow their IPv4 address.
func IsPrivate(a netip.Addr) bool {
	a = a.WithZone("")
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Is4() {
		return inAny(a, private4) && !inAny(a, private4Except)
	}
	return inAny(a, private6) && !inAny(a, private6Except)
}

// IsGlobal is Python's is_global: not private, and for IPv4 also not in 100.64.0.0/10. Multicast counts as
// global there, and so here.
func IsGlobal(a netip.Addr) bool {
	a = a.WithZone("")
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Is4() && shared4.Contains(a) {
		return false
	}
	return !IsPrivate(a)
}
