package ipinfo

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
)

// A minimal MaxMind DB writer (format 2.0, IPv4 tree, 24-bit records): every address resolves to one record.
// Enough to drive the lookups without shipping a real DB-IP file; maxminddb-golang has no writer.

type mmUint struct {
	typ  int // 5 uint16, 6 uint32, 9 uint64
	v    uint64
	size int
}

func ctrl(typ, size int) []byte {
	var ext []byte
	if size >= 29 { // 29..284: the rest of the size in one more byte
		if size > 284 {
			panic("mmdb test writer: sizes up to 284 only")
		}
		size, ext = 29, []byte{byte(size - 29)}
	}
	if typ <= 7 {
		return append([]byte{byte(typ<<5 | size)}, ext...)
	}
	return append([]byte{byte(size), byte(typ - 7)}, ext...)
}

func mmEncode(v any) []byte {
	switch t := v.(type) {
	case string:
		return append(ctrl(2, len(t)), t...)
	case mmUint:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, t.v)
		b = b[8-t.size:]
		return append(ctrl(t.typ, t.size), b...)
	case []any:
		out := ctrl(11, len(t))
		for _, x := range t {
			out = append(out, mmEncode(x)...)
		}
		return out
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := ctrl(7, len(t))
		for _, k := range keys {
			out = append(out, mmEncode(k)...)
			out = append(out, mmEncode(t[k])...)
		}
		return out
	}
	panic(fmt.Sprintf("mmdb test writer: %T", v))
}

func writeMMDB(t *testing.T, path, dbType string, record map[string]any) {
	t.Helper()
	const nodes = 1
	ptr := uint32(nodes + 16) // data section offset 0
	tree := []byte{byte(ptr >> 16), byte(ptr >> 8), byte(ptr), byte(ptr >> 16), byte(ptr >> 8), byte(ptr)}
	b := make([]byte, 0, len(tree)+16)
	b = append(b, tree...)
	b = append(b, make([]byte, 16)...)
	b = append(b, mmEncode(record)...)
	b = append(b, "\xab\xcd\xefMaxMind.com"...)
	b = append(b, mmEncode(map[string]any{
		"node_count":                  mmUint{6, nodes, 4},
		"record_size":                 mmUint{5, 24, 2},
		"ip_version":                  mmUint{5, 4, 2},
		"database_type":               dbType,
		"languages":                   []any{"en", "ru"},
		"binary_format_major_version": mmUint{5, 2, 2},
		"binary_format_minor_version": mmUint{5, 0, 0},
		"build_epoch":                 mmUint{9, 1767225600, 8},
		"description":                 map[string]any{"en": "kanareika test database"},
	})...)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// With both databases present, a global address gets country, city and ASN; names prefer Russian.
// 233.252.0.0/24 is MCAST-TEST-NET (RFC 5771): documentation, yet global in Python's sense.
func TestLookupWithDatabases(t *testing.T) {
	dir := t.TempDir()
	writeMMDB(t, filepath.Join(dir, "dbip-city.mmdb"), "DBIP-City-Lite", map[string]any{
		"country": map[string]any{"iso_code": "ZZ", "names": map[string]any{"en": "Testland", "ru": "Тестландия"}},
		"city":    map[string]any{"names": map[string]any{"en": "Example City"}},
	})
	writeMMDB(t, filepath.Join(dir, "dbip-asn.mmdb"), "DBIP-ASN-Lite", map[string]any{
		"autonomous_system_number":       mmUint{6, 64496, 4},
		"autonomous_system_organization": "ACME-NET",
	})
	t.Setenv("KANAREIKA_FEEDS_DIR", dir)
	Reload()
	t.Cleanup(Reload)
	got := Lookup([]string{"233.252.0.10", "192.0.2.10"}, nil)
	want := map[string]string{
		"233.252.0.10": `{"asn":64496,"cc":"ZZ","city":"Example City","country":"Тестландия","org":"ACME-NET"}`,
		"192.0.2.10":   `{"scope":"private"}`,
		"_db":          `{"available":true}`,
	}
	for k, w := range want {
		if g := mustJSON(got[k]); g != w {
			t.Errorf("%s: %s, want %s", k, g, w)
		}
	}
}

func TestLookupCapsTheList(t *testing.T) {
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir())
	Reload()
	t.Cleanup(Reload)
	ips := make([]string, MaxIPs+1)
	for i := range ips {
		ips[i] = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)}).String()
	}
	got := Lookup(ips, []*config.Org{})
	if len(got) != MaxIPs+1 { // MaxIPs addresses and "_db"
		t.Fatalf("%d entries", len(got))
	}
	if _, ok := got[ips[MaxIPs]]; ok {
		t.Error("address past MaxIPs looked up")
	}
	if _, ok := got[ips[MaxIPs-1]]; !ok {
		t.Error("last address within MaxIPs missing")
	}
}

// IPv6 networks take a prefix length only, never a netmask.
func TestIPv6Netmask(t *testing.T) {
	if p, ok := parseNetwork("2001:db8::/ffff:ffff::"); ok {
		t.Fatalf("parsed as %s", p)
	}
	if p, ok := parseNetwork("2001:db8::1/32"); !ok || p.String() != "2001:db8::/32" {
		t.Fatalf("%s %v", p, ok)
	}
}
