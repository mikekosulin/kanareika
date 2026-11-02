package ipinfo

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
)

// testdata/python_ipaddress.json: is_global / is_private and ip_network(strict=False) as Python 3.13 computes them
// for special-purpose, documentation and anonymized addresses. Recorded once with the former Python implementation
// (removed from the repo; the Go port had to match it) and kept as a frozen fixture: a change here is a behaviour
// change — review it as such.
func TestPythonParity(t *testing.T) {
	b, err := os.ReadFile("testdata/python_ipaddress.json")
	if err != nil {
		t.Fatal(err)
	}
	var want struct {
		IPs  map[string]struct{ Global, Private bool }
		Nets map[string]*string
	}
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	for ip, w := range want.IPs {
		a := netip.MustParseAddr(ip)
		if g, p := IsGlobal(a), IsPrivate(a); g != w.Global || p != w.Private {
			t.Errorf("%s: global=%v private=%v, Python %v %v", ip, g, p, w.Global, w.Private)
		}
	}
	for in, w := range want.Nets {
		p, ok := parseNetwork(in)
		switch {
		case w == nil && ok:
			t.Errorf("%s: parsed as %s, Python rejects it", in, p)
		case w != nil && !ok:
			t.Errorf("%s: rejected, Python %s", in, *w)
		case w != nil && in == "fe80::1%eth0":
			if p.String() != "fe80::1/128" {
				t.Errorf("%s: %s", in, p)
			}
		case w != nil && p.String() != *w:
			t.Errorf("%s: %s, Python %s", in, p, *w)
		}
	}
}

func TestLookupOurs(t *testing.T) {
	o := &config.Org{ID: "acme",
		Hosts: []config.Host{{Name: "web", Env: "prod", Address: "203.0.113.5"}, {Name: "db", Env: "prod", Address: "10.0.0.5"}},
		Data: map[string]any{
			"access":   map[string]any{"jumps": map[string]any{"bastion": map[string]any{"address": "203.0.113.9"}, "same": map[string]any{"address": "10.0.0.5"}}},
			"external": map[string]any{"prod": []any{"198.51.100.0/24", "example.com"}},
		}}
	t.Setenv("KANAREIKA_FEEDS_DIR", t.TempDir()) // no databases: only "ours" and scope
	Reload()
	got := Lookup([]string{"203.0.113.5", "10.0.0.5", "203.0.113.9", "198.51.100.7", "100.64.0.1", "x", "8.8.8.8"}, []*config.Org{o})
	want := map[string]map[string]any{
		"203.0.113.5":  {"ours": "acme/web", "scope": "private"},
		"10.0.0.5":     {"ours": "acme/db", "scope": "private"},
		"203.0.113.9":  {"ours": "acme/jump bastion", "scope": "private"},
		"198.51.100.7": {"ours": "acme/external", "scope": "private"},
		"100.64.0.1":   {"scope": "special"},
		"8.8.8.8":      {},
	}
	for ip, w := range want {
		g, _ := got[ip].(map[string]any)
		if gb, wb := mustJSON(g), mustJSON(w); gb != wb {
			t.Errorf("%s: %s, want %s", ip, gb, wb)
		}
	}
	if _, ok := got["x"]; ok {
		t.Error("unparseable address listed")
	}
	if db := mustJSON(got["_db"]); db != `{"available":false}` {
		t.Errorf("_db: %s", db)
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
