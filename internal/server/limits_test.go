package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
)

func TestScanLimitsAPI(t *testing.T) {
	f := &fakeScan{release: make(chan struct{})}
	s, h := newTest(t, Options{Scan: f.run})
	limits := func() config.Limits {
		r := do(h, "GET", "/api/scan-options?org=acme&env=production", nil, nil)
		var d struct{ Limits config.Limits }
		must(t, json.Unmarshal([]byte(r.body), &d))
		return d.Limits
	}
	if l := limits(); l.Parallel != (config.Limit{Value: 8, Source: "default"}) || l.TrivyParallel.Value != 2 {
		t.Fatalf("defaults %+v", l)
	}
	r := do(h, "POST", "/api/settings/scan", map[string]int{"parallel": 12, "trivy_parallel": 3}, s.postHdr())
	if r.code != 200 {
		t.Fatal(r.code, r.body)
	}
	if l := limits(); l.Parallel != (config.Limit{Value: 12, Source: "settings"}) || l.TrivyParallel.Value != 3 {
		t.Fatalf("after POST %+v", l)
	}
	b, err := os.ReadFile(filepath.Join(s.paths.Policy, "settings.yml"))
	must(t, err)
	if !strings.Contains(string(b), "retention:") || !strings.Contains(string(b), "parallel: 12") {
		t.Fatalf("settings.yml:\n%s", b)
	}
	for _, bad := range []any{map[string]int{"parallel": 65}, map[string]int{"trivy_parallel": -1}, map[string]int{"x": 1}} {
		if r := do(h, "POST", "/api/settings/scan", bad, s.postHdr()); r.code != 400 {
			t.Errorf("%v: %d", bad, r.code)
		}
	}
	if r := do(h, "POST", "/api/settings/scan", map[string]int{"parallel": 1}, nil); r.code < 400 {
		t.Fatalf("no CSRF token: %d", r.code)
	}
	_, ro := newTest(t, Options{})
	if r := do(ro, "POST", "/api/settings/scan", map[string]int{"parallel": 1}, s.postHdr()); r.code != 403 {
		t.Fatalf("scans off: %d", r.code)
	}
}
