package remediate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/report"
)

func TestRouteWithoutJumps(t *testing.T) {
	org := &config.Org{ID: "acme", Data: map[string]any{}}
	h := &config.Host{Name: "web-01", User: "audit", Address: "192.0.2.10", Port: 22}
	if got := Route(org, h); got != "ssh audit@192.0.2.10" {
		t.Fatalf("Route = %q", got)
	}
}

func TestStepsForNothingToInstall(t *testing.T) {
	vendor := "vendor"
	v := &report.View{Plan: []report.PlanRow{
		{Host: "web-01", Target: "os", Pkg: "rsync", Fixed: "2", FixState: &vendor}, // no fix in the repositories
		{Host: "web-01", Target: "os", Pkg: "linux-image", Fixed: "2", Kernel: true},
		{Host: "web-02", Target: "os", Pkg: "openssl", Fixed: "2"},
	}}
	for _, cat := range []string{"os", "vendor"} {
		host := "web-01"
		if cat == "vendor" {
			host = "web-02" // web-02 has only a fixable row, nothing waiting for the vendor
		}
		r, why := StepsFor(&report.Action{Cat: cat}, host, v)
		if r != nil || why != "manual.no_fixed" {
			t.Errorf("%s: %v %q", cat, r, why)
		}
	}
}

func TestClosePortFromTitle(t *testing.T) {
	v := &report.View{}
	r, why := StepsFor(&report.Action{Cat: "exposure", Msg: "net.close", Title: "Close port :8080"}, "web-01", v)
	if why != "" || len(r) != 1 || !strings.Contains(r[0].Apply, "8080") {
		t.Fatalf("title port: %+v %q", r, why)
	}
	// json.Number, int and float64 ports are read too
	for _, p := range []any{json.Number("8443"), 8443, 8443.0} {
		r, why = StepsFor(&report.Action{Cat: "exposure", Msg: "net.close", Args: map[string]any{"port": p}}, "web-01", v)
		if why != "" || len(r) != 1 || !strings.Contains(r[0].Apply, "8443") {
			t.Errorf("port %T: %+v %q", p, r, why)
		}
	}
	r, why = StepsFor(&report.Action{Cat: "exposure", Msg: "net.close", Title: "Close an open port",
		Args: map[string]any{"port": "8080"}}, "web-01", v)
	if r != nil || why != "manual.none" {
		t.Fatalf("no port anywhere: %+v %q", r, why)
	}
}

func TestBuildPlanUnknownHostDefaultOwnerAndLang(t *testing.T) {
	org := &config.Org{ID: "acme", Data: map[string]any{"org": map[string]any{
		"contacts": []any{map[string]any{"email": "ops@example.com"}}}}, // no named contact
		Hosts: []config.Host{{Name: "web-01", Env: "production", User: "audit", Address: "192.0.2.10", Port: 22}}}
	vendor := "vendor"
	osName := "Debian GNU/Linux 12 (bookworm)"
	v := &report.View{
		Facts: map[string]report.Fact{"web-01": {OS: &osName}},
		Plan: []report.PlanRow{{Host: "web-01", Target: "os", Pkg: "rsync", Fixed: "2", FixState: &vendor,
			CVEs: 1, CVETop: []string{"CVE-2099-0001"}}},
		Actions: []report.Action{{ID: "a1", Cat: "vendor", Title: "rsync: no fix yet", Hosts: []string{"web-01", "db-09"}}},
	}
	p := BuildPlan(org, "production", v, []string{"a1"}, "en")
	for _, s := range p.Steps {
		if s.Host != "web-01" {
			t.Errorf("step for a host outside the org: %+v", s)
		}
	}
	for _, m := range p.Manual {
		if m.Host != "web-01" {
			t.Errorf("manual entry for a host outside the org: %+v", m)
		}
	}
	if len(p.Steps) == 0 || !strings.Contains(p.ExceptionsYAML, `owner: "owner"`) {
		t.Fatalf("plan: %+v", p)
	}
	md := RenderMarkdown(p, "xx")
	if md != RenderMarkdown(p, "en") {
		t.Error("unknown lang must render in the default language")
	}
	if !strings.Contains(md, "### 1. [-] rsync: no fix yet — web-01") {
		t.Errorf("a step without priority must show [-]:\n%s", md)
	}
}
