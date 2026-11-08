package remediate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/report"
)

// Parity with the former Python reference implementation. testdata/fixture holds a synthetic home (orgs/,
// current/ views) and the goldens recorded from the Python reference over it with the clock pinned; they are frozen
// fixtures now (the generator went away with the Python code).

// Clock is the clock the goldens were recorded with.
var Clock = time.Date(2026, 11, 2, 12, 34, 56, 0, time.Local)

// gcase is one entry of golden/cases.json.
type gcase struct {
	Org              string          `json:"org"`
	Env              string          `json:"env"`
	IDs              []string        `json:"ids"`
	Lang             string          `json:"lang"`
	Plan             json.RawMessage `json:"plan"`
	Markdown         string          `json:"markdown"`
	MarkdownInPrompt bool            `json:"markdown_in_prompt"`
	Prompt           string          `json:"prompt"`
}

func TestMain(m *testing.M) {
	Now = func() time.Time { return Clock }
	os.Exit(m.Run())
}

func TestRecipesParity(t *testing.T) {
	var raw map[string]json.RawMessage
	readJSON(t, "testdata/fixture/golden/recipes.json", &raw)
	gold := map[string]map[string]json.RawMessage{}
	for k, v := range raw {
		var m map[string]json.RawMessage
		if json.Unmarshal(v, &m) == nil {
			gold[k] = m
		}
	}
	pk := []string{"openssl", "bash", "openssl", "libstdc++6", "lib'quote", "a b", ""}
	for os, want := range gold["family"] {
		var w string
		_ = json.Unmarshal(want, &w)
		if got := Family(os); got != w {
			t.Errorf("Family(%q) = %q, want %q", os, got, w)
		}
	}
	for _, fam := range []string{"apt", "yum", "dnf", "unknown"} {
		got := map[string]Recipe{
			"ssh_password": SSHHardening(fam, true, false), "ssh_root": SSHHardening(fam, false, true),
			"ssh_both": SSHHardening(fam, true, true), "kernel": Kernel(fam), "reboot": Reboot(fam),
			"os": OSPackages(fam, pk), "ntp": NTP(fam), "old_kernels": OldKernels(fam),
			"vendor_check": VendorCheck(fam, []string{"rsync", "cups", "rsync"}), "vendor_users": VendorUsers(fam, pk),
		}
		sameRecipes(t, fam, gold[fam], got)
	}
	sameRecipes(t, "any", gold["any"], map[string]Recipe{"rpcbind": Rpcbind(), "port_tcp_docker": RestrictPort(8080, "tcp", true),
		"port_udp_input": RestrictPort(9100, "udp", false),
		"disable":        DisableUnits([]string{"rsyncd.socket", "rsyncd.service"}, "rsync / rsync-daemon")})
	rows := []report.PlanRow{{Host: "b", Pkg: "z", CVEs: 3, CVETop: []string{"CVE-3", "CVE-2", "CVE-1", "CVE-0"}, Fixed: "1.2"},
		{Host: "a", Pkg: "y", CVEs: 1, CVETop: []string{"CVE-9"}}, {Host: "b", Pkg: "a", CVEs: 2, CVETop: []string{}, Fixed: "2"}}
	var w string
	_ = json.Unmarshal(raw["exception_yaml"], &w)
	if got := ExceptionYAML(rows, "Alice Smith", "2026-12-01"); got != w {
		t.Errorf("ExceptionYAML:\n%s\nwant\n%s", got, w)
	}
}

func sameRecipes(t *testing.T, fam string, gold map[string]json.RawMessage, got map[string]Recipe) {
	t.Helper()
	for name, g := range got {
		var w struct {
			Apply, Verify, Rollback string
			Reversible              bool
			Note                    [2]json.RawMessage
		}
		if err := json.Unmarshal(gold[name], &w); err != nil {
			t.Fatalf("%s/%s: %v", fam, name, err)
		}
		var key string
		var args map[string]any
		_ = json.Unmarshal(w.Note[0], &key)
		_ = json.Unmarshal(w.Note[1], &args)
		ga := map[string]any{}
		for k, v := range g.NoteArgs {
			ga[k] = v
			if n, ok := v.(int); ok {
				ga[k] = float64(n)
			}
		}
		for _, d := range []struct{ what, got, want string }{{"apply", g.Apply, w.Apply}, {"verify", g.Verify, w.Verify},
			{"rollback", g.Rollback, w.Rollback}, {"note", g.Note, key}} {
			if d.got != d.want {
				t.Errorf("%s/%s %s:\n%s\nwant\n%s", fam, name, d.what, d.got, d.want)
			}
		}
		if g.Reversible != w.Reversible || !reflect.DeepEqual(ga, args) {
			t.Errorf("%s/%s: reversible %v args %v, want %v %v", fam, name, g.Reversible, ga, w.Reversible, args)
		}
	}
}

func TestFixtureParity(t *testing.T) { checkCases(t, "testdata/fixture") }

func checkPlan(t *testing.T, org *config.Org, v *report.View, c gcase) {
	p := BuildPlan(org, c.Env, v, c.IDs, c.Lang)
	got, _ := json.Marshal(p)
	var g, w any
	_ = json.Unmarshal(got, &g)
	_ = json.Unmarshal(c.Plan, &w)
	if !reflect.DeepEqual(g, w) {
		t.Errorf("plan:\n%s\nwant\n%s", got, c.Plan)
	}
	md := RenderMarkdown(p, c.Lang)
	if c.MarkdownInPrompt {
		if !strings.Contains(c.Prompt, md) || md == "" {
			t.Errorf("markdown not in the golden prompt:\n%s", md)
		}
	} else if md != c.Markdown {
		t.Errorf("markdown:\n%s\nwant\n%s", md, c.Markdown)
	}
}

// checkCases runs checkPlan for every case of <root>/golden/cases.json against <root>/home.
func checkCases(t *testing.T, root string) {
	var cases []gcase
	readJSON(t, filepath.Join(root, "golden", "cases.json"), &cases)
	p := config.PathsAt(filepath.Join(root, "home"))
	l, err := config.NewLoader(p)
	if err != nil {
		t.Fatal(err)
	}
	orgs, errs := l.LoadAll()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	views := map[string]*report.View{}
	for _, c := range cases {
		var org *config.Org
		for _, o := range orgs {
			if o.ID == c.Org {
				org = o
			}
		}
		key := c.Org + "/" + c.Env
		if views[key] == nil {
			views[key] = loadView(t, filepath.Join(report.EnvDir(p, c.Org, c.Env), report.Current, "view.json"))
		}
		name := key + "/" + c.Lang + "/" + strings.Join(c.IDs[:min(3, len(c.IDs))], ",")
		if len(c.IDs) > 3 {
			name += ",…"
		}
		t.Run(name, func(t *testing.T) { checkPlan(t, org, views[key], c) })
	}
}

// loadView decodes a view.json as the servers do (numbers kept as written).
func loadView(t testing.TB, path string) *report.View {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v report.View
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func readJSON(t testing.TB, path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

// TestVendorFixPlan is test_vendor_fix_plan of the Python suite.
func TestVendorFixPlan(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "orgs"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../orgs/_example.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "orgs", "acme.yml"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := config.NewLoader(config.PathsAt(home))
	if err != nil {
		t.Fatal(err)
	}
	orgs, errs := l.LoadAll()
	if len(errs) > 0 || len(orgs) != 1 {
		t.Fatal(errs)
	}
	acme := orgs[0]
	f := func(id, pkg, prio, state, repo string) finding.Finding {
		x := finding.Finding{Org: "acme", Host: "web-01", Module: "os_packages", Kind: "vuln", ID: id, Pkg: pkg, Installed: "1",
			Fixed: "2", Severity: "HIGH", Exposure: 1, Target: "os", Priority: &prio, FixState: state}
		if repo != "" {
			x.RepoVersion = repo
		}
		return x
	}
	fs := []finding.Finding{f("CVE-V", "rsync", "P1", "vendor", ""), f("CVE-UP", "openssl", "P2", "available", "3.5.9")}
	osName := "CentOS Stream 9"
	facts := map[string]report.Fact{"web-01": {OS: &osName}}
	rows := report.PlanRows(report.PatchPlan(fs))
	v := &report.View{Plan: rows, Actions: report.BuildActions(rows, nil, facts), Facts: facts}
	var ids []string
	for _, a := range v.Actions {
		ids = append(ids, a.ID)
	}
	plan := BuildPlan(acme, acme.Hosts[0].Env, v, ids, "en")
	var rsyncNote, osStep, unitStep bool
	for _, s := range plan.Steps {
		rsyncNote = rsyncNote || strings.Contains(s.Note, "rsync") // rsyncd mitigation step
		if strings.Contains(s.Apply, "upgrade") && !osStep {
			osStep = true
			if !strings.Contains(s.Apply, "openssl") || strings.Contains(s.Apply, "rsync") { // nothing to install for rsync
				t.Errorf("os step: %s", s.Apply)
			}
		}
		if strings.Contains(s.Apply, "rsyncd") && !unitStep {
			unitStep = true
			if !strings.Contains(s.Apply, `tr '\n' ' '`) {
				t.Errorf("unit step: %s", s.Apply)
			}
		}
	}
	y := plan.ExceptionsYAML
	if !rsyncNote || !osStep || !unitStep {
		t.Errorf("steps: %+v", plan.Steps)
	}
	if !strings.Contains(y, "until_available: true") || !strings.Contains(y, "package: rsync") ||
		strings.Count(y, "- id:") != 1 { // one entry per package and host, not per CVE
		t.Errorf("exceptions:\n%s", y)
	}
	if !strings.Contains(RenderMarkdown(plan, "en"), "```yaml") {
		t.Error("no yaml block in the markdown")
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{"": "''", "openssl": "openssl", "libstdc++6": "libstdc++6", "a b": "'a b'",
		"it's": `'it'"'"'s'`, "pkg:amd64": "pkg:amd64", "x$y": "'x$y'", "ü": "'ü'"} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}

// A socket without a process is docker-proxy unless the kernel owns the port (VXLAN): then INPUT, not DOCKER-USER.
func TestClosePortChain(t *testing.T) {
	for _, c := range []struct {
		port      int
		proto     string
		process   string
		wantChain string
	}{
		{4789, "udp", "", "INPUT"},
		{8080, "tcp", "", "DOCKER-USER"},
		{443, "tcp", "docker-proxy", "DOCKER-USER"},
		{9100, "tcp", "node_exporter", "INPUT"},
	} {
		v := &report.View{Exposure: map[string]any{"h": map[string]any{"listen": []any{
			map[string]any{"port": float64(c.port), "proto": c.proto, "process": c.process, "public": true}}}}}
		rs, manual := closePort(&report.Action{Args: map[string]any{"port": float64(c.port)}}, "h", v)
		if manual != "" || len(rs) != 1 {
			t.Fatalf("%s/%d: manual %q, %d recipes", c.proto, c.port, manual, len(rs))
		}
		if got := rs[0].NoteArgs["chain"]; got != c.wantChain {
			t.Errorf("%s/%d (%q): chain %v, want %s", c.proto, c.port, c.process, got, c.wantChain)
		}
	}
}
