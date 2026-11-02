package k8s

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/check/checktest"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
)

// testdata/python.json: recorded with the former Python run_k8s over a synthetic `trivy k8s --report all` report
// (k8s-prod.json.gz: namespaced and cluster-scoped resources, null/absent names and results; vulnerabilities from a
// real Ubuntu scan) and clusters across environments with missing, non-file, escaping kubeconfigs and failing trivy.
// A frozen fixture: a change here is a behaviour change — review it as such.
func TestMatchesPython(t *testing.T) {
	b, err := os.ReadFile("testdata/python.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Clusters []map[string]any  `json:"clusters"`
		Secrets  map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	cases := checktest.LoadReplays(t)
	set := func(f checktest.TrivyFunc) func() { old := trivyRun; trivyRun = f; return func() { trivyRun = old } }
	for i := range cases {
		c := &cases[i]
		t.Run(c.Name, func(t *testing.T) {
			org, secrets := loadOrg(t, g.Clusters, g.Secrets)
			checktest.RunReplay(t, c, org, set, func(ctx *check.Ctx, r checktest.ReplayRun, out string) ([]finding.Finding, error) {
				return Run(ctx, r.Cfg, r.Env)
			}, [2]string{secrets, "$SECRETS"})
		})
	}
}

// loadOrg: the example org with these clusters, loaded the real way, with secrets in a temp dir.
func loadOrg(t *testing.T, clusters []map[string]any, secrets map[string]string) (*config.Org, string) {
	t.Helper()
	root, _ := filepath.Abs("../../..")
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sec := filepath.Join(tmp, "secrets")
	for rel, text := range secrets {
		p := filepath.Join(sec, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src, err := os.ReadFile(filepath.Join(root, "orgs", "_example.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := yaml.Unmarshal(src, &data); err != nil {
		t.Fatal(err)
	}
	data["k8s"] = clusters
	if o, ok := data["org"].(map[string]any); ok {
		o["id"] = "acme"
	}
	out, _ := yaml.Marshal(data)
	orgs := filepath.Join(tmp, "orgs")
	_ = os.MkdirAll(orgs, 0o755)
	path := filepath.Join(orgs, "acme.yml")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := config.NewLoader(config.Paths{Home: root, Orgs: orgs, Policy: filepath.Join(root, "policy"),
		Secrets: sec, Reports: filepath.Join(tmp, "reports")})
	if err != nil {
		t.Fatal(err)
	}
	org, problems := l.LoadOrg(path)
	if org == nil {
		t.Fatal(problems)
	}
	return org, sec
}
