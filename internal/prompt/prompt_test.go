package prompt

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/remediate"
	"github.com/mikekosulin/kanareika/internal/report"
)

// Parity with prompt.build of the former Python reference, over the frozen goldens of package remediate (recorded
// from the Python reference over its synthetic fixture): the same selections, the same pinned clock.

const fixture = "../remediate/testdata/fixture"

func TestMain(m *testing.M) {
	remediate.Now = func() time.Time { return time.Date(2026, 11, 2, 12, 34, 56, 0, time.Local) }
	os.Exit(m.Run())
}

func TestFixtureParity(t *testing.T) { checkCases(t, fixture) }

func checkCases(t *testing.T, root string) {
	b, err := os.ReadFile(filepath.Join(root, "golden", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Org, Env, Lang, Prompt string
		IDs                    []string
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	p := config.PathsAt(filepath.Join(root, "home"))
	l, err := config.NewLoader(p)
	if err != nil {
		t.Fatal(err)
	}
	orgs, errs := l.LoadAll()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	byID := map[string]*config.Org{}
	for _, o := range orgs {
		byID[o.ID] = o
	}
	views := map[string]*report.View{}
	for _, c := range cases {
		key := c.Org + "/" + c.Env
		if views[key] == nil {
			views[key] = loadView(t, filepath.Join(report.EnvDir(p, c.Org, c.Env), report.Current, "view.json"))
		}
		name := key + "/" + c.Lang + "/" + strings.Join(c.IDs[:min(3, len(c.IDs))], ",")
		t.Run(name, func(t *testing.T) {
			if got := Build(byID[c.Org], c.Env, views[key], c.IDs, c.Lang); got != c.Prompt {
				t.Errorf("prompt:\n%s\nwant\n%s", got, c.Prompt)
			}
		})
	}
}

func loadView(t *testing.T, path string) *report.View {
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

func TestRoute(t *testing.T) {
	org := &config.Org{Data: map[string]any{"access": map[string]any{"user": "audit", "jumps": map[string]any{
		"outer": map[string]any{"address": "203.0.113.5", "port": 2222.0},
		"inner": map[string]any{"address": "192.0.2.5", "jump": "outer", "user": "jumper", "port": 22.0}}}}}
	for _, c := range []struct {
		h    config.Host
		want string
	}{
		{config.Host{User: "audit", Address: "192.0.2.1", Port: 22}, "ssh audit@192.0.2.1"},
		{config.Host{User: "root", Address: "192.0.2.1", Port: 2200, Jump: "outer"}, "ssh -J audit@203.0.113.5:2222 root@192.0.2.1 -p 2200"},
		{config.Host{User: "audit", Address: "192.0.2.1", Port: 22, Jump: "inner"}, "ssh -J audit@203.0.113.5:2222,jumper@192.0.2.5 audit@192.0.2.1"},
	} {
		if got := Route(org, &c.h); got != c.want {
			t.Errorf("Route = %q, want %q", got, c.want)
		}
	}
}
