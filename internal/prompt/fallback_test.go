package prompt

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/report"
)

// An unknown language falls back to the default texts; a category outside Recheck rechecks os_packages.
func TestUnknownLangAndCategory(t *testing.T) {
	p := config.PathsAt(filepath.Join(fixture, "home"))
	l, err := config.NewLoader(p)
	if err != nil {
		t.Fatal(err)
	}
	orgs, errs := l.LoadAll()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	var org *config.Org
	for _, o := range orgs {
		if o.ID == "acme" {
			org = o
		}
	}
	if org == nil {
		t.Fatal("no org acme in the fixture")
	}
	view := loadView(t, filepath.Join(report.EnvDir(p, "acme", "production"), report.Current, "view.json"))
	if len(view.Actions) == 0 {
		t.Fatal("fixture view has no actions")
	}
	view.Actions = view.Actions[:1]
	view.Actions[0].Cat = "mystery"
	ids := []string{view.Actions[0].ID}

	got := Build(org, "production", view, ids, "xx")
	if got == "" {
		t.Fatal("empty prompt")
	}
	if want := Build(org, "production", view, ids, i18n.Default); got != want {
		t.Errorf("unknown lang must render as %q:\n%s\nwant\n%s", i18n.Default, got, want)
	}
	if !strings.Contains(got, "--module os_packages") || strings.Count(got, "--module ") != 1 {
		t.Errorf("an unknown category must recheck os_packages only:\n%s", got)
	}
}
