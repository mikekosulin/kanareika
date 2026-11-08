package main

import (
	"cmp"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/internal/i18n"
)

// root: the repository, from this package's directory.
const root = "../.."

// readme: where a language's README is (English at the root, the others in docs/readme/).
func readme(lang string) string {
	if lang == "en" {
		return "README.md"
	}
	return "docs/readme/README." + lang + ".md"
}

// localeNames: every language with a locale file, and its own name ("name" in the file).
func localeNames(t *testing.T) (langs []string, names map[string]string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, "assets/locales/*.json"))
	if err != nil || len(files) < 3 {
		t.Fatal(files, err)
	}
	names = map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var l struct{ Name string }
		if err := json.Unmarshal(b, &l); err != nil || l.Name == "" {
			t.Fatalf("%s: no name (%v)", f, err)
		}
		lang := strings.TrimSuffix(filepath.Base(f), ".json")
		langs = append(langs, lang)
		names[lang] = l.Name
	}
	// in the order of the interfaces' language menus (English first, then by their own names)
	order := i18n.Langs()
	slices.SortFunc(langs, func(a, b string) int { return cmp.Compare(slices.Index(order, a), slices.Index(order, b)) })
	return langs, names
}

// TestReadmes: a README per interface language, each with a switcher to all the others, its banner and
// screenshots in its own language, and relative links that lead somewhere.
func TestReadmes(t *testing.T) {
	langs, names := localeNames(t)
	link := regexp.MustCompile(`\]\(([^)#\s]+)(?:#[^)]*)?\)|src="([^"]+)"`)
	for _, lang := range langs {
		path := readme(lang)
		b, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Errorf("%s: no README: %v", lang, err)
			continue
		}
		text := string(b)

		var switcher []string
		for _, other := range langs {
			if other == lang {
				switcher = append(switcher, "**"+names[other]+"**")
				continue
			}
			rel, _ := filepath.Rel(filepath.Dir(path), readme(other))
			switcher = append(switcher, "["+names[other]+"]("+filepath.ToSlash(rel)+")")
		}
		if want := strings.Join(switcher, " · "); !strings.Contains(text, want) {
			t.Errorf("%s: no language switcher %q", path, want)
		}

		for _, pic := range []string{"brand/banner-" + lang + ".png", "screenshots/tui-" + lang + ".png", "screenshots/web-" + lang + ".png"} {
			if !strings.Contains(text, pic) {
				t.Errorf("%s: does not show %s", path, pic)
			}
		}

		for _, m := range link.FindAllStringSubmatch(text, -1) {
			target := m[1] + m[2]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			if _, err := os.Stat(filepath.Join(root, filepath.Dir(path), target)); err != nil {
				t.Errorf("%s: link to %s leads nowhere", path, target)
			}
		}
	}
}
