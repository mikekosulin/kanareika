package server

import (
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/assets"
	"github.com/mikekosulin/kanareika/internal/i18n"
)

var (
	jsT     = regexp.MustCompile(`\btf?\("((?:[^"\\]|\\.)*)"[),]`) // t("…") and tf("…", {…})
	attrT   = regexp.MustCompile(`data-t(?:-title)?="([^"]+)"`)
	notWord = regexp.MustCompile(`^([A-Z0-9/+-]{1,6}|[^A-Za-z]*|Trivy|Kanareika)$`)
)

// TestEveryPageStringTranslated: every interface string of the web page (t("...") and data-t attributes) has a
// translation in every language.
func TestEveryPageStringTranslated(t *testing.T) {
	b, err := fs.ReadFile(assets.Web(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range jsT.FindAllStringSubmatch(string(b), -1) {
		s, err := strconv.Unquote(`"` + m[1] + `"`)
		if err == nil && !notWord.MatchString(s) {
			seen[s] = true
		}
	}
	for _, m := range attrT.FindAllStringSubmatch(string(b), -1) {
		if !notWord.MatchString(m[1]) {
			seen[strings.ReplaceAll(m[1], "&amp;", "&")] = true
		}
	}
	if len(seen) < 100 {
		t.Fatalf("only %d strings found: the extraction is broken", len(seen))
	}
	ui := i18n.UI()
	for _, lang := range i18n.Langs()[1:] {
		var missing []string
		for s := range seen {
			if ui[lang][s] == "" {
				missing = append(missing, strconv.Quote(s))
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("%s: %d untranslated:\n%s", lang, len(missing), strings.Join(missing, "\n"))
		}
	}
}

// TestPageShape: the page is HTML from its first byte, and the helpers every view calls are defined inside its
// script (the tests do not run the page's JavaScript: a helper left outside it breaks the page silently).
func TestPageShape(t *testing.T) {
	b, err := fs.ReadFile(assets.Web(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	if !strings.HasPrefix(page, "<!doctype html>") {
		t.Fatalf("the page starts with %q", page[:min(len(page), 40)])
	}
	open, end := strings.Index(page, "<script>"), strings.LastIndex(page, "</script>")
	for _, def := range []string{"const t = (s) => ", "const tf = (s, v) => ", "function L(", "const LANG_NAMES = ", "const LANGS = "} {
		i := strings.Index(page, def)
		if i < open || i > end || strings.Count(page, def) != 1 {
			t.Errorf("%q: not once inside the script", def)
		}
	}
}
