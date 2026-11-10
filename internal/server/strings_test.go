package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/mikekosulin/kanareika/assets"
	"github.com/mikekosulin/kanareika/internal/i18n"
)

var (
	jsT     = regexp.MustCompile(`\bt[fx]?\("((?:[^"\\]|\\.)*)"[),]`) // t("…"), tx("…", {…})
	notWord = regexp.MustCompile(`^([A-Z0-9/+-]{1,6}|[^A-Za-z]*|Trivy|Kanareika)$`)
)

// webSources: the page's source files (web/src; the built page, assets/web/index.html.gz, is minified).
func webSources(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir("../../web/src", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !(strings.HasSuffix(p, ".ts") || strings.HasSuffix(p, ".tsx")) {
			return err
		}
		b, err := os.ReadFile(p)
		out[p] = string(b)
		return err
	})
	if err != nil || len(out) < 10 {
		t.Fatalf("web sources: %v (%d files)", err, len(out))
	}
	return out
}

// TestEveryPageStringTranslated: every interface string of the web page (t("…") and tx("…") in its sources) has
// a translation in every language.
func TestEveryPageStringTranslated(t *testing.T) {
	seen := map[string]bool{}
	for _, src := range webSources(t) {
		for _, m := range jsT.FindAllStringSubmatch(src, -1) {
			s, err := strconv.Unquote(`"` + m[1] + `"`)
			if err == nil && !notWord.MatchString(s) {
				seen[s] = true
			}
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

// TestPageShape: the built page is HTML from its first byte, with the server's placeholders once each, inside
// the script that hands them to the page; and it is built from the sources (web/: npm run build).
func TestPageShape(t *testing.T) {
	b, err := gunzip(assets.Web(), "index.html.gz")
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	if !strings.HasPrefix(page, "<!doctype html>") {
		t.Fatalf("the page starts with %q", page[:min(len(page), 40)])
	}
	if !strings.Contains(page, `window.KANAREIKA = { csrf: /*CSRF*/"", ui: /*I18N_UI*/{}, names: /*I18N_NAMES*/{} };`) {
		t.Error("the page lost its placeholders (web/index.html)")
	}
	for _, ph := range []string{`/*CSRF*/""`, "/*I18N_UI*/{}", "/*I18N_NAMES*/{}"} {
		if n := strings.Count(page, ph); n != 1 {
			t.Errorf("%s: %d times", ph, n)
		}
	}
	if !strings.Contains(page, `<script type="module"`) || strings.Contains(page, `src="/src/main.tsx"`) {
		t.Error("assets/web/index.html.gz is not the built page: make web")
	}
}

// TestLogos: the page's images are the lossless WebP (/logo.webp); the favicon is a small PNG (/favicon.png, and
// /favicon.ico, which browsers ask for on their own).
func TestLogos(t *testing.T) {
	_, h := newTest(t, Options{})
	for _, path := range []string{"/favicon.png", "/favicon.ico"} {
		png := do(h, "GET", path, nil, nil)
		if png.code != 200 || png.h.Get("Content-Type") != "image/png" || !strings.HasPrefix(png.body, "\x89PNG") || len(png.body) > 8<<10 {
			t.Errorf("%s: %d %s %d bytes", path, png.code, png.h.Get("Content-Type"), len(png.body))
		}
	}
	if r := do(h, "GET", "/logo.png", nil, nil); r.code != 404 {
		t.Errorf("/logo.png: %d", r.code)
	}
	webp := do(h, "GET", "/logo.webp", nil, nil)
	if webp.code != 200 || webp.h.Get("Content-Type") != "image/webp" || webp.body[:4] != "RIFF" || webp.body[8:12] != "WEBP" {
		t.Errorf("webp: %d %s", webp.code, webp.h.Get("Content-Type"))
	}
	b, err := gunzip(assets.Web(), "index.html.gz")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "/logo.png") || !strings.Contains(string(b), `"/logo.webp"`) ||
		!strings.Contains(string(b), `<link rel="icon" type="image/png" href="/favicon.png">`) {
		t.Error("the page: images from logo.webp, the icon from favicon.png")
	}
}

// TestPageEscapesData: the page shows what the server sends (vulnerability DB texts, what the scanned hosts
// reported, the org files). React writes text as text; this keeps the ways around it out of the sources: raw
// HTML, links not limited to http(s), and the CVSS vector's parts taken from anything but the known letters.
func TestPageEscapesData(t *testing.T) {
	srcs := webSources(t)
	all := ""
	for p, src := range srcs {
		all += src
		for _, bad := range []string{"dangerouslySetInnerHTML", ".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write"} {
			if strings.Contains(src, bad) {
				t.Errorf("%s: %s", p, bad)
			}
		}
		// a link from data: only through webURL (http(s))
		for _, m := range regexp.MustCompile(`href=\{([^}]*)\}`).FindAllStringSubmatch(src, -1) {
			if !strings.Contains(m[1], "href(") && m[1] != "url" && !strings.HasPrefix(m[1], `"#`) { // the icon sprite
				t.Errorf("%s: href={%s}: a link not made by webURL", p, m[1])
			}
		}
	}
	for _, must := range []string{`const CVSS3: Record<string, string> = { AV: "NALP"`, `export const webURL = `, `const url = webURL(c.url);`} {
		if !strings.Contains(all, must) {
			t.Errorf("the page lost %q", must)
		}
	}
}
