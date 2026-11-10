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
	for _, def := range []string{"const t = (s, args) => ", "const LANG_NAMES = ", "const LANG = ", "const UI = "} {
		i := strings.Index(page, def)
		if i < open || i > end || strings.Count(page, def) != 1 {
			t.Errorf("%q: not once inside the script", def)
		}
	}
}

// TestLogos: the page's images are the lossless WebP (/logo.webp); the favicon stays PNG (/logo.png).
func TestLogos(t *testing.T) {
	_, h := newTest(t, Options{})
	png, webp := do(h, "GET", "/logo.png", nil, nil), do(h, "GET", "/logo.webp", nil, nil)
	if png.code != 200 || png.h.Get("Content-Type") != "image/png" || !strings.HasPrefix(png.body, "\x89PNG") {
		t.Errorf("png: %d %s", png.code, png.h.Get("Content-Type"))
	}
	if webp.code != 200 || webp.h.Get("Content-Type") != "image/webp" || webp.body[:4] != "RIFF" || webp.body[8:12] != "WEBP" ||
		len(webp.body) >= len(png.body) {
		t.Errorf("webp: %d %s %d bytes", webp.code, webp.h.Get("Content-Type"), len(webp.body))
	}
	for _, name := range []string{"index.html"} {
		b, err := fs.ReadFile(assets.Web(), name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `<img src="/logo.png"`) || !strings.Contains(string(b), `<img src="/logo.webp"`) ||
			!strings.Contains(string(b), `<link rel="icon" type="image/png" href="/logo.png">`) {
			t.Errorf("%s: images from logo.webp, the favicon from logo.png", name)
		}
	}
}

// TestPageEscapesData:the page writes what the server sends (vulnerability DB texts, what the scanned hosts
// reported, the org files) through esc(). The tests do not run the page's JavaScript, so this looks for the
// shapes that let such text through as HTML: a field interpolated straight into an element or an attribute, a
// field passed raw into t()'s {args}, a link not limited to http(s), and the CVSS vector's parts written unescaped.
func TestPageEscapesData(t *testing.T) {
	b, err := fs.ReadFile(assets.Web(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	const field = `[\w?.\[\]]+\.(?:description|title|label|pkg|reason|owner|note|comment|problem|process|mount|error|message|command|output|installed|fixed|path|address|user|host|name|env|jump|system|os|priority|severity|state|url|vector|id)`
	risky := map[string]*regexp.Regexp{
		"a field as element text":           regexp.MustCompile(`>\$\{` + field + `\}`),
		"a field as an attribute":           regexp.MustCompile(`="\$\{` + field + `\}"`),
		"a raw field in t() args":           regexp.MustCompile(`\bt\("[^"]*", \{[^}]*?\w+: ` + field + `\b`),
		"a raw S.env in t() args":           regexp.MustCompile(`\bt\("[^"]*", \{[^}]*?\w+: S\.(?:env|org|run)\b`),
		"a link not limited to http(s)":     regexp.MustCompile(`href="\$\{(?:esc\((?:c|x|n|d)\.url\)|(?:c|x|n|d)\.url)`),
		"a translated value left unescaped": regexp.MustCompile(`<b>\$\{t\((?:val|v|txt)\)\}</b>`),
	}
	for i, line := range strings.Split(page, "\n") {
		if !strings.Contains(line, "<") { // plain text: the palette, the clipboard, filters
			continue
		}
		for what, re := range risky {
			for _, m := range re.FindAllString(line, -1) {
				t.Errorf("line %d: %s: %s", i+1, what, m)
			}
		}
	}
	// the vector: only known CVSS 3 metric letters make the table, the rest is shown as escaped text
	for _, must := range []string{`const CVSS3 = { AV: "NALP"`, `<b>${esc(t(val))}</b>`, `const webURL = `, `href="${esc(webURL(c.url))}"`} {
		if !strings.Contains(page, must) {
			t.Errorf("the page lost %q", must)
		}
	}
}
