package main

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/i18n"
	"github.com/mikekosulin/kanareika/internal/server"
	"github.com/mikekosulin/kanareika/tools/internal/chrome"
)

// seams for tests: where Chrome is, the file:// URL of a page, Chrome itself, and the environment
var (
	findChrome = chrome.Find
	fileURL    = chrome.FileURL
	shot       = chrome.Shot
	setenv     = os.Setenv
)

// The web page's size in CSS pixels (rendered at 2x); the TUI's follows its terminal size: a cell of the 13px
// monospace font is 7.83×15.86, plus the window's padding and title bar (150x26 makes 1207×472).
const webW, webH = 1600, 1000

func tuiSize(cols, rows int) (int, int) {
	return int(float64(cols)*7.83+0.5) + 32, int(float64(rows)*15.86+0.5) + 60
}

// shots: the README's screenshots in every language: tui-<lang>.png (the frame of size after keys, as run
// draws it), web-<lang>.png and web-<lang>-light.png (ToDo of `kanareika web` grouped by CVE, dark and light), in out.
// The directory is demo data (tools/demo): its trivy cache and feeds are used, not this machine's.
func shots(out, home, bin, org, env, size, keys, at string) error {
	if bin == "" {
		if bin = findChrome(); bin == "" {
			return fmt.Errorf("no Chrome or Chromium found: give one with -chrome")
		}
	}
	var cols, rows int
	if _, err := fmt.Sscanf(size, "%dx%d", &cols, &rows); err != nil {
		return fmt.Errorf("-size %q: %w", size, err)
	}
	tuiW, tuiH := tuiSize(cols, rows)
	// the demo's trivy cache and feeds, and times in UTC (Chrome inherits TZ), wherever this runs
	for k, v := range map[string]string{"TRIVY_CACHE_DIR": filepath.Join(home, "trivy"),
		"KANAREIKA_FEEDS_DIR": filepath.Join(home, "feeds"), "TZ": "UTC"} {
		if err := setenv(k, v); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	s, err := newServer(server.Options{Paths: config.PathsAt(home), Log: log.New(io.Discard, "", 0)})
	if err != nil {
		return err
	}
	web := httptest.NewServer(s.Handler())
	defer web.Close()
	for _, lang := range i18n.Langs() {
		var frame bytes.Buffer
		if err := run(&frame, home, lang, org, env, size, keys, at); err != nil {
			return err
		}
		page := filepath.Join(out, "tui-"+lang+".html")
		if err := os.WriteFile(page, []byte(terminal(frame.String())), 0o644); err != nil {
			return err
		}
		u, err := fileURL(page)
		if err != nil {
			return err
		}
		if err := shot(bin, u, filepath.Join(out, "tui-"+lang+".png"), tuiW, tuiH); err != nil {
			return err
		}
		// the web page grouped by CVE (the most telling view), in both themes: the README picks by the reader's theme
		where := url.Values{"org": {org}, "env": {env}, "by": {"cve"}, "lang": {lang}}
		page2 := web.URL + "/todo?" + where.Encode()
		if err := shot(bin, page2, filepath.Join(out, "web-"+lang+".png"), webW, webH,
			"--force-dark-mode", "--blink-settings=preferredColorScheme=0", "--virtual-time-budget=10000"); err != nil {
			return err
		}
		if err := shot(bin, page2, filepath.Join(out, "web-"+lang+"-light.png"), webW, webH,
			"--blink-settings=preferredColorScheme=1", "--virtual-time-budget=10000"); err != nil {
			return err
		}
	}
	return nil
}

// terminal: a frame as an HTML page: a window with the frame's colors, the size tuiSize gives it.
func terminal(frame string) string {
	return `<!doctype html><html><head><meta charset="utf-8"><style>
html,body{margin:0;background:transparent;overflow:hidden}
.term{display:inline-block;padding:14px 16px;background:#141413;border-radius:10px}
.bar{height:26px;display:flex;gap:7px;align-items:center;padding:0 2px 6px}
.bar i{width:11px;height:11px;border-radius:50%;display:block}
pre{margin:0;color:#e6e5e1;font:13px/1.22 "SF Mono",Menlo,"DejaVu Sans Mono","PingFang SC","Noto Sans Mono CJK SC",monospace}
.w{display:inline-block;width:2ch;text-align:center;font-weight:inherit}
</style></head><body><div class="term"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i>` +
		`<i style="background:#28c840"></i></div><pre>` + ansiHTML(strings.TrimRight(frame, "\n")) + `</pre></div>
</body></html>`
}

var sgr = regexp.MustCompile(`\x1b\[([0-9;]*)m`)

// ansiHTML: text with SGR codes (24-bit colors, bold, italic) as HTML spans; a character two columns wide in the
// terminal is a box two columns wide, so CJK text keeps the frame's columns.
func ansiHTML(s string) string {
	var b strings.Builder
	var fg, bg string
	var bold, italic bool
	emit := func(text string) {
		if text == "" {
			return
		}
		var st []string
		if fg != "" {
			st = append(st, "color:"+fg)
		}
		if bg != "" {
			st = append(st, "background:"+bg)
		}
		if bold {
			st = append(st, "font-weight:700")
		}
		if italic {
			st = append(st, "font-style:italic")
		}
		if len(st) > 0 {
			fmt.Fprintf(&b, `<span style="%s">%s</span>`, strings.Join(st, ";"), cells(text))
		} else {
			b.WriteString(cells(text))
		}
	}
	pos := 0
	for _, m := range sgr.FindAllStringSubmatchIndex(s, -1) {
		emit(s[pos:m[0]])
		pos = m[1]
		codes := strings.Split(s[m[2]:m[3]], ";")
		for i := 0; i < len(codes); i++ {
			c, _ := strconv.Atoi(codes[i]) // "" is 0, as in a bare ESC[m
			switch {
			case c == 0:
				fg, bg, bold, italic = "", "", false, false
			case c == 1:
				bold = true
			case c == 3:
				italic = true
			case c == 22:
				bold = false
			case c == 23:
				italic = false
			case c == 39:
				fg = ""
			case c == 49:
				bg = ""
			case (c == 38 || c == 48) && i+4 < len(codes) && codes[i+1] == "2":
				rgb := [3]int{}
				for j := range rgb {
					rgb[j], _ = strconv.Atoi(codes[i+2+j])
				}
				col := fmt.Sprintf("#%02x%02x%02x", rgb[0], rgb[1], rgb[2])
				if c == 38 {
					fg = col
				} else {
					bg = col
				}
				i += 4
			case (c == 38 || c == 48) && i+2 < len(codes) && codes[i+1] == "5":
				i += 2 // a 256-color index (the TUI uses 24-bit colors): skipped, not read as codes
			}
		}
	}
	emit(s[pos:])
	return b.String()
}

// cells: text escaped for HTML, wide characters in boxes of two columns.
func cells(text string) string {
	var b strings.Builder
	for _, r := range text {
		if ansi.StringWidth(string(r)) == 2 {
			b.WriteString(`<b class="w">` + html.EscapeString(string(r)) + `</b>`)
		} else {
			b.WriteString(html.EscapeString(string(r)))
		}
	}
	return b.String()
}
