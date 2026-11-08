// Command brand draws the repository's pictures: the social preview (GitHub: Settings → Social preview) and the
// banner at the top of each README:
//
//	go run ./tools/brand -out docs/brand
//
// Each picture is an HTML page (og.html, banner.html, style.css next to this file, read from -pages: edit them),
// rendered to PNG at 2x by headless Chrome (-chrome, or found on its own). Without Chrome only the pages are
// written. The data on them is invented like the demo's: hosts from tools/demo, CVE ids that do not exist.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// sources: the pages to fill in and the style they share. Read from files, not embedded: what goes into a binary
// comes from assets/ only (tools/anonymize/guard_test.go), and a changed page needs no rebuild.
type sources struct{ og, banner, css string }

func load(dir string) (sources, error) {
	var s sources
	for _, f := range []struct {
		name string
		to   *string
	}{{"og.html", &s.og}, {"banner.html", &s.banner}, {"style.css", &s.css}} {
		b, err := os.ReadFile(filepath.Join(dir, f.name))
		if err != nil {
			return s, err
		}
		*f.to = string(b)
	}
	return s, nil
}

// seams for tests: main's fatal exit, Chrome itself, and where Chrome is looked for
var (
	fatal     = log.Fatal
	runChrome = func(ctx context.Context, bin string, args ...string) error {
		out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w: %s", bin, err, bytes.TrimSpace(out))
		}
		return nil
	}
	lookPath = exec.LookPath
	goos     = runtime.GOOS
	absPath  = filepath.Abs
	macApps  = []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium"}
)

// row: one line of the ToDo list in the picture.
type row struct {
	P                int
	Host, Text, Kind string
}

// lang: the words of one language; tabs as the TUI names them (assets/locales).
type lang struct {
	Code, Tag, Accent, Sub, DB, Keys string
	Tabs                             []string
	Rows                             []row
}

var langs = []lang{
	{Code: "en", Tag: "Security audit of your servers over SSH.", Accent: "What to patch first.",
		Sub: "agentless · read-only · TUI + web · MCP", DB: "db ok", Keys: "↑↓ move · space select · f fix plan · / search",
		Tabs: []string{"ToDo", "Hosts", "Packages", "Access", "Network", "Health"},
		Rows: []row{
			{1, "web-01", "openssl 3.0.13 → 3.0.15", "CVE-2026-90017"},
			{1, "db-01", "glibc 2.34-100 → 2.34-125", "CVE-2026-90042"},
			{2, "web-01", "sshd: password login enabled", "access"},
			{2, "web-02", ":6379 reachable from anywhere", "network"},
			{3, "db-01", "kernel 5.14.0-427 · reboot pending", "reboot"},
			{3, "web-02", "NTP drift 4.2 s", "health"},
			{3, "stage-web-01", "firewall · default policy ACCEPT", "network"},
			{4, "web-02", "libxml2 · no fix in repo yet", "vendor"},
			{4, "db-01", "curl · low, EPSS 0.02%", "CVE-2026-90210"},
		}},
	{Code: "ru", Tag: "Аудит безопасности серверов по SSH.", Accent: "Начните с главного.",
		Sub:  "без агента · только чтение · TUI + веб · MCP",
		Tabs: []string{"Что делать", "Хосты", "Пакеты", "Доступ", "Сеть", "Здоровье"},
		Rows: []row{
			{1, "web-01", "openssl 3.0.13 → 3.0.15", "CVE-2026-90017"},
			{1, "db-01", "glibc 2.34-100 → 2.34-125", "CVE-2026-90042"},
			{2, "web-01", "sshd: вход по паролю включён", "доступ"},
			{2, "web-02", ":6379 доступен отовсюду", "сеть"},
			{3, "db-01", "ядро 5.14.0-427 · ждёт перезагрузки", "перезагрузка"},
		}},
	{Code: "zh", Tag: "通过 SSH 审计服务器安全。", Accent: "从最重要的开始。",
		Sub:  "无代理 · 只读 · TUI + Web · MCP",
		Tabs: []string{"待办", "主机", "软件包", "访问", "网络", "健康"},
		Rows: []row{
			{1, "web-01", "openssl 3.0.13 → 3.0.15", "CVE-2026-90017"},
			{1, "db-01", "glibc 2.34-100 → 2.34-125", "CVE-2026-90042"},
			{2, "web-01", "sshd：已启用密码登录", "访问"},
			{2, "web-02", ":6379 对外开放", "网络"},
			{3, "db-01", "内核 5.14.0-427 · 等待重启", "重启"},
		}},
}

// bannerRows: the banner is low, the first rows are enough.
const bannerRows = 5

// picture: a page to write and the size to render it at, in CSS pixels.
type picture struct {
	name string
	w, h int
	html []byte
}

func main() {
	out := flag.String("out", "docs/brand", "directory to write the pictures to")
	logo := flag.String("logo", "assets/web/logo.png", "the canary")
	pages := flag.String("pages", "tools/brand", "where og.html, banner.html and style.css are")
	chrome := flag.String("chrome", "", "Chrome or Chromium to render with (default: found on its own; none: pages only)")
	flag.Parse()
	if err := run(*out, *logo, *pages, *chrome); err != nil {
		fatal(err)
	}
}

func run(out, logoPath, pagesDir, chrome string) error {
	src, err := load(pagesDir)
	if err != nil {
		return err
	}
	png, err := os.ReadFile(logoPath)
	if err != nil {
		return err
	}
	pics, err := pictures("data:image/png;base64,"+base64.StdEncoding.EncodeToString(png), src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if chrome == "" {
		chrome = findChrome()
	}
	for _, p := range pics {
		page := filepath.Join(out, p.name+".html")
		if err := os.WriteFile(page, p.html, 0o644); err != nil {
			return err
		}
		if chrome == "" {
			continue
		}
		if err := render(chrome, page, filepath.Join(out, p.name+".png"), p.w, p.h); err != nil {
			return err
		}
	}
	if chrome == "" {
		log.Printf("no Chrome found (-chrome): wrote the pages to %s, not the pictures", out)
	}
	return nil
}

// pictures: the social preview (English: GitHub shows one for every language) and a banner per language.
func pictures(logo string, src sources) ([]picture, error) {
	og, err := template.New("og").Parse(src.og)
	if err != nil {
		return nil, err
	}
	banner, err := template.New("banner").Parse(src.banner)
	if err != nil {
		return nil, err
	}
	type count struct{ N, Count int }
	data := func(l lang, rows []row) map[string]any {
		var counts []count
		for n := 1; n <= 4; n++ {
			c := 0
			for _, r := range rows {
				if r.P == n {
					c++
				}
			}
			counts = append(counts, count{n, c})
		}
		return map[string]any{"CSS": template.CSS(src.css), "Logo": template.URL(logo), "L": l, "Rows": rows, "Counts": counts}
	}
	var b bytes.Buffer
	if err := og.Execute(&b, data(langs[0], langs[0].Rows)); err != nil {
		return nil, err
	}
	pics := []picture{{"og", 1280, 640, bytes.Clone(b.Bytes())}}
	for _, l := range langs {
		b.Reset()
		if err := banner.Execute(&b, data(l, l.Rows[:min(bannerRows, len(l.Rows))])); err != nil {
			return nil, err
		}
		pics = append(pics, picture{"banner-" + l.Code, 1280, 360, bytes.Clone(b.Bytes())})
	}
	return pics, nil
}

// findChrome: Chrome or Chromium on this machine, "" if there is none.
func findChrome() string {
	if goos == "darwin" {
		for _, p := range macApps {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := lookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// render: one page to PNG at 2x; transparent where the page is (the banner's rounded corners).
func render(chrome, page, png string, w, h int) error {
	abs, err := absPath(page)
	if err != nil {
		return err
	}
	shot, err := absPath(png)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := runChrome(ctx, chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars",
		"--force-device-scale-factor=2", "--default-background-color=00000000",
		fmt.Sprintf("--window-size=%d,%d", w, h), "--screenshot="+shot, fileURL(abs)); err != nil {
		return err
	}
	if _, err := os.Stat(shot); err != nil {
		return errors.New("chrome wrote no picture: " + shot)
	}
	return nil
}

// fileURL: file:///home/x/og.html, file:///C:/x/og.html on Windows.
func fileURL(abs string) string {
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return "file://" + p
}
