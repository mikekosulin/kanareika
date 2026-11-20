// Command brand draws the repository's pictures: the social preview (GitHub: Settings → Social preview) and the
// banner at the top of each README:
//
//	go run ./tools/brand -out docs/brand
//
// Each picture is an HTML page (og.html, banner.html, style.css next to this file, read from -pages: edit them),
// rendered to PNG at 2x by headless Chrome (-chrome, or found on its own). Without Chrome only the pages are
// written. The data on them is invented like the demo's: hosts from tools/demo, CVE ids of the year 0000 (never assigned).
package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"html/template"
	"log"
	"os"
	"path/filepath"

	"github.com/mikekosulin/kanareika/tools/internal/chrome"
	"github.com/mikekosulin/kanareika/tools/internal/webp"
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

// seams for tests: main's fatal exit, where Chrome is, and Chrome itself
var (
	fatal      = log.Fatal
	findChrome = chrome.Find
	fileURL    = chrome.FileURL
	shot       = chrome.Shot
)

// row: one line of the Fixes list in the picture: a fix, on how many hosts, and what it is (its CVEs, or a setting).
type row struct {
	P     int
	Text  string
	Hosts int
	Kind  string
}

// lang: the words of one language; tabs as the TUI names them (assets/locales), Fixes first and open.
type lang struct {
	Code, Tag, Accent, Sub, DB, Keys string
	Tabs                             []string
	Rows                             []row
}

var langs = []lang{
	{Code: "en", Tag: "Security audit of your servers over SSH.", Accent: "What to patch first.",
		Sub: "agentless · read-only · TUI + web · MCP", DB: "db ok", Keys: "↑↓ move · space select · f fix plan · / search",
		Tabs: []string{"Fixes", "Servers", "History"},
		Rows: []row{
			{1, "openssl 3.0.13 → 3.0.15", 12, "2 CVE"},
			{1, "glibc 2.34-100 → 2.34-125", 8, "1 CVE"},
			{2, "sshd: password login enabled", 3, "access"},
			{2, ":6379 reachable from anywhere", 1, "network"},
			{3, "kernel 5.14.0-427 · reboot pending", 5, "reboot"},
			{3, "NTP drift 4.2 s", 1, "health"},
			{3, "firewall · default policy ACCEPT", 4, "network"},
			{4, "libxml2 · no fix in repo yet", 6, "vendor"},
			{4, "curl · low, EPSS 0.02%", 9, "1 CVE"},
		}},
	{Code: "ru", Tag: "Аудит безопасности серверов по SSH.", Accent: "Начните с главного.",
		Sub:  "без агента · только чтение · TUI + веб · MCP",
		Tabs: []string{"Исправления", "Серверы", "История"},
		Rows: []row{
			{1, "openssl 3.0.13 → 3.0.15", 12, "2 CVE"},
			{1, "glibc 2.34-100 → 2.34-125", 8, "1 CVE"},
			{2, "sshd: вход по паролю включён", 3, "доступ"},
			{2, ":6379 доступен отовсюду", 1, "сеть"},
			{3, "ядро 5.14.0-427 · ждёт перезагрузки", 5, "перезагрузка"},
		}},
	{Code: "zh", Tag: "通过 SSH 审计服务器安全。", Accent: "从最重要的开始。",
		Sub:  "无代理 · 只读 · TUI + Web · MCP",
		Tabs: []string{"修复", "服务器", "历史"},
		Rows: []row{
			{1, "openssl 3.0.13 → 3.0.15", 12, "2 CVE"},
			{1, "glibc 2.34-100 → 2.34-125", 8, "1 CVE"},
			{2, "sshd：已启用密码登录", 3, "访问"},
			{2, ":6379 对外开放", 1, "网络"},
			{3, "内核 5.14.0-427 · 等待重启", 5, "重启"},
		}},
	{Code: "es", Tag: "Auditoría de seguridad de servidores por SSH.", Accent: "Empiece por lo importante.",
		Sub:  "sin agente · solo lectura · TUI + web · MCP",
		Tabs: []string{"Correcciones", "Servidores", "Historial"},
		Rows: []row{
			{1, "openssl 3.0.13 → 3.0.15", 12, "2 CVE"},
			{1, "glibc 2.34-100 → 2.34-125", 8, "1 CVE"},
			{2, "sshd: acceso con contraseña activado", 3, "acceso"},
			{2, ":6379 abierto a todo el mundo", 1, "red"},
			{3, "kernel 5.14.0-427 · pendiente de reinicio", 5, "reinicio"},
		}},
	{Code: "fr", Tag: "Audit de sécurité des serveurs via SSH.", Accent: "Commencez par l'essentiel.",
		Sub:  "sans agent · lecture seule · TUI + web · MCP",
		Tabs: []string{"Correctifs", "Serveurs", "Historique"},
		Rows: []row{
			{1, "openssl 3.0.13 → 3.0.15", 12, "2 CVE"},
			{1, "glibc 2.34-100 → 2.34-125", 8, "1 CVE"},
			{2, "sshd : connexion par mot de passe activée", 3, "accès"},
			{2, ":6379 accessible de partout", 1, "réseau"},
			{3, "noyau 5.14.0-427 · redémarrage en attente", 5, "redémarrage"}, //nolint:misspell // French
		}},
	{Code: "pt", Tag: "Auditoria de segurança de servidores via SSH.", Accent: "Comece pelo que importa.",
		Sub:  "sem agente · somente leitura · TUI + web · MCP",
		Tabs: []string{"Correções", "Servidores", "Histórico"},
		Rows: []row{
			{1, "openssl 3.0.13 → 3.0.15", 12, "2 CVE"},
			{1, "glibc 2.34-100 → 2.34-125", 8, "1 CVE"},
			{2, "sshd: login por senha ativado", 3, "acesso"},
			{2, ":6379 aberto para todos", 1, "rede"},
			{3, "kernel 5.14.0-427 · reinicialização pendente", 5, "reiniciar"},
		}},
	{Code: "ja", Tag: "SSH によるサーバーのセキュリティ監査。", Accent: "まずは重要なものから。",
		Sub:  "エージェント不要 · 読み取り専用 · TUI + Web · MCP",
		Tabs: []string{"修正", "サーバー", "履歴"},
		Rows: []row{
			{1, "openssl 3.0.13 → 3.0.15", 12, "2 CVE"},
			{1, "glibc 2.34-100 → 2.34-125", 8, "1 CVE"},
			{2, "sshd: パスワードログイン有効", 3, "アクセス"},
			{2, ":6379 がどこからでも到達可能", 1, "ネットワーク"},
			{3, "カーネル 5.14.0-427 · 再起動待ち", 5, "再起動"},
		}},
	{Code: "ko", Tag: "SSH를 통한 서버 보안 감사.", Accent: "중요한 것부터 시작하세요.",
		Sub:  "에이전트 불필요 · 읽기 전용 · TUI + 웹 · MCP",
		Tabs: []string{"패치", "서버", "기록"},
		Rows: []row{
			{1, "openssl 3.0.13 → 3.0.15", 12, "2 CVE"},
			{1, "glibc 2.34-100 → 2.34-125", 8, "1 CVE"},
			{2, "sshd: 비밀번호 로그인 켜짐", 3, "접근"},
			{2, ":6379 어디서나 접근 가능", 1, "네트워크"},
			{3, "커널 5.14.0-427 · 재부팅 대기", 5, "재부팅"},
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
	logo := flag.String("logo", "docs/brand/logo.png", "the canary, 512 px")
	pages := flag.String("pages", "tools/brand", "where og.html, banner.html and style.css are")
	bin := flag.String("chrome", "", "Chrome or Chromium to render with (default: found on its own; none: pages only)")
	flag.Parse()
	if err := run(*out, *logo, *pages, *bin); err != nil {
		fatal(err)
	}
}

func run(out, logoPath, pagesDir, bin string) error {
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
	if bin == "" {
		bin = findChrome()
	}
	for _, p := range pics {
		page := filepath.Join(out, p.name+".html")
		if err := os.WriteFile(page, p.html, 0o644); err != nil {
			return err
		}
		if bin == "" {
			continue
		}
		if err := render(bin, page, filepath.Join(out, p.name+".png"), p.w, p.h); err != nil {
			return err
		}
		if p.name != "og" { // the README's banners as lossless WebP; the social preview stays PNG
			if _, err := webp.FromPNG(filepath.Join(out, p.name+".png")); err != nil {
				return err
			}
		}
	}
	if bin == "" {
		log.Printf("no Chrome found (-chrome): wrote the pages to %s, not the pictures", out)
	}
	return nil
}

// pictures: the social preview (English: GitHub shows one for every language; dark only, a preview has no theme)
// and a banner per language, dark and light (-light: the README picks by the reader's theme).
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
		for _, light := range []bool{false, true} {
			d := data(l, l.Rows[:min(bannerRows, len(l.Rows))])
			d["Light"] = light
			name := "banner-" + l.Code
			if light {
				name += "-light"
			}
			b.Reset()
			if err := banner.Execute(&b, d); err != nil {
				return nil, err
			}
			pics = append(pics, picture{name, 1280, 360, bytes.Clone(b.Bytes())})
		}
	}
	return pics, nil
}

// render: one page to PNG at 2x.
func render(bin, page, png string, w, h int) error {
	url, err := fileURL(page)
	if err != nil {
		return err
	}
	return shot(bin, url, png, w, h)
}
