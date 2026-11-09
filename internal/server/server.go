// Package server is the local dashboard (`kanareika serve`): web/index.html, a read-only JSON API over reports/
// and orgs/, and scans started from the page. It binds to localhost by default (reports hold addresses and
// vulnerabilities).
//
// The read API is the one the Python dashboard served, path for path and field for field.
//
// Safety: on localhost only requests addressed to a loopback name are served (a DNS-rebinding page can't read
// reports or start scans); with a token (--token) every request needs it (once as ?token=, then a cookie); scans
// need the page's CSRF token in a header, which no other site can read. Bound elsewhere without a token, the
// dashboard is read-only.
package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/mikekosulin/kanareika/assets"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
	"github.com/mikekosulin/kanareika/internal/report"
)

// Defaults of `kanareika serve`.
const (
	DefaultHost = "127.0.0.1"
	DefaultPort = 8088
)

// csp: the page is self-contained (inline script and style, logo from the same origin); nothing else loads.
const csp = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"

// PromptFunc builds the agent task text for the selected actions of a view (internal/prompt.Build). It is
// passed in by the CLI, so this package does not depend on the prompt code.
type PromptFunc func(org *config.Org, env string, view *report.View, ids []string, lang string) string

type Options struct {
	Paths  config.Paths
	Prompt PromptFunc // nil: /api/prompt answers 501
	Scan   ScanFunc   // nil: scans can't be started from the dashboard
	// UpdateDB: what `db update` does; nil: DB updates can't be started from an interface
	UpdateDB DBUpdateFunc
	Token    string      // "": no access token (fine on localhost)
	Log      *log.Logger // errors and panics; nil: the standard logger
}

// Server holds the API state: org configs (reloaded by /api/orgs) and the last few views.
type Server struct {
	paths   config.Paths
	prompt  PromptFunc
	log     *log.Logger
	state   atomic.Pointer[orgState]
	page    []byte // index.html with the UI strings and the CSRF token filled in
	classic []byte // classic.html, the same way
	logo    []byte
	token   string
	csrf    string
	jobs    *jobs       // nil: scans disabled
	db      *dbUpdater  // nil: DB updates disabled
	local   atomic.Bool // bound to loopback: only loopback Host headers are served

	orgFiles sync.Map // org id -> *sync.Mutex: one setup write (create, add hosts) per org file at a time

	mu    sync.Mutex // view builds and current/ updates, one at a time (each can take seconds on big runs)
	views []cachedView
	trees *treeInput // the last tree input (findings + view), by view mtime
}

type cachedView struct {
	key  viewKey
	body []byte
}

// New loads the org configs and prepares the page; config errors are not fatal (they are shown in the page).
func New(o Options) (*Server, error) {
	s := &Server{paths: o.Paths, prompt: o.Prompt, log: o.Log, token: o.Token, csrf: newID() + newID()}
	if s.log == nil {
		s.log = log.Default()
	}
	if o.Scan != nil {
		s.jobs = &jobs{scan: o.Scan, now: time.Now}
	}
	if o.UpdateDB != nil {
		s.db = &dbUpdater{fn: o.UpdateDB, now: time.Now}
		if s.jobs != nil {
			db := s.db
			s.jobs.before = func(ctx context.Context, out io.Writer) {
				db.mu.Lock()
				running := db.running
				db.mu.Unlock()
				if running {
					fmt.Fprintln(out, "waiting for the vulnerability DB download started from the page to finish ...")
					db.wait(ctx)
				}
			}
		}
	}
	var err error
	if s.page, err = page("index.html"); err != nil {
		return nil, err
	}
	s.page = bytes.Replace(s.page, []byte(`/*CSRF*/""`), []byte(`"`+s.csrf+`"`), 1)
	if s.classic, err = page("classic.html"); err != nil {
		return nil, err
	}
	s.classic = bytes.Replace(s.classic, []byte(`/*CSRF*/""`), []byte(`"`+s.csrf+`"`), 1)
	if s.logo, err = fs.ReadFile(webFS(), "logo.png"); err != nil {
		return nil, err
	}
	s.reload()
	return s, nil
}

// webFS and localesFS: where the page and the UI strings come from (variables so tests can break them).
var webFS, localesFS = assets.Web, assets.Locales

// views: the page's three places, each at its own address (/servers?org=…&env=…), all the same page; / lands on
// Servers.
var views = []string{"servers", "todo", "history"}

// moved: where the earlier addresses went (their query is kept, after the target's own).
var moved = map[string]string{
	"/hosts": "/servers", "/packages": "/todo", "/access": "/servers?show=logins", "/network": "/servers?show=network",
	"/health": "/servers?show=health", "/exceptions": "/todo?f=accepted", "/changes": "/history", "/runs": "/history",
	"/setup/access": "/setup/connect",
}

// page: index.html with the /*I18N_UI*/{} placeholder replaced by the UI strings of every language, encoded
// as Python's json.dumps did ("</" escaped so a string cannot close the script tag).
func page(name string) ([]byte, error) {
	html, err := fs.ReadFile(webFS(), name)
	if err != nil {
		return nil, err
	}
	ui, names, err := uiJSON()
	if err != nil {
		return nil, err
	}
	ui = strings.ReplaceAll(ui, "</", `<\/`)
	names = strings.ReplaceAll(names, "</", `<\/`)
	html = bytes.ReplaceAll(html, []byte("/*I18N_UI*/{}"), []byte(ui))
	return bytes.ReplaceAll(html, []byte("/*I18N_NAMES*/{}"), []byte(names)), nil
}

// uiJSON: {lang: ui} for the locales that have UI strings, in file name order, keys as in the files; and
// {lang: name}, each language in its own name (the "name" of its file).
func uiJSON() (string, string, error) {
	files, err := fs.Glob(localesFS(), "*.json")
	if err != nil {
		return "", "", err
	}
	all, names := pyfmt.Obj{}, pyfmt.Obj{}
	for _, f := range files { // Glob sorts
		b, err := fs.ReadFile(localesFS(), f)
		if err != nil {
			return "", "", err
		}
		var l struct {
			Name string          `json:"name"`
			UI   json.RawMessage `json:"ui"`
		}
		if err := json.Unmarshal(b, &l); err != nil {
			return "", "", fmt.Errorf("locales/%s: %w", f, err)
		}
		lang := strings.TrimSuffix(f, ".json")
		if ui, _ := pyfmt.Loads(string(l.UI)); pyfmt.Truthy(ui) {
			all = append(all, pyfmt.KV{K: lang, V: ui})
		}
		if l.Name != "" {
			names = append(names, pyfmt.KV{K: lang, V: l.Name})
		}
	}
	b, err := pyfmt.DumpsLine(all, false)
	n, err2 := pyfmt.DumpsLine(names, false)
	return string(b), string(n), errors.Join(err, err2)
}

// Handler: the routes. GET for the page and the read API; POST only to start and cancel scans; other methods
// get 501 as before.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, headers, s.errorLog, s.guard, methods)
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) { send(w, 404, "text/plain", []byte("not found")) })
	r.Get("/logo.png", func(w http.ResponseWriter, _ *http.Request) { send(w, 200, "image/png", s.logo) })
	index := func(w http.ResponseWriter, _ *http.Request) { send(w, 200, "text/html; charset=utf-8", s.page) }
	r.Get("/", index)
	// no .html in addresses: the old one goes to /; the setup steps are addresses of the same page
	r.Get("/index.html", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusMovedPermanently) })
	r.Get("/setup", index)
	r.Get("/setup/{step}", index)
	for _, v := range views {
		r.Get("/"+v, index)
	}
	for from, to := range moved {
		r.Get(from, func(w http.ResponseWriter, r *http.Request) {
			u := to
			if q := r.URL.RawQuery; q != "" {
				if strings.Contains(u, "?") {
					u += "&" + q
				} else {
					u += "?" + q
				}
			}
			http.Redirect(w, r, u, http.StatusMovedPermanently)
		})
	}
	r.Get("/classic", func(w http.ResponseWriter, _ *http.Request) { send(w, 200, "text/html; charset=utf-8", s.classic) })
	for path, fn := range map[string]func(query) (any, error){
		"/api/orgs": s.apiOrgs, "/api/env": s.apiEnv, "/api/run": s.apiRun, "/api/log": s.apiLog,
		"/api/hostfile": s.apiHostfile, "/api/ipinfo": s.apiIPInfo, "/api/prompt": s.apiPrompt,
		"/api/i18n": s.apiI18n, "/api/tree": s.apiTree, "/api/node": s.apiNode, "/api/lens": s.apiLens, "/api/history": s.apiHistory,
	} {
		r.Get(path, s.api(fn))
	}
	r.Get("/api/scan-options", s.api(s.apiScanOptions))
	r.Get("/api/session", s.apiSession)
	r.Get("/api/jobs", s.apiJobs)
	r.Get("/api/db", s.apiDB)
	r.Get("/api/db/size", s.apiDBSize)
	r.Get("/api/setup/discover", s.apiSetupDiscover)
	r.With(s.csrfCheck).Post("/api/db/update", s.apiDBUpdate)
	r.With(s.csrfCheck).Post("/api/scan", s.apiScan)
	r.With(s.csrfCheck).Post("/api/setup", s.apiSetup)
	r.With(s.csrfCheck).Post("/api/setup/check", s.apiSetupCheck)
	r.With(s.csrfCheck).Post("/api/setup/parse", s.apiSetupParse)
	r.With(s.csrfCheck).Post("/api/setup/add", s.apiSetupAdd)
	r.With(s.csrfCheck).Post("/api/jobs/{id}/cancel", s.apiCancel)
	return r
}

func (s *Server) api(fn func(query) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := fn(parseQS(r.URL.RawQuery))
		var nf notFound
		switch {
		case errors.As(err, &nf):
			b, _ := json.Marshal(map[string]string{"error": nf.Error()})
			send(w, 404, "application/json", b)
			return
		case errors.Is(err, errNoPrompt):
			send(w, 501, "application/json", []byte(`{"error": "prompt builder not configured"}`))
			return
		case err != nil:
			s.log.Printf("dashboard: %s: %v", r.URL.RequestURI(), err)
			send(w, 500, "application/json", []byte(`{"error": "internal error"}`))
			return
		}
		b, err := pyfmt.Marshal(v)
		if err != nil {
			s.log.Printf("dashboard: %s: %v", r.URL.RequestURI(), err)
			send(w, 500, "application/json", []byte(`{"error": "internal error"}`))
			return
		}
		send(w, 200, "application/json; charset=utf-8", b)
	}
}

func send(w http.ResponseWriter, code int, ctype string, body []byte) {
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// headers on every response, errors included: no caching (reports change under the page), no sniffing, and
// a CSP that keeps the page from loading or sending anything elsewhere.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}

// methods: GET everywhere, POST to the scan endpoints only.
func methods(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		post := r.Method == http.MethodPost && (r.URL.Path == "/api/scan" || r.URL.Path == "/api/db/update" ||
			r.URL.Path == "/api/setup" || r.URL.Path == "/api/setup/check" || r.URL.Path == "/api/setup/parse" || r.URL.Path == "/api/setup/add" ||
			strings.HasPrefix(r.URL.Path, "/api/jobs/") && strings.HasSuffix(r.URL.Path, "/cancel"))
		if r.Method != http.MethodGet && !post {
			send(w, 501, "text/plain", []byte("unsupported method"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tokenCookie: where the access token lives in the browser after the first ?token= visit.
const tokenCookie = "kanareika_token"

// loopbackHost: the Host header names this machine (localhost, 127.x, ::1), with or without a port.
func loopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

func same(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// guard: the Host check on a loopback bind, and the access token when one is set.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.local.Load() && !loopbackHost(r.Host) {
			send(w, http.StatusMisdirectedRequest, "text/plain", []byte("this dashboard answers on localhost only"))
			return
		}
		if s.token == "" {
			next.ServeHTTP(w, r)
			return
		}
		if q := r.URL.Query().Get("token"); q != "" && r.Method == http.MethodGet {
			if !same(q, s.token) {
				send(w, http.StatusUnauthorized, "text/plain", []byte("wrong token"))
				return
			}
			http.SetCookie(w, &http.Cookie{Name: tokenCookie, Value: s.token, Path: "/", HttpOnly: true,
				SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if c, err := r.Cookie(tokenCookie); err == nil && got == "" {
			got = c.Value
		}
		if !same(got, s.token) {
			send(w, http.StatusUnauthorized, "text/plain", []byte("token required: open the URL kanareika serve printed"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfCheck: a state-changing request must come from the dashboard page itself: JSON, the page's CSRF token in
// X-Kanareika-CSRF (other sites can't read it), and no foreign Origin.
func (s *Server) csrfCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			u, err := url.Parse(o)
			if err != nil || u.Host != r.Host {
				sendErr(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || !same(r.Header.Get("X-Kanareika-CSRF"), s.csrf) {
			sendErr(w, http.StatusForbidden, "missing or wrong CSRF token: reload the page")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// errorLog: the dashboard logs nothing per request (it is polled every few seconds), only server errors.
func (s *Server) errorLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		next.ServeHTTP(ww, r)
		if ww.Status() >= 500 && ww.Status() != 501 {
			s.log.Printf("dashboard: %s %s -> %d (%s)", r.Method, r.URL.RequestURI(), ww.Status(), time.Since(start))
		}
	})
}

func parseAddr(s string) (netip.Addr, error) { return netip.ParseAddr(s) }

// Serve listens on host:port and serves until ctx is cancelled, then shuts down gracefully: in-flight requests
// get 10s, scans started here are cancelled (their runs are marked interrupted). out receives the startup lines.
func (s *Server) Serve(ctx context.Context, host string, port int, out io.Writer) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return s.serve(ctx, ln, host, out)
}

func (s *Server) serve(ctx context.Context, ln net.Listener, host string, out io.Writer) error {
	s.local.Store(loopbackHost(host))
	if !s.local.Load() && s.token == "" && (s.jobs != nil || s.db != nil) {
		s.jobs, s.db = nil, nil
		fmt.Fprintln(out, "note: listening beyond localhost without --token: the dashboard is read-only (no scans, no DB updates)")
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	shown := host
	if s.local.Load() || host == "" || host == "0.0.0.0" || host == "::" {
		shown = "127.0.0.1"
	}
	link := "http://" + net.JoinHostPort(shown, port) + "/"
	if s.token != "" {
		link += "?token=" + url.QueryEscape(s.token)
	}
	mode := "scans can be started from the page"
	if s.jobs == nil {
		mode = "read-only"
	}
	fmt.Fprintf(out, "kanareika dashboard on %s (%s; Ctrl+C stops it)\n", link, mode)
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, ErrorLog: s.log}
	done := make(chan error, 1)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done <- srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	err := <-done
	if s.jobs != nil {
		s.jobs.stop()
	}
	if s.db != nil {
		s.db.stop()
	}
	return err
}
