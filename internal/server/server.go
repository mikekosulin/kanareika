// Package server is the local dashboard (`kanareika serve`): web/index.html plus a read-only JSON API over
// reports/ and orgs/. It binds to localhost by default (reports hold addresses and vulnerabilities).
//
// The API is the one the Python dashboard served, path for path and field for field, so the page (embedded
// unchanged) works against either.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
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
	Prompt PromptFunc  // nil: /api/prompt answers 501
	Log    *log.Logger // errors and panics; nil: the standard logger
}

// Server holds the API state: org configs (reloaded by /api/orgs) and the last few views.
type Server struct {
	paths  config.Paths
	prompt PromptFunc
	log    *log.Logger
	state  atomic.Pointer[orgState]
	page   []byte // index.html with the UI strings filled in
	logo   []byte

	mu    sync.Mutex // view builds and current/ updates, one at a time (each can take seconds on big runs)
	views []cachedView
}

type cachedView struct {
	key  viewKey
	body []byte
}

// New loads the org configs and prepares the page; config errors are not fatal (they are shown in the page).
func New(o Options) (*Server, error) {
	s := &Server{paths: o.Paths, prompt: o.Prompt, log: o.Log}
	if s.log == nil {
		s.log = log.Default()
	}
	var err error
	if s.page, err = page(); err != nil {
		return nil, err
	}
	if s.logo, err = fs.ReadFile(assets.Web(), "logo.png"); err != nil {
		return nil, err
	}
	s.reload()
	return s, nil
}

// page: index.html with the /*I18N_UI*/{} placeholder replaced by the UI strings of every language, encoded
// as Python's json.dumps did ("</" escaped so a string cannot close the script tag).
func page() ([]byte, error) {
	html, err := fs.ReadFile(assets.Web(), "index.html")
	if err != nil {
		return nil, err
	}
	ui, err := uiJSON()
	if err != nil {
		return nil, err
	}
	ui = strings.ReplaceAll(ui, "</", `<\/`)
	return bytes.ReplaceAll(html, []byte("/*I18N_UI*/{}"), []byte(ui)), nil
}

// uiJSON: {lang: ui} for the locales that have UI strings, in file name order, keys as in the files.
func uiJSON() (string, error) {
	files, err := fs.Glob(assets.Locales(), "*.json")
	if err != nil {
		return "", err
	}
	all := pyfmt.Obj{}
	for _, f := range files { // Glob sorts
		b, err := fs.ReadFile(assets.Locales(), f)
		if err != nil {
			return "", err
		}
		var l struct {
			UI json.RawMessage `json:"ui"`
		}
		if err := json.Unmarshal(b, &l); err != nil {
			return "", fmt.Errorf("locales/%s: %w", f, err)
		}
		if ui, _ := pyfmt.Loads(string(l.UI)); pyfmt.Truthy(ui) {
			all = append(all, pyfmt.KV{K: strings.TrimSuffix(f, ".json"), V: ui})
		}
	}
	b, err := pyfmt.DumpsLine(all, false)
	return string(b), err
}

// Handler: the routes. Only GET is served (the API is read-only); other methods get 501 as before.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer, headers, s.errorLog, getOnly)
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) { send(w, 404, "text/plain", []byte("not found")) })
	r.Get("/logo.png", func(w http.ResponseWriter, _ *http.Request) { send(w, 200, "image/png", s.logo) })
	index := func(w http.ResponseWriter, _ *http.Request) { send(w, 200, "text/html; charset=utf-8", s.page) }
	r.Get("/", index)
	r.Get("/index.html", index)
	for path, fn := range map[string]func(query) (any, error){
		"/api/orgs": s.apiOrgs, "/api/env": s.apiEnv, "/api/run": s.apiRun, "/api/log": s.apiLog,
		"/api/hostfile": s.apiHostfile, "/api/ipinfo": s.apiIPInfo, "/api/prompt": s.apiPrompt,
		"/api/i18n": s.apiI18n,
	} {
		r.Get(path, s.api(fn))
	}
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

func getOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			send(w, 501, "text/plain", []byte("unsupported method"))
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

// Serve listens on host:port and serves until ctx is cancelled, then shuts down gracefully (in-flight
// requests get 10s). out receives the startup line.
func (s *Server) Serve(ctx context.Context, host string, port int, out io.Writer) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "kanareika dashboard on http://%s:%d (published as http://127.0.0.1:%d)\n", host, port, port)
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
	return <-done
}
