// Package tui is the full-screen terminal interface (`kanareika` with no command, or `kanareika tui`).
//
// It is a client of the same JSON API the web interface uses: in-process (a server built from the local
// working directory, no network) or a remote `kanareika web` (--url, --token). Same data, same rules, same scans.
package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Client talks to the API: GET and POST of JSON.
type Client interface {
	Get(ctx context.Context, path string, out any) error
	Post(ctx context.Context, path string, body, out any) error
}

// APIError: the API answered with an error status; Msg is its "error" field when it has one.
type APIError struct {
	Status int
	Msg    string
}

func (e *APIError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// doer: one HTTP round trip (an in-process handler or the network).
type doer func(*http.Request) (*http.Response, error)

type client struct {
	base  string
	token string // access token (remote --token)
	do    doer

	mu   sync.Mutex
	csrf string
}

// Local: the API of an in-process server (its http.Handler), addressed as localhost.
func Local(h http.Handler) Client {
	return &client{base: "http://localhost", do: func(r *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Result(), nil
	}}
}

// Remote: the API of a running `kanareika web` at base (http://host:port), with its access token if it has one.
func Remote(base, token string) Client {
	hc := &http.Client{Timeout: 30 * time.Second}
	return &client{base: strings.TrimRight(base, "/"), token: token, do: hc.Do}
}

func (c *client) request(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		r.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return r, nil
}

func (c *client) roundTrip(r *http.Request, out any) error {
	resp, err := c.do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error == "" && resp.StatusCode == http.StatusUnauthorized {
			e.Error = "access token required or wrong (--token)"
		}
		return &APIError{Status: resp.StatusCode, Msg: e.Error}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

func (c *client) Get(ctx context.Context, path string, out any) error {
	r, err := c.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	return c.roundTrip(r, out)
}

// Post: with the session's CSRF token (fetched once, and again when the server restarted).
func (c *client) Post(ctx context.Context, path string, body, out any) error {
	if body == nil {
		body = map[string]any{}
	}
	for attempt := 0; ; attempt++ {
		csrf, err := c.session(ctx, attempt > 0)
		if err != nil {
			return err
		}
		r, err := c.request(ctx, http.MethodPost, path, body)
		if err != nil {
			return err
		}
		r.Header.Set("X-Kanareika-CSRF", csrf)
		err = c.roundTrip(r, out)
		var ae *APIError
		if attempt == 0 && errors.As(err, &ae) && ae.Status == http.StatusForbidden && strings.Contains(ae.Msg, "CSRF") {
			continue
		}
		return err
	}
}

func (c *client) session(ctx context.Context, refresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.csrf != "" && !refresh {
		return c.csrf, nil
	}
	var s struct {
		CSRF string `json:"csrf"`
	}
	if err := c.Get(ctx, "/api/session", &s); err != nil {
		return "", err
	}
	c.csrf = s.CSRF
	return c.csrf, nil
}
