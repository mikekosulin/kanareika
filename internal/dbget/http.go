package dbget

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// UserAgent: what every download announces (nothing else is sent: no IDs, no telemetry). priority.SetVersion puts
// the running version in it.
var UserAgent = "github.com/mikekosulin/kanareika (+vulnerability audit)"

// Timeout: connecting, the TLS handshake and waiting for the response headers, each. Idle: the longest a body may
// stall. Tests shorten them.
var (
	Timeout = 30 * time.Second
	Idle    = 60 * time.Second
)

// Transport: nil for the default; tests set their TLS server's (it trusts the test certificate).
var Transport http.RoundTripper

// Client: an HTTP client with the timeouts above (proxies from the environment, as curl and trivy use them).
func Client() *http.Client {
	if Transport != nil {
		return &http.Client{Transport: Transport}
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: Timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   Timeout,
		ResponseHeaderTimeout: Timeout,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
	}}
}

// Get: a GET whose 2xx response body must deliver data at least every Idle; other statuses are a *StatusError.
// hdr: extra request headers (Accept, Authorization).
func Get(ctx context.Context, rawURL string, hdr http.Header) (*http.Response, error) {
	return GetIdle(ctx, rawURL, hdr, Idle)
}

// GetIdle: Get with its own idle limit. A User-Agent in hdr replaces UserAgent.
func GetIdle(parent context.Context, rawURL string, hdr http.Header, idle time.Duration) (*http.Response, error) {
	ctx, cancel := context.WithCancel(parent)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	for k, v := range hdr {
		req.Header[http.CanonicalHeaderKey(k)] = v
	}
	resp, err := Client().Do(req)
	if err != nil {
		cancel()
		return nil, timeoutOf(parent, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cancel()
		return nil, &StatusError{Code: resp.StatusCode, Host: req.URL.Hostname(), RetryAfter: resp.Header.Get("Retry-After"),
			Challenge: resp.Header.Get("WWW-Authenticate")}
	}
	resp.Body = newIdleBody(resp.Body, idle, cancel)
	return resp, nil
}

// timeoutOf: a transport timeout as a *TimeoutError: the configured limit fired, not the caller's deadline.
func timeoutOf(parent context.Context, err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() && parent.Err() == nil {
		return &TimeoutError{What: "timed out", After: Timeout, Err: err}
	}
	return err
}

// idleBody: a body that fails with a *TimeoutError when no data came for idle.
type idleBody struct {
	io.ReadCloser
	timer  *time.Timer
	idle   time.Duration
	cancel context.CancelFunc
	fired  chan struct{}
	once   sync.Once
}

func newIdleBody(rc io.ReadCloser, idle time.Duration, cancel context.CancelFunc) *idleBody {
	b := &idleBody{ReadCloser: rc, idle: idle, cancel: cancel, fired: make(chan struct{})}
	b.timer = time.AfterFunc(idle, func() { b.once.Do(func() { close(b.fired) }); cancel() })
	return b
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	select {
	case <-b.fired:
		if err != nil && err != io.EOF {
			return n, &TimeoutError{What: "no data", After: b.idle, Err: err}
		}
	default:
		b.timer.Reset(b.idle)
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	b.cancel()
	return b.ReadCloser.Close()
}

// StatusError: the server answered with a status other than 2xx.
type StatusError struct {
	Code       int
	Host       string
	RetryAfter string
	Challenge  string // WWW-Authenticate of a 401
}

func (e *StatusError) Error() string { return e.Host + ": " + e.Reason() }

// Reason: "too many requests (429)", "unauthorized (401)", ...
func (e *StatusError) Reason() string {
	var s string
	switch c := e.Code; {
	case c == 401:
		s = "unauthorized"
	case c == 403:
		s = "forbidden"
	case c == 404:
		s = "not found"
	case c == 407:
		s = "proxy authentication required"
	case c == 429:
		s = "too many requests"
		if e.RetryAfter != "" {
			if n, err := strconv.Atoi(e.RetryAfter); err == nil {
				return fmt.Sprintf("too many requests (429), retry after %s", Seconds(time.Duration(n)*time.Second))
			}
		}
	case c >= 500:
		s = "server error"
	default:
		s = strings.ToLower(http.StatusText(c))
		if s == "" {
			s = "HTTP status"
		}
	}
	return fmt.Sprintf("%s (%d)", s, e.Code)
}

// TimeoutError: a limit fired: "timed out after 30 s", "no data for 60 s".
type TimeoutError struct {
	What  string // "timed out", "no data"
	After time.Duration
	Err   error
}

func (e *TimeoutError) Error() string { return e.Reason() }
func (e *TimeoutError) Unwrap() error { return e.Err }
func (e *TimeoutError) Reason() string {
	if e.What == "no data" {
		return "no data for " + Seconds(e.After)
	}
	return e.What + " after " + Seconds(e.After)
}

// NoSpaceError: the disk filled up; Need: bytes the download needs free (0: unknown).
type NoSpaceError struct {
	Need int64
	Err  error
}

func (e *NoSpaceError) Error() string { return e.Reason() }
func (e *NoSpaceError) Unwrap() error { return e.Err }
func (e *NoSpaceError) Reason() string {
	if e.Need > 0 {
		return "no space left on device: " + Size(e.Need) + " free needed"
	}
	return "no space left on device"
}

// NoSpace: err as a *NoSpaceError when the disk is full, else err.
func NoSpace(err error, need int64) error {
	if errors.Is(err, syscall.ENOSPC) {
		return &NoSpaceError{need, err}
	}
	return err
}

// ChecksumError: the bytes are not what the registry published.
type ChecksumError struct{ Want, Got string }

func (e *ChecksumError) Error() string { return e.Reason() }
func (e *ChecksumError) Reason() string {
	return fmt.Sprintf("sha256 mismatch: got %s, expected %s (corrupted download)", short(e.Got), short(e.Want))
}

func short(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

type reasoner interface{ Reason() string }

// Reason: err as a person reads it: "too many requests (429)", "timed out after 30 s", "TLS: certificate signed by
// unknown authority (a proxy?)", "no space left on device: 2.1 GB free needed", "unauthorized (401)".
func Reason(err error) string {
	if err == nil {
		return ""
	}
	if r, ok := err.(reasoner); ok {
		return r.Reason()
	}
	var (
		status   *StatusError
		timeout  *TimeoutError
		nospace  *NoSpaceError
		checksum *ChecksumError
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
		record   tls.RecordHeaderError
		dns      *net.DNSError
		ne       net.Error
	)
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.As(err, &status):
		return status.Reason()
	case errors.As(err, &timeout):
		return timeout.Reason()
	case errors.As(err, &nospace):
		return nospace.Reason()
	case errors.Is(err, syscall.ENOSPC):
		return "no space left on device"
	case errors.As(err, &checksum):
		return checksum.Reason()
	case errors.As(err, &unknown):
		return "TLS: certificate signed by unknown authority (a proxy?)"
	case errors.As(err, &hostname):
		return "TLS: the certificate is not for " + hostname.Host + " (a proxy?)"
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired {
			return "TLS: certificate expired or not yet valid (is the clock right?)"
		}
		return "TLS: invalid certificate (a proxy?)"
	case errors.As(err, &record), strings.Contains(err.Error(), "server gave HTTP response to HTTPS client"):
		return "TLS: the server does not speak TLS"
	case errors.As(err, &dns):
		return "cannot resolve " + dns.Name + " (offline? DNS?)"
	case refused(err):
		return "connection refused"
	case reset(err):
		return "connection reset"
	case unreachable(err):
		return "network unreachable (offline?)"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "connection closed mid-download"
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error() // without `Get "https://…":`
	}
	return err.Error()
}

// Seconds: "30 s", "200 ms", "2 min 5 s".
func Seconds(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Round(time.Second).Seconds()))
	}
	d = d.Round(time.Second)
	m, s := int(d.Minutes()), int(d.Seconds())%60
	if s == 0 {
		return fmt.Sprintf("%d min", m)
	}
	return fmt.Sprintf("%d min %d s", m, s)
}

// Size: 2.1 GB, 139 MB, 12 KB (decimal, as registries and disks count).
func Size(n int64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%d MB", (n+5e5)/1e6)
	case n > 0:
		return fmt.Sprintf("%d KB", max(1, (n+500)/1e3))
	}
	return "0 KB"
}
