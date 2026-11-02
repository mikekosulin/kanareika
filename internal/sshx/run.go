package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/mikekosulin/kanareika/internal/config"
)

// ProgressEvery: how often Stream reports progress while data flows (ssh.py's every_s).
var ProgressEvery = 20 * time.Second

// Run executes command and returns its stdout. With check, a non-zero exit is an error carrying the stderr tail.
// Like ssh.py, exit codes follow the ssh client: a remote signal or a lost connection is exit 255. Unlike ssh.py,
// failing to connect at all is an error even without check (ssh.py returned "" then).
func (o *OrgSSH) Run(ctx context.Context, h config.Host, command string, timeout time.Duration, check bool) (string, error) {
	s, err := o.session(ctx, h)
	if err != nil {
		return "", err
	}
	defer s.Close()
	var out bytes.Buffer
	stderr := &tail{}
	s.Stdout, s.Stderr = &out, stderr
	code, err := wait(ctx, h, s, command, timeout, nil, stderr)
	if err != nil {
		return "", err
	}
	if check && code != 0 {
		return "", exitError(h, code, stderr)
	}
	return strings.ToValidUTF8(out.String(), "�"), nil
}

// Stream runs command and copies its stdout to w; it aborts when the output exceeds maxBytes.
// progress(mb) is called at most every ProgressEvery while data flows. A non-zero exit is only an error when
// nothing was written (as in ssh.py: tools like dpkg-query exit 1 on warnings but the output is still good).
func (o *OrgSSH) Stream(ctx context.Context, h config.Host, command string, w io.Writer, maxBytes int64,
	timeout time.Duration, progress func(mb int64)) (int64, error) {
	s, err := o.session(ctx, h)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	lw := &limitWriter{w: w, max: maxBytes, progress: progress, last: time.Now(), over: make(chan struct{})}
	stderr := &tail{}
	s.Stdout, s.Stderr = lw, stderr
	code, err := wait(ctx, h, s, command, timeout, lw.over, stderr)
	total, werr := lw.state()
	switch {
	case errors.Is(werr, errTooBig):
		return total, fmt.Errorf("%s: output exceeds %d MB, aborted", h.Name, maxBytes>>20)
	case werr != nil:
		return total, fmt.Errorf("%s: write: %w", h.Name, werr)
	case err != nil:
		return total, err
	}
	if code != 0 && total == 0 {
		return 0, exitError(h, code, stderr)
	}
	return total, nil
}

// session opens a channel on the host's connection; a cached connection that died since is replaced once.
func (o *OrgSSH) session(ctx context.Context, h config.Host) (*ssh.Session, error) {
	if err := o.guard(h); err != nil {
		return nil, err
	}
	t := hostTarget(h)
	for attempt := 0; ; attempt++ {
		c, err := o.client(ctx, t, 0)
		if err != nil {
			return nil, err
		}
		s, err := c.NewSession()
		if err == nil {
			return s, nil
		}
		o.forget(t.key, c)
		if attempt > 0 {
			return nil, fmt.Errorf("%s: %w", h.Name, err)
		}
	}
}

// forget drops c from the cache (if it is still the cached one) and closes it.
func (o *OrgSSH) forget(key string, c *ssh.Client) {
	c.Close()
	o.mu.Lock()
	e := o.conns[key]
	o.mu.Unlock()
	if e == nil {
		return
	}
	e.mu.Lock()
	if e.client == c {
		e.client = nil
	}
	e.mu.Unlock()
}

var errTooBig = errors.New("output too big")

// wait starts command and waits for its exit code. A timeout, a cancelled ctx or abort (closed by the writer)
// kill the session: SIGKILL where sshd supports signals, and the channel is closed in any case.
func wait(ctx context.Context, h config.Host, s *ssh.Session, command string, timeout time.Duration,
	abort <-chan struct{}, stderr *tail) (int, error) {
	if err := s.Start(command); err != nil {
		return 0, fmt.Errorf("%s: %w", h.Name, err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	var expired <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		expired = t.C
	}
	kill := func() {
		s.Signal(ssh.SIGKILL)
		s.Close()
	}
	select {
	case err := <-done:
		return exitCode(err, stderr)
	case <-expired:
		kill()
		return 0, fmt.Errorf("%s: timeout", h.Name)
	case <-ctx.Done():
		kill()
		return 0, fmt.Errorf("%s: %w", h.Name, ctx.Err())
	case <-abort:
		kill()
		return 0, errTooBig
	}
}

// exitCode maps the session result to an ssh(1)-style exit code; transport errors stay errors.
func exitCode(err error, stderr *tail) (int, error) {
	var ee *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		if ee.Signal() != "" { // ssh(1) exits 255 when the remote command dies of a signal
			return 255, nil
		}
		return ee.ExitStatus(), nil
	case errors.As(err, &missing):
		fmt.Fprint(stderr, "\nconnection closed without exit status")
		return 255, nil
	case errors.Is(err, errTooBig):
		return 0, err
	}
	return 0, err
}

func exitError(h config.Host, code int, stderr *tail) error {
	err := []rune(strings.TrimSpace(strings.ToValidUTF8(stderr.String(), "�")))
	if len(err) > 500 {
		err = err[len(err)-500:]
	}
	return fmt.Errorf("%s: exit %d: %s", h.Name, code, string(err))
}

// tail keeps the last few KB of stderr: enough for the 500-character error message, bounded for chatty commands.
type tail struct {
	mu  sync.Mutex
	buf []byte
}

const tailMax = 8 << 10

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > tailMax {
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-tailMax:]...)
	}
	return len(p), nil
}

func (t *tail) String() string { t.mu.Lock(); defer t.mu.Unlock(); return string(t.buf) }

// limitWriter counts Stream output, refuses the write that would cross max and reports progress. The first failed
// write closes over, so wait kills the command instead of leaving it blocked on a full channel window.
type limitWriter struct {
	w        io.Writer
	max      int64
	progress func(mb int64)
	last     time.Time
	over     chan struct{}
	mu       sync.Mutex
	total    int64
	err      error
}

func (l *limitWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return 0, l.err
	}
	if l.total+int64(len(p)) > l.max {
		return 0, l.fail(errTooBig)
	}
	n, err := l.w.Write(p)
	l.total += int64(n)
	if err != nil {
		return n, l.fail(err)
	}
	if l.progress != nil && time.Since(l.last) >= ProgressEvery {
		l.last = time.Now()
		l.progress(l.total >> 20)
	}
	return n, nil
}

func (l *limitWriter) fail(err error) error {
	l.err = err
	close(l.over)
	return err
}

func (l *limitWriter) state() (int64, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.total, l.err }
