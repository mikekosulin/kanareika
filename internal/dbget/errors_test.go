package dbget

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestReasonsWrapped: an error wrapped on its way up ("pull: …") still reads as its reason; a deadline that fired on
// a connection is "timed out"; what a URL error says is kept without its `Get "…":`.
func TestReasonsWrapped(t *testing.T) {
	for err, want := range map[error]string{
		fmt.Errorf("pull: %w", &StatusError{Code: 404, Host: "ghcr.io"}):                           "not found (404)",
		fmt.Errorf("pull: %w", &TimeoutError{What: "no data", After: time.Minute}):                 "no data for 1 min",
		fmt.Errorf("pull: %w", &NoSpaceError{Need: 2e9}):                                           "no space left on device: 2.0 GB free needed",
		fmt.Errorf("pull: %w", &ChecksumError{Want: "sha256:0123456789abcdef0", Got: "sha256:ab"}): "sha256 mismatch: got ab, expected 0123456789ab (corrupted download)",
		fmt.Errorf("read: %w", os.ErrDeadlineExceeded):                                             "timed out",
	} {
		if got := Reason(err); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
	resp, err := Get(context.Background(), "ftp://mirror.example/db.tar.gz", nil) // fails before any connection
	if resp != nil {
		resp.Body.Close()
	}
	if got := Reason(err); got != `unsupported protocol scheme "ftp"` {
		t.Fatal(got)
	}
	if got := (&StatusError{Code: 499}).Reason(); got != "HTTP status (499)" { // a status Go has no words for
		t.Fatal(got)
	}
}

// TestErrorTypes: the error types read as their reasons, and errors.Is sees through them to the cause (a full
// disk stays ENOSPC under "kept").
func TestErrorTypes(t *testing.T) {
	timeout := &TimeoutError{What: "timed out", After: 30 * time.Second, Err: context.DeadlineExceeded}
	sum := &ChecksumError{Want: "sha256:aaaaaaaaaaaaaaaa", Got: "sha256:bbbbbbbbbbbbbbbb"}
	full := NoSpace(&os.PathError{Op: "write", Path: "/cache/db.tar.gz", Err: syscall.ENOSPC}, 0)
	for err, want := range map[error]string{
		timeout: "timed out after 30 s",
		sum:     "sha256 mismatch: got bbbbbbbbbbbb, expected aaaaaaaaaaaa (corrupted download)",
		full:    "no space left on device",
	} {
		if err.Error() != want {
			t.Errorf("%q, want %q", err.Error(), want)
		}
	}
	if !errors.Is(timeout, context.DeadlineExceeded) || !errors.Is(full, syscall.ENOSPC) {
		t.Fatal("cause hidden")
	}
	kept := Kept(full, "the copy from 2026-11-08 06:00Z (28h0m0s old) stays in use")
	if !errors.Is(kept, syscall.ENOSPC) || kept.Error() != "no space left on device; the copy from 2026-11-08 06:00Z (28h0m0s old) stays in use" {
		t.Fatal(kept)
	}
}

// TestUnknownSize: a download whose size the server did not say has no time left, and the totals have none either
// while it runs (the time left of all is unknown); a download of known size keeps its own.
func TestUnknownSize(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)}
	tr := NewTracker()
	tr.now = c.now
	started, read, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	job := func(total int64) func(context.Context, *Progress) error {
		return func(_ context.Context, p *Progress) error {
			p.Start(total)
			started <- struct{}{}
			<-read
			_, err := io.Copy(io.Discard, p.Reader(strings.NewReader(strings.Repeat("x", 100))))
			started <- struct{}{}
			<-release
			return err
		}
	}
	jobs := []Job{{Name: "db", Label: "DB", Run: job(1000)}, {Name: "kev", Label: "KEV", Run: job(0)}}
	done := make(chan struct{})
	go func() { tr.Run(context.Background(), jobs); close(done) }()
	<-started
	<-started
	c.add(time.Second)
	close(read)
	<-started
	<-started
	s := tr.Snapshot()
	db, kev := s.Items[0], s.Items[1]
	if db.ETA == nil || *db.ETA != 9 || kev.ETA != nil || kev.State != Downloading || kev.Bytes != 100 || kev.Speed != 100 {
		t.Fatalf("%+v %+v", db, kev)
	}
	if s.Totals.ETA != nil || s.Totals.Speed != 200 || s.Totals.Total != 1000 {
		t.Fatalf("%+v", s.Totals)
	}
	close(release)
	<-done
}
