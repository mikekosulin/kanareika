package hardening

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
)

// seqRunner answers the calls in order: an output, or an error when the entry starts with "ERR:".
type seqRunner struct {
	out   []string
	calls int
}

func (r *seqRunner) Run(context.Context, config.Host, string, time.Duration, bool) (string, error) {
	r.calls++
	if r.calls > len(r.out) {
		return "", errors.New("unexpected call")
	}
	if s := r.out[r.calls-1]; strings.HasPrefix(s, "ERR:") {
		return "", errors.New(s[4:])
	}
	return r.out[r.calls-1], nil
}

func (r *seqRunner) Stream(context.Context, config.Host, string, io.Writer, int64, time.Duration, func(int64)) (int64, error) {
	return 0, errors.New("no stream")
}

func TestRunErrors(t *testing.T) {
	r := &seqRunner{out: []string{"ERR:ssh down"}}
	if f, err := Run(&check.Ctx{Context: context.Background(), SSH: r}, config.Host{Name: "web-01"}, nil, t.TempDir(),
		check.Facts{}); err == nil || f != nil || err.Error() != "ssh down" {
		t.Fatalf("got %v, %v", f, err)
	}
	r = &seqRunner{out: []string{"reboot_required=yes\n"}}
	out := filepath.Join(t.TempDir(), "missing")
	if f, err := Run(&check.Ctx{Context: context.Background(), SSH: r}, config.Host{Name: "web-01"}, nil, out,
		check.Facts{}); err == nil || f != nil || !strings.Contains(err.Error(), "hardening.txt") {
		t.Fatalf("got %v, %v", f, err)
	}
}
