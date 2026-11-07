package mongo

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
	for _, tc := range []struct {
		name     string
		outputs  []string
		unwrite  bool
		wantErr  string
		wantCall int
	}{
		{"version fails", []string{"ERR:ssh down"}, false, "ssh down", 1},
		{"listen fails", []string{"db version v7.0.2", "ERR:listen down"}, false, "listen down", 2},
		{"unwritable", []string{"db version v7.0.2", ""}, true, "mongo.txt", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &seqRunner{out: tc.outputs}
			out := t.TempDir()
			if tc.unwrite {
				out = filepath.Join(out, "missing")
			}
			f, err := Run(&check.Ctx{Context: context.Background(), SSH: r}, config.Host{Name: "web-01"}, nil, out,
				check.Facts{})
			if err == nil || f != nil || !strings.Contains(err.Error(), tc.wantErr) || r.calls != tc.wantCall {
				t.Fatalf("got %v, %v after %d calls", f, err, r.calls)
			}
		})
	}
}
