package swarm

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/priv"
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

const manager = `{"ControlAvailable":true}`

func TestRunErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	for _, tc := range []struct {
		name, out, want string
		outputs         []string
	}{
		{"info fails", "", "ssh down", []string{"ERR:ssh down"}},
		{"empty info", "", "not a swarm manager", []string{""}},
		{"bad info", "", "", []string{"{"}},
		{"info not object", "", "not a JSON object", []string{"[1]"}},
		{"nodes fail", "", "nodes down", []string{manager, "ERR:nodes down"}},
		{"services fail", "", "services down", []string{manager, "", "ERR:services down"}},
		{"bad nodes", "", "", []string{manager, "{\n", ""}},
		{"bad services", "", "", []string{manager, `{"Hostname":"web-01"}`, "nope"}},
		{"unwritable", missing, "", []string{manager, "", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &seqRunner{out: tc.outputs}
			out := tc.out
			if out == "" {
				out = t.TempDir()
			}
			ctx := &check.Ctx{Context: context.Background(), SSH: r, Log: func(string, ...any) { t.Error("logged") }}
			f, err := Run(ctx, config.Host{Name: "web-01", Privilege: "sudo"}, nil, out, check.Facts{})
			if err == nil || f != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, %v; want error %q", f, err, tc.want)
			}
			if r.calls != len(tc.outputs) {
				t.Errorf("%d calls, want %d", r.calls, len(tc.outputs))
			}
		})
	}
}

// An empty swarm: swarm.json written, no findings.
func TestRunNoNodes(t *testing.T) {
	out := t.TempDir()
	ctx := &check.Ctx{Context: context.Background(), SSH: &seqRunner{out: []string{manager, "\n  \n", ""}},
		Log: func(string, ...any) {}}
	f, err := Run(ctx, config.Host{Name: "web-01"}, nil, out, check.Facts{})
	if err != nil || len(f) != 0 {
		t.Fatalf("got %v, %v", f, err)
	}
	if _, err := os.Stat(filepath.Join(out, "swarm.json")); err != nil {
		t.Fatal(err)
	}
}

// The privileged op missing from the registry: the command cannot be built, nothing runs.
func TestRunUnknownOp(t *testing.T) {
	old, ok := priv.Ops["swarm-info"]
	delete(priv.Ops, "swarm-info")
	defer func() {
		if ok {
			priv.Ops["swarm-info"] = old
		}
	}()
	r := &seqRunner{}
	ctx := &check.Ctx{Context: context.Background(), SSH: r}
	if _, err := Run(ctx, config.Host{Name: "web-01"}, nil, t.TempDir(), check.Facts{}); err == nil ||
		!strings.Contains(err.Error(), "unknown privileged op") || r.calls != 0 {
		t.Fatalf("err %v, %d calls", err, r.calls)
	}
}
