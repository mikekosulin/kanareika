package k8s

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
)

// brokenReport: a report stream that fails partway, recording whether it was closed.
type brokenReport struct {
	r      io.Reader
	closed bool
}

func (b *brokenReport) Read(p []byte) (int, error) {
	if n, err := b.r.Read(p); err != io.EOF {
		return n, err
	}
	return 0, errors.New("report stream cut")
}

func (b *brokenReport) Close() error { b.closed = true; return nil }

// A cluster's report that can't be read to the end ends the module with the read error; the stream is closed.
func TestRunReportReadError(t *testing.T) {
	cluster := []map[string]any{{"name": "prod", "env": "production", "kubeconfig": "acme/kubeconfig-prod"}}
	org, _ := loadOrg(t, cluster, map[string]string{"acme/kubeconfig-prod": "apiVersion: v1\n"})
	rep := &brokenReport{r: strings.NewReader(`{"Resources":[`)}
	old := trivyRun
	t.Cleanup(func() { trivyRun = old })
	trivyRun = func(context.Context, []string, string, time.Duration) (io.ReadCloser, error) { return rep, nil }
	ctx := &check.Ctx{Context: context.Background(), Org: org, RunDir: t.TempDir(), Log: func(string, ...any) {}}
	f, err := Run(ctx, nil, "production")
	if err == nil || err.Error() != "report stream cut" || f != nil {
		t.Errorf("got %v, %v", f, err)
	}
	if !rep.closed {
		t.Error("report not closed")
	}
}
