package health

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
	"github.com/mikekosulin/kanareika/internal/finding"
	"github.com/mikekosulin/kanareika/internal/i18n"
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
		name, raw, want string
		unwritable      bool
	}{
		{"ssh fails", "ERR:ssh down", "ssh down", false},
		{"bad output", "@@df@@\nFilesystem Size Used Avail Use% Mounted\n/dev/sda1 1G 1G 0 x% /\n", "invalid literal", false},
		{"unwritable", "", "health.json", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := t.TempDir()
			if tc.unwritable {
				out = filepath.Join(out, "missing")
			}
			ctx := &check.Ctx{Context: context.Background(), SSH: &seqRunner{out: []string{tc.raw}},
				Log: func(string, ...any) { t.Error("logged") }}
			f, err := Run(ctx, config.Host{Name: "web-01"}, nil, out, check.Facts{})
			if err == nil || f != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, %v; want %q", f, err, tc.want)
			}
		})
	}
}

// Numbers that do not parse fail the run, as Python's int() / float() raised.
func TestAnalyzeErrors(t *testing.T) {
	const dfHead = "Filesystem Size Used Avail Use% Mounted\n"
	for name, raw := range map[string]string{
		"df":              "@@df@@\n" + dfHead + "/dev/sda1 1G 1G 0 x% /\n",
		"dfi":             "@@dfi@@\n" + dfHead + "/dev/sda1 1 1 0 1x% /\n",
		"mem total":       "@@mem@@\nMem: x 1 1 1 1 1\n",
		"mem available":   "@@mem@@\nMem: 100 1 1 1 1 x\n",
		"swap total":      "@@mem@@\nSwap: x 1 1\n",
		"swap used":       "@@mem@@\nSwap: 100 x 1\n",
		"load1":           "@@load@@\nx 0.1 0.2 1/100 1234 4\n",
		"load15":          "@@load@@\n0.1 0.1 x 1/100 1234 4\n",
		"chrony stratum":  "@@chrony@@\nStratum         : 99999999999999999999999\n",
		"chrony offset":   "@@chrony@@\nSystem time     : 1.2.3 seconds fast of NTP time\n",
		"ntpq offset":     "@@ntpq@@\n*192.0.2.10 .GPS. 1 u 10 64 377 0.5 x 0.1\n",
		"timesyncd offst": "@@timesyncd@@\nServer: 192.0.2.10\nOffset: +1.2.3ms\n",
	} {
		if f, data, err := analyze(config.Host{Name: "web-01"}, raw, 0); err == nil || f != nil || data != nil {
			t.Errorf("%s: got %v %v %v", name, f, data, err)
		}
	}
}

func TestParseTimeZoneinfoAndActiveService(t *testing.T) {
	ti, err := parseTime(map[string]string{
		"time":    "1700000000.5\n/etc/localtime -> ../usr/share/zoneinfo/Europe/Berlin",
		"timesvc": "chronyd active",
	}, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	o := ti.obj()
	if o.Get("timezone") != "Europe/Berlin" || o.Get("service") != "chronyd" || o.Get("synced") != "unknown" ||
		o.Get("skew_s") != 0.5 {
		t.Errorf("got %v", o)
	}
}

func TestFindingDetail(t *testing.T) {
	h := config.Host{Org: "acme", Name: "web-01", Group: "web", Exposure: 2}
	long := strings.Repeat("x", 400)
	f := Finding(h, "access", finding.Misconfig, "id", "LOW", i18n.Plain("t"), i18n.Plain(long))
	if f.Module != "access" || f.Host != "web-01" || f.Kind != finding.Misconfig || len(f.Target) != 300 {
		t.Errorf("plain detail: %+v", f)
	}
	f = Finding(h, "access", finding.Misconfig, "id", "LOW", i18n.Plain("t"), i18n.Msg("k", map[string]any{"v": long}))
	if f.TargetMsg != "k" || f.TargetArgs["v"] != long {
		t.Errorf("message detail: %+v", f)
	}
}
