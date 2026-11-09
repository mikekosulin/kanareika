package exposure

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check"
	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/pyfmt"
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
		{"unwritable", "", "exposure.json", true},
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

func TestKnownNetsNoOrg(t *testing.T) {
	if got := knownNets(nil); got != nil {
		t.Errorf("got %v", got)
	}
}

func TestNetworkBadBits(t *testing.T) {
	if p, ok := network("192.0.2.1/x"); ok {
		t.Errorf("got %v", p)
	}
}

func TestListenShortLines(t *testing.T) {
	got := listen("tcp LISTEN 0\n\ntcp LISTEN 0 128 192.0.2.5:5432 0.0.0.0:*\n")
	if len(got) != 1 || got[0].addr != "192.0.2.5" || got[0].port != 5432 {
		t.Fatalf("got %+v", got)
	}
}

// The host's own (public) address and one the org file lists are expected, another public one is not; a socket printed without an address
// counts as a wildcard; firewalld that is not running filters nothing.
func TestAnalyzeOwnAddressWildcardFirewalldDown(t *testing.T) {
	raw := "@@addrs@@\neth0 inet 192.0.0.9/24\neth1 inet 192.0.0.10/24\neth2 inet6 2001:4:112::1/64\n" +
		"@@listen@@\ntcp LISTEN 0 128 3306 0.0.0.0:* users:((\"mysqld\",pid=1,fd=3))\n" +
		"@@firewalld_state@@\nnot running\n@@firewalld@@\nnot running\n"
	org := &config.Org{ID: "acme", Hosts: []config.Host{{Name: "web-02", Address: "2001:4:112::1"}}}
	f, data, line := analyze(config.Host{Name: "web-01", Address: "192.0.0.9", Exposure: 1}, org, raw)
	var got []string
	for _, x := range f {
		got = append(got, x.ID+" "+x.Severity+" "+x.Target)
	}
	want := []string{
		"public-ip-unlisted HIGH present on eth1 but missing in orgs/ — the external scan does not check it",
		"listen-public-3306 HIGH tcp *:3306 mysqld",
		"exposure-limited INFO  is not root and kanareika does not use sudo on this host (privilege: none)", // the why; the test host has no user
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings\n got %q\nwant %q", got, want)
	}
	if f[0].Args["ip"] != "192.0.0.10" {
		t.Errorf("unlisted %v", f[0].Args)
	}
	fw, _ := data.Get("firewall").(pyfmt.Obj)
	if fw.Get("firewalld") != "not running" || fw.Get("readable") != false {
		t.Errorf("firewall %v", fw)
	}
	if !strings.Contains(line, "public IPs: 192.0.0.9, 192.0.0.10, 2001:4:112::1") {
		t.Errorf("summary %q", line)
	}
}
