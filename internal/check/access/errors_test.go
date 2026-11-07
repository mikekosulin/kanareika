package access

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
	h := config.Host{Name: "web-01", User: "root", Privilege: "sudo"}
	for _, tc := range []struct {
		name, raw, want string
		unwritable      bool
	}{
		{"ssh fails", "ERR:ssh down", "ssh down", false},
		{"malformed key line", "@@keys@@\nK:root:/root/.ssh/authorized_keys\n", "authorized-keys: malformed line", false},
		{"unwritable", "", "access.json", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := t.TempDir()
			if tc.unwritable {
				out = filepath.Join(out, "missing")
			}
			r := &seqRunner{out: []string{tc.raw}}
			ctx := &check.Ctx{Context: context.Background(), SSH: r, Log: func(string, ...any) { t.Error("logged") }}
			f, err := Run(ctx, h, nil, out, check.Facts{})
			if err == nil || f != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, %v; want %q", f, err, tc.want)
			}
		})
	}
}

// An auth log date that does not exist in the year it resolves to is an error, as in Python.
func TestAnalyzeBadStamp(t *testing.T) {
	now := time.Date(2028, 1, 5, 0, 0, 0, 0, time.UTC)
	_, _, _, err := analyze(config.Host{Name: "web-01"}, "@@auth@@\nFeb 29 10:00:00 web-01 sshd[1]: x\n", now)
	if err == nil {
		t.Fatal("want an error")
	}
}

// No PasswordAuthentication readable: unknown, reported as denied, no password finding.
func TestAnalyzeSSHDUnknown(t *testing.T) {
	f, data, _, err := analyze(config.Host{Name: "web-01", Privilege: "none"}, "@@passwd@@\nroot:0:/root:/bin/bash\n",
		time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if data.Get("password_auth") != nil {
		t.Errorf("password_auth %v, want unknown", data.Get("password_auth"))
	}
	if d, _ := data.Get("denied").([]string); !slices.Contains(d, "denied.sshd") {
		t.Errorf("denied %v", d)
	}
	for _, x := range f {
		if x.ID == "ssh-password-auth" {
			t.Errorf("unexpected %+v", x)
		}
	}
}

// Passwords on but /etc/shadow unreadable: which users have a password is unknown.
func TestAnalyzePasswordUsersUnknown(t *testing.T) {
	raw := "@@sshd_files@@\nPasswordAuthentication yes\n@@shadow_pw@@\nPermission denied\n"
	for exp, sev := range map[int]string{1: "MEDIUM", 2: "LOW"} {
		f, data, _, err := analyze(config.Host{Name: "web-01", Privilege: "sudo", Exposure: exp}, raw, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if data.Get("users_with_password") != nil {
			t.Errorf("users_with_password %v", data.Get("users_with_password"))
		}
		var got []string
		for _, x := range f {
			if x.ID == "ssh-password-auth" {
				got = append(got, x.Severity+" "+x.TargetMsg)
			}
		}
		if want := []string{sev + " ssh.password.unknown"}; !slices.Equal(got, want) {
			t.Errorf("exposure %d: %v, want %v", exp, got, want)
		}
	}
}

// Passwords on, but only a nologin account has one: reported LOW as "nobody can log in with a password".
func TestAnalyzePasswordNoLoginUsers(t *testing.T) {
	raw := "@@sshd_files@@\nPasswordAuthentication yes\n@@passwd@@\nsvc:998:/var/lib/svc:/usr/sbin/nologin\n" +
		"@@shadow_pw@@\nPW:svc\n"
	f, _, _, err := analyze(config.Host{Name: "web-01", Privilege: "sudo", Exposure: 1}, raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range f {
		if x.ID == "ssh-password-auth" {
			got = append(got, x.Severity+" "+x.TargetMsg)
		}
	}
	if want := []string{"LOW ssh.password.none"}; !slices.Equal(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
}
