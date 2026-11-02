package access

import (
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check/checktest"
)

// TestGolden: recorded on stream9 (journal + secure, sudo; once more without privilege), centos6 (CentOS 6,
// OpenSSH 5.3 syslog), ubuntu24 (Ubuntu 24.04), via-jump; auth logs cut to their last 5000 lines. Synthetic
// cases cover password auth, Match blocks, partial sshd_config, unreadable shadow, odd syslog dates.
func TestGolden(t *testing.T) {
	for _, c := range checktest.Cases(t) {
		t.Run(c.Dir, func(t *testing.T) {
			now := c.NowTime(t)
			Now = func() time.Time { return now }
			defer func() { Now = time.Now }()
			checktest.Check(t, c, Run, "raw.txt")
		})
	}
}

// from tests/test_core.py::test_old_rhel_and_sshd_parsing (the access parts)
func TestOldRHELAndSSHDParsing(t *testing.T) {
	order, per := perUserSSHD("U:deploy\npasswordauthentication yes\nusepam yes\nU:root\npasswordauthentication no\nU:ghost\n")
	if !pwOn(per["deploy"]) || pwOn(per["root"]) {
		t.Errorf("per user: %v", per)
	}
	if _, ok := per["ghost"]; ok || len(order) != 2 {
		t.Errorf("ghost has no output and must be skipped: %v", order)
	}
	if !pwOn(settings{{K: "passwordauthentication", V: "no"}, {K: "kbdinteractiveauthentication", V: "yes"}, {K: "usepam", V: "yes"}}) {
		t.Error("keyboard-interactive via PAM is password login")
	}
	m := reInvalid.FindStringSubmatch("Nov  1 23:22:27 host-08 sshd[20679]: Invalid user anonymous from 203.0.113.72")
	if m == nil || m[1] != "anonymous" || m[2] != "203.0.113.72" {
		t.Errorf("old OpenSSH line: %q", m)
	}
	m = reInvalid.FindStringSubmatch("2026-11-01T10:00:00 h sshd[1]: Invalid user admin from 1.2.3.4 port 5555")
	if m == nil || m[1] != "admin" || m[2] != "1.2.3.4" {
		t.Errorf("line with port: %q", m)
	}
}

func TestStamp(t *testing.T) {
	jan := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	for line, want := range map[string]string{
		"2026-11-01T10:00:00+0300 h sshd[1]: x": "2026-11-01T10:00:00",
		"Dec 31 23:59:59 h sshd[1]: x":          "2025-12-31T23:59:59", // read in January: last year
		"Jan  6 11:59:59 h sshd[1]: x":          "2026-01-06T11:59:59", // within a day ahead: this year
		"jan  5 10:00:00 h":                     "2026-01-05T10:00:00", // %b is case-insensitive
		"Feb 30 10:00:00 h":                     "",
		"Jan 32 10:00:00 h":                     "",
		"Jan  5 24:00:00 h":                     "",
		"Foo  5 10:00:00 h":                     "",
		"no stamp":                              "",
	} {
		if got, err := stamp(line, jan); err != nil || got != want {
			t.Errorf("%q: got %q %v, want %q", line, got, err, want)
		}
	}
	// Feb 29 of a leap year read in January of that year moves to a year without it: Python raised
	if _, err := stamp("Feb 29 10:00:00 h", time.Date(2028, 1, 5, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Error("want an error")
	}
}
