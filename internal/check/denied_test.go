package check

import (
	"testing"

	"github.com/mikekosulin/kanareika/internal/config"
	"github.com/mikekosulin/kanareika/internal/finding"
)

func TestDeniedTitleAndWhy(t *testing.T) {
	h := config.Host{Name: "web-01", User: "audit", Privilege: "sudo"}
	title, detail := Denied(h, []string{"denied.shadow", "denied.keys"})
	if title.Key != "denied.title" || title.Text != "Not checked (needs root): /etc/shadow (which accounts have a password), other users' authorized_keys" {
		t.Errorf("title: %q (%s)", title.Text, title.Key)
	}
	if detail.Key != "denied.why.sudo" || detail.Text != "audit has no passwordless sudo (sudo -n was refused)" {
		t.Errorf("detail: %q (%s)", detail.Text, detail.Key)
	}
}

func TestDeniedWhyByPrivilege(t *testing.T) {
	for _, c := range []struct {
		user, priv, key, text string
	}{
		{"root", "sudo", "denied.why.root", "refused even as root (a container, or a security module such as SELinux)"},
		{"audit", "sudo", "denied.why.sudo", "audit has no passwordless sudo (sudo -n was refused)"},
		{"audit", "helper", "denied.why.helper", "audit may not run the kanareika-collect helper with sudo (not installed, or not allowed in sudoers)"},
		{"audit", "none", "denied.why.none", "audit is not root and kanareika does not use sudo on this host (privilege: none)"},
		{"audit", "", "denied.why.none", "audit is not root and kanareika does not use sudo on this host (privilege: none)"},
	} {
		got := DeniedWhy(config.Host{User: c.user, Privilege: c.priv})
		if got.Key != c.key || got.Text != c.text || got.Args["user"] != c.user {
			t.Errorf("%s/%s: %q (%s) %v", c.user, c.priv, got.Text, got.Key, got.Args)
		}
	}
}

func TestDeniedLog(t *testing.T) {
	if got := DeniedLog(nil); got != "" {
		t.Errorf("nothing denied: %q", got)
	}
	if got := DeniedLog([]string{"denied.firewall"}); got != "not checked (needs root): firewall rules" {
		t.Errorf("log: %q", got)
	}
}

func TestSink(t *testing.T) {
	var got []string
	c := &Ctx{Sinks: map[string]func(f *finding.Finding){"web-01": func(f *finding.Finding) { got = append(got, f.ID) }}}
	if c.Sink("db-01") != nil {
		t.Error("a host without a sink has none")
	}
	c.Sink("web-01")(&finding.Finding{ID: "CVE-1"})
	if len(got) != 1 || got[0] != "CVE-1" {
		t.Errorf("sink got %v", got)
	}
	if (&Ctx{}).Sink("web-01") != nil {
		t.Error("no sinks: nil")
	}
}
