package priv

import (
	"strings"
	"testing"
)

func TestCmdUnknownOp(t *testing.T) {
	if _, err := Cmd("sudo", "no-such-op", false); err == nil || !strings.Contains(err.Error(), "no-such-op") {
		t.Fatalf("unknown op: %v", err)
	}
}

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":             "''",
		"web-01":       "web-01",
		"a b":          "'a b'",
		"it's":         `'it'"'"'s'`,
		"héllo":        "'héllo'",
		"/var/lib/rpm": "/var/lib/rpm",
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRender(t *testing.T) {
	script := "a=$(@P:sshd-config@)\nfor u in x; do @P:sshd-config-user@ \"$u\"; done\n@P:no-such-op@\n"
	got := Render(script, "helper")
	want := "a=$(sudo -n " + HelperPath + " sshd-config)\nfor u in x; do sudo -n " + HelperPath + " sshd-config-user \"$u\"; done\n@P:no-such-op@\n"
	if got != want {
		t.Fatalf("helper render:\n got %q\nwant %q", got, want)
	}
	if got := Render("@P:dmesg@", "sudo"); got != "sudo -n sh -c "+Quote(Ops["dmesg"].Snippet)+" kanareika " {
		t.Fatalf("sudo render: %q", got)
	}
	if got := Render("@P:dmesg@", "none"); strings.HasPrefix(got, "sudo") || !strings.HasPrefix(got, "sh -c ") {
		t.Fatalf("none render: %q", got)
	}
}
