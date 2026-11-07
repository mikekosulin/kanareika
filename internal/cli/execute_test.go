package cli

import "testing"

// TestExecute: the entry point main calls, wired to the process's own stdin/stdout/stderr.
func TestExecute(t *testing.T) {
	sandbox(t)
	if rc := Execute("test", []string{"version"}); rc != 0 {
		t.Fatal(rc)
	}
	if rc := Execute("test", []string{"no-such-command"}); rc == 0 {
		t.Fatal("unknown command accepted")
	}
}
