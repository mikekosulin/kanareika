package sshx

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestExitCode: ssh(1)'s codes for what the session ended with; transport errors stay errors.
func TestExitCode(t *testing.T) {
	st := &tail{}
	if c, err := exitCode(nil, st); c != 0 || err != nil {
		t.Fatal(c, err)
	}
	if c, err := exitCode(&ssh.ExitMissingError{}, st); c != 255 || err != nil || !strings.Contains(st.String(), "without exit status") {
		t.Fatal(c, err, st.String())
	}
	if c, err := exitCode(errTooBig, st); c != 0 || !errors.Is(err, errTooBig) {
		t.Fatal(c, err)
	}
	boom := errors.New("connection reset")
	if _, err := exitCode(boom, st); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}

func TestTailKeepsTheEnd(t *testing.T) {
	st := &tail{}
	_, _ = st.Write([]byte(strings.Repeat("a", tailMax)))
	_, _ = st.Write([]byte("END"))
	if s := st.String(); len(s) != tailMax || !strings.HasSuffix(s, "END") {
		t.Fatal(len(s))
	}
}
