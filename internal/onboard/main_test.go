package onboard

import (
	"os"
	"testing"
)

// TestMain: pasted names never resolve against the ~/.ssh/config of the machine running the tests.
func TestMain(m *testing.M) {
	LocalSSHConfig = func() []SSHHost { return nil }
	os.Exit(m.Run())
}
