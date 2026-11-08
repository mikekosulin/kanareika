package server

import (
	"os"
	"testing"

	"github.com/mikekosulin/kanareika/internal/onboard"
)

// TestMain: pasted names never resolve against the ~/.ssh/config of the machine running the tests.
func TestMain(m *testing.M) {
	onboard.LocalSSHConfig = func() []onboard.SSHHost { return nil }
	os.Exit(m.Run())
}
