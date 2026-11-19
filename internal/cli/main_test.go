package cli

import (
	"os"
	"testing"

	"github.com/mikekosulin/kanareika/internal/onboard"
)

// TestMain: pasted names never resolve against the ~/.ssh/config of the machine running the tests; nothing asks
// GitHub for a newer release (the tests' version, v9.9.9-test, reads as a release).
func TestMain(m *testing.M) {
	onboard.LocalSSHConfig = func() []onboard.SSHHost { return nil }
	_ = os.Setenv("KANAREIKA_UPDATE_CHECK", "off")
	os.Exit(m.Run())
}
