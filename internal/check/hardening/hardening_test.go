package hardening

import (
	"testing"

	"github.com/mikekosulin/kanareika/internal/check/checktest"
)

// TestGolden: recorded on stream9, centos6, ubuntu24, via-jump; synthetic long uptime / empty output.
func TestGolden(t *testing.T) {
	for _, c := range checktest.Cases(t) {
		t.Run(c.Host.Name, func(t *testing.T) { checktest.Check(t, c, Run, "raw.txt") })
	}
}
