package health_test

import (
	"math"
	"testing"
	"time"

	"github.com/mikekosulin/kanareika/internal/check/checktest"
	"github.com/mikekosulin/kanareika/internal/check/health"
)

// TestGolden: the Python module's output for outputs recorded on stream9 (CentOS Stream 9, sudo), centos6
// (CentOS 6, no systemd), ubuntu24 (Ubuntu 24.04, chrony), via-jump, plus synthetic cases for every finding.
func TestGolden(t *testing.T) {
	for _, c := range checktest.Cases(t) {
		t.Run(c.Host.Name, func(t *testing.T) {
			sec, frac := math.Modf(*c.ScannerTS)
			health.Now = func() time.Time { return time.Unix(int64(sec), int64(frac*1e9)) }
			defer func() { health.Now = time.Now }()
			checktest.Check(t, c, health.Run, "raw.txt")
		})
	}
}
