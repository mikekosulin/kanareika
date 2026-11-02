package swarm

import (
	"testing"

	"github.com/mikekosulin/kanareika/internal/check/checktest"
)

// TestGolden: recorded on stream9 (staging swarm manager); synthetic: not a manager, non-ASCII and odd numbers
// (swarm.json is written with ensure_ascii and Python's number formatting).
func TestGolden(t *testing.T) {
	for _, c := range checktest.Cases(t) {
		t.Run(c.Host.Name, func(t *testing.T) { checktest.Check(t, c, Run, "info.txt", "nodes.txt", "services.txt") })
	}
}
