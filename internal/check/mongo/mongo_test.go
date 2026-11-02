package mongo

import (
	"testing"

	"github.com/mikekosulin/kanareika/internal/check/checktest"
)

// TestGolden: recorded on the four hosts (none runs mongod); synthetic: mongod listening on all interfaces.
func TestGolden(t *testing.T) {
	for _, c := range checktest.Cases(t) {
		t.Run(c.Host.Name, func(t *testing.T) { checktest.Check(t, c, Run, "version.txt", "listen.txt") })
	}
}
