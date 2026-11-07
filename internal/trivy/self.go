package trivy

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
)

// EngineCommand: the hidden first argument that makes kanareika run as trivy. cmd/kanareika hands it to package
// engine before the CLI sees it, so trivy parses its own flags exactly as the trivy binary does.
const EngineCommand = "__trivy"

// EngineModule: trivy's Go module. Its version in this binary's build info is the version of the embedded trivy.
const EngineModule = "github.com/aquasecurity/trivy"

// executable and buildInfo: the running binary and its build info; tests replace them.
var (
	executable = os.Executable
	buildInfo  = debug.ReadBuildInfo
)

// Embedded: version of the trivy linked into this binary, without the "v" ("0.75.0"); "" when there is none
// (test binaries, which don't link package engine).
func Embedded() string {
	bi, ok := buildInfo()
	if !ok {
		return ""
	}
	for _, d := range bi.Deps {
		if d.Path != EngineModule {
			continue
		}
		if d.Replace != nil {
			d = d.Replace
		}
		return strings.TrimPrefix(d.Version, "v")
	}
	return ""
}

// Binary: how to start trivy. KANAREIKA_TRIVY names an external trivy binary (no prefix); otherwise it is kanareika
// itself with EngineCommand first. Every scan gets its own trivy process either way: hosts are scanned in parallel
// and trivy keeps global state (logger, caches), so processes keep them apart.
func Binary() (bin string, prefix []string, err error) {
	if p := os.Getenv("KANAREIKA_TRIVY"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", nil, fmt.Errorf("KANAREIKA_TRIVY: %w", err)
		}
		return p, nil, nil
	}
	if Embedded() == "" {
		return "", nil, errors.New("this kanareika build has no embedded trivy: set KANAREIKA_TRIVY to a trivy binary")
	}
	self, err := executable()
	if err != nil {
		return "", nil, fmt.Errorf("kanareika executable: %w", err)
	}
	return self, []string{EngineCommand}, nil
}
