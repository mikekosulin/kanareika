// Command kanareika: agentless read-only security audit of our servers, per organization.
package main

import (
	"os"

	"github.com/mikekosulin/kanareika/internal/cli"
	"github.com/mikekosulin/kanareika/internal/trivy"
	"github.com/mikekosulin/kanareika/internal/trivy/engine"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// cliMain and engineMain: the two personalities of the binary; tests replace them.
var (
	cliMain    = cli.Execute
	engineMain = engine.Main
)

// run: `kanareika __trivy ...` is the embedded trivy (started by kanareika itself), anything else is the CLI.
func run(args []string) int {
	if len(args) > 0 && args[0] == trivy.EngineCommand {
		return engineMain(args[1:])
	}
	return cliMain(version, args)
}

func main() { os.Exit(run(os.Args[1:])) }
