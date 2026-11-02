// Command kanareika: agentless read-only security audit of our servers, per organization.
package main

import (
	"os"

	"github.com/mikekosulin/kanareika/internal/cli"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() { os.Exit(cli.Execute(version, os.Args[1:])) }
