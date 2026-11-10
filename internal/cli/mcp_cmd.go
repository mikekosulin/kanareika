package cli

import (
	"github.com/spf13/cobra"

	"github.com/mikekosulin/kanareika/internal/mcp"
)

func (a *app) mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "MCP server on stdio (read-only) for Claude Code and other agents",
		RunE: func(cmd *cobra.Command, _ []string) error {
			limitMemory()
			ctx, stop := interruptible()
			defer stop()
			return mcp.Serve(ctx, cmd.InOrStdin(), cmd.OutOrStdout(), a.paths, a.version)
		},
	}
}
