// Package main is the entry point for the DevShield CLI.
package main

import (
	"os"

	"github.com/NIRODH/devshield/internal/cli"

	// Register all scanner adapters via blank imports.
	_ "github.com/NIRODH/devshield/internal/adapters/gitleaks"
	_ "github.com/NIRODH/devshield/internal/adapters/semgrep"
	_ "github.com/NIRODH/devshield/internal/adapters/tfsec"
	_ "github.com/NIRODH/devshield/internal/adapters/trivy"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
