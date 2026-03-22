package cli

import (
	"fmt"
	"os"

	"github.com/NIRODH/devshield/internal/config"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate .devshield.yaml configuration for this project",
	Long: `Generates a default .devshield.yaml configuration file in the current
directory. You can then customize scanner settings, exclusions, and thresholds.`,
	RunE: runInit,
}

func runInit(cmd *cobra.Command, args []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Check if config already exists
	configPath := cwd + "/.devshield.yaml"
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf(".devshield.yaml already exists in %s — use --config to specify a different path", cwd)
	}

	path, err := config.WriteDefault(cwd)
	if err != nil {
		return err
	}

	fmt.Printf("✓ Generated %s\n", path)
	fmt.Println("  Edit this file to customize your DevShield scan configuration.")
	return nil
}
