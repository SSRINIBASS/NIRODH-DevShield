// Package cli implements the Cobra-based CLI for DevShield.
package cli

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// Version is set at build time via ldflags.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

var (
	cfgFile     string
	outputDir   string
	formats     string
	failOn      string
	timeout     string
	concurrency int
	noTUI       bool
	debug       bool
	offline     bool
)

// rootCmd is the base command for DevShield.
var rootCmd = &cobra.Command{
	Use:   "devshield",
	Short: "DevShield — Open-Source DevSecOps Platform",
	Long: `DevShield is a free, open-source, privacy-first DevSecOps platform
that unifies 16 best-in-class security scanners behind one binary,
one configuration file, and one unified report.

Run a complete DevSecOps security scan with a single command.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Configure zerolog
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		if debug {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	},
}

func init() {
	// Global flags per SRS Section 12.2
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Path to .devshield.yaml (default: auto-detect)")
	rootCmd.PersistentFlags().StringVar(&outputDir, "output-dir", ".devshield-reports", "Directory for report output files")
	rootCmd.PersistentFlags().StringVar(&formats, "format", "sarif,html,json", "Comma-separated output formats: sarif, html, json, junit")
	rootCmd.PersistentFlags().StringVar(&failOn, "fail-on", "high", "Severity threshold for exit 1: critical|high|medium|low")
	rootCmd.PersistentFlags().StringVar(&timeout, "timeout", "5m", "Per-scanner timeout")
	rootCmd.PersistentFlags().IntVar(&concurrency, "concurrency", 0, "Max parallel scanners (default: CPU count / 2)")
	rootCmd.PersistentFlags().BoolVar(&noTUI, "no-tui", false, "Disable TUI, use plain text output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable verbose debug logging to stderr")
	rootCmd.PersistentFlags().BoolVar(&offline, "offline", false, "Skip all network calls")

	// Register subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(initCmd)
}

// Execute runs the root CLI command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return err
	}
	return nil
}
