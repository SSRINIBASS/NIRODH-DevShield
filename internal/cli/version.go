package cli

import (
	"fmt"
	"runtime"

	"github.com/NIRODH/devshield/internal/scanner"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show DevShield and all tool versions",
	RunE:  runVersion,
}

func runVersion(cmd *cobra.Command, args []string) error {
	fmt.Printf("DevShield %s\n", Version)
	fmt.Printf("  Git commit:  %s\n", GitCommit)
	fmt.Printf("  Build date:  %s\n", BuildDate)
	fmt.Printf("  Go version:  %s\n", runtime.Version())
	fmt.Printf("  OS/Arch:     %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	scanners := scanner.All()
	if len(scanners) == 0 {
		fmt.Println("  No scanners registered.")
		return nil
	}

	fmt.Println("Registered Scanners:")
	for _, s := range scanners {
		version := "unknown"
		if v, err := s.Version(); err == nil {
			version = v
		}
		available := "✓"
		if !s.IsAvailable() {
			available = "✗"
		}
		fmt.Printf("  [%s] %-15s v%-10s  (%s)\n", available, s.Name(), version, s.Category())
	}

	return nil
}
