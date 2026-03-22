// Package scanner defines the Scanner interface and the global scanner registry.
package scanner

import (
	"context"

	"github.com/NIRODH/devshield/pkg/schema"
)

// Scanner is the core interface that every security scanning tool must implement.
// Whether a Go library import, a Python subprocess, or a Go binary — all tools
// implement this same interface. The orchestration layer never needs to know
// which integration method is used.
type Scanner interface {
	// Name returns the scanner's unique identifier (e.g., "gitleaks", "semgrep").
	Name() string

	// Category returns the scanner's primary security category.
	Category() schema.Category

	// IsAvailable reports whether the scanner is ready to run.
	// For Go lib scanners this is always true. For subprocess scanners
	// this checks if the binary exists and is executable.
	IsAvailable() bool

	// Scan runs the security scan and returns normalized findings.
	// The context should be used for cancellation and timeout.
	Scan(ctx context.Context, sc schema.ScanContext) ([]schema.Finding, error)

	// Version returns the scanner tool's version string.
	Version() (string, error)
}
