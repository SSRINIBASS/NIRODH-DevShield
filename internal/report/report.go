// Package report implements output generators for DevShield scan results.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/NIRODH/devshield/internal/config"
	"github.com/NIRODH/devshield/pkg/schema"
)

// Generate produces all configured report outputs.
func Generate(result *schema.ScanResult, cfg *config.Config) error {
	outDir := cfg.Output.Dir
	if outDir == "" {
		outDir = ".devshield-reports"
	}

	// Ensure output directory exists
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir %s: %w", outDir, err)
	}

	for _, format := range cfg.Output.Formats {
		format = strings.TrimSpace(strings.ToLower(format))
		switch format {
		case "sarif":
			path := filepath.Join(outDir, "devshield.sarif")
			if err := WriteSARIF(result, path); err != nil {
				log.Error().Err(err).Str("format", "sarif").Msg("Report generation failed")
				return fmt.Errorf("SARIF report failed: %w", err)
			}
			log.Info().Str("path", path).Msg("SARIF report written")

		case "json":
			path := filepath.Join(outDir, "devshield.json")
			if err := WriteJSON(result, path); err != nil {
				log.Error().Err(err).Str("format", "json").Msg("Report generation failed")
				return fmt.Errorf("JSON report failed: %w", err)
			}
			log.Info().Str("path", path).Msg("JSON report written")

		case "html":
			path := filepath.Join(outDir, "devshield.html")
			if err := WriteHTML(result, path); err != nil {
				log.Error().Err(err).Str("format", "html").Msg("Report generation failed")
				return fmt.Errorf("HTML report failed: %w", err)
			}
			log.Info().Str("path", path).Msg("HTML report written")

		default:
			log.Warn().Str("format", format).Msg("Unknown output format, skipping")
		}
	}

	return nil
}
