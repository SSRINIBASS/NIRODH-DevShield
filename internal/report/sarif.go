package report

import (
	"fmt"
	"os"

	"github.com/owenrumney/go-sarif/v2/sarif"

	"github.com/NIRODH/devshield/pkg/schema"
)

// WriteSARIF generates a SARIF 2.1.0 report from scan results.
// Each scanner becomes a run within the SARIF file with its own tool entry.
func WriteSARIF(result *schema.ScanResult, outputPath string) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return fmt.Errorf("failed to create SARIF report: %w", err)
	}

	// Group findings by tool
	findingsByTool := make(map[string][]schema.Finding)
	for _, f := range result.Findings {
		findingsByTool[f.Tool] = append(findingsByTool[f.Tool], f)
	}

	// Get tool version info
	toolVersions := make(map[string]string)
	for _, ti := range result.ToolsUsed {
		toolVersions[ti.Name] = ti.Version
	}

	// Create a run for each tool
	for toolName, findings := range findingsByTool {
		version := toolVersions[toolName]
		run := sarif.NewRunWithInformationURI(toolName, fmt.Sprintf("https://github.com/NIRODH/devshield/docs/tools/%s", toolName))
		run.Tool.Driver.Version = &version

		// Collect unique rules
		ruleMap := make(map[string]bool)
		for _, f := range findings {
			if !ruleMap[f.RuleID] {
				ruleMap[f.RuleID] = true
				rule := run.AddRule(f.RuleID).
					WithDescription(f.Description)

				if f.Title != "" {
					rule.WithShortDescription(sarif.NewMultiformatMessageString(f.Title))
				}

				// Add help text with remediation
				if f.Remediation != "" {
					rule.WithHelp(sarif.NewMultiformatMessageString(f.Remediation))
				}

				// Add CWE tag
				if f.CWEID != "" {
					rule.WithProperties(sarif.Properties{
						"tags": []string{f.CWEID},
					})
				}
			}
		}

		// Add results
		for _, f := range findings {
			level := severityToSARIFLevel(f.Severity)

			r := sarif.NewRuleResult(f.RuleID).
				WithLevel(level).
				WithMessage(sarif.NewTextMessage(f.Title))

			if f.File != "" {
				location := sarif.NewLocationWithPhysicalLocation(
					sarif.NewPhysicalLocation().
						WithArtifactLocation(sarif.NewSimpleArtifactLocation(f.File)).
						WithRegion(sarif.NewSimpleRegion(f.Line, f.Line)),
				)
				r.WithLocations([]*sarif.Location{location})
			}

			// Add fingerprint for deduplication
			if f.Fingerprint != "" {
				r.WithPartialFingerPrints(map[string]interface{}{
					"devshield/v1": f.Fingerprint,
				})
			}

			// Mark suppressed findings
			if f.Suppressed {
				r.WithSuppression([]*sarif.Suppression{
					sarif.NewSuppression("inSource"),
				})
			}

			run.AddResult(r)
		}

		report.AddRun(run)
	}

	// If no findings at all, create an empty run for DevShield itself
	if len(findingsByTool) == 0 {
		run := sarif.NewRunWithInformationURI("devshield", "https://github.com/NIRODH/devshield")
		version := result.Version
		run.Tool.Driver.Version = &version
		report.AddRun(run)
	}

	// Write to file
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create SARIF file: %w", err)
	}
	defer f.Close()

	return report.PrettyWrite(f)
}

// severityToSARIFLevel maps DevShield severity to SARIF level.
func severityToSARIFLevel(s schema.Severity) string {
	switch s {
	case schema.SeverityCritical:
		return "error"
	case schema.SeverityHigh:
		return "error"
	case schema.SeverityMedium:
		return "warning"
	case schema.SeverityLow:
		return "note"
	case schema.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}
