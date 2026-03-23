package tfsec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/NIRODH/devshield/internal/scanner"
	"github.com/NIRODH/devshield/pkg/schema"
)

type Scanner struct{}

func init() {
	scanner.Register(&Scanner{})
}

func (s *Scanner) Name() string {
	return "tfsec"
}

func (s *Scanner) Category() schema.Category {
	return schema.CategoryIaC
}

func (s *Scanner) IsAvailable() bool {
	_, err := exec.LookPath("tfsec")
	return err == nil
}

func (s *Scanner) Version() (string, error) {
	cmd := exec.Command("tfsec", "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(out)), nil
}

type tfsecOutput struct {
	Results []struct {
		RuleID      string `json:"rule_id"`
		LongID      string `json:"long_id"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Resolution  string `json:"resolution"`
		Links       []string `json:"links"`
		Location    struct {
			Filename  string `json:"filename"`
			StartLine int    `json:"start_line"`
			EndLine   int    `json:"end_line"`
		} `json:"location"`
	} `json:"results"`
}

func (s *Scanner) Scan(ctx context.Context, sc schema.ScanContext) ([]schema.Finding, error) {
	// tfsec <path> --format json --no-color
	cmd := exec.CommandContext(ctx, "tfsec", sc.RootPath, "--format", "json", "--no-color")

	out, err := cmd.Output()
	if err != nil && out == nil {
		return nil, fmt.Errorf("failed to run tfsec: %w", err)
	}

	var parsed tfsecOutput
	if unmarshalErr := json.Unmarshal(out, &parsed); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to parse tfsec json: %w", unmarshalErr)
	}

	var findings []schema.Finding
	for _, r := range parsed.Results {
		sev := mapSeverity(r.Severity)
		fp := computeFingerprint(r.RuleID, r.Location.Filename, r.Location.StartLine)

		// Create safe fallback for links
		link := ""
		if len(r.Links) > 0 {
			link = r.Links[0]
		}

		findings = append(findings, schema.Finding{
			ID:          fmt.Sprintf("tfsec:%s:%s:%d", r.RuleID, r.Location.Filename, r.Location.StartLine),
			Tool:        s.Name(),
			Category:    s.Category(),
			Severity:    sev,
			Title:       r.LongID,
			Description: r.Description,
			File:        r.Location.Filename,
			Line:        r.Location.StartLine,
			RuleID:      r.RuleID,
			CWEID:       "",
			Fingerprint: fp,
			Extra: map[string]interface{}{
				"resolution": r.Resolution,
				"url":        link,
				"endLine":    r.Location.EndLine,
			},
		})
	}

	return findings, nil
}

func mapSeverity(tfsecSev string) schema.Severity {
	switch strings.ToUpper(tfsecSev) {
	case "CRITICAL":
		return schema.SeverityCritical
	case "HIGH":
		return schema.SeverityHigh
	case "MEDIUM":
		return schema.SeverityMedium
	case "LOW":
		return schema.SeverityLow
	default:
		return schema.SeverityInfo
	}
}

func computeFingerprint(ruleID, file string, line int) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", ruleID, file, line)))
	return hex.EncodeToString(hash[:])
}
