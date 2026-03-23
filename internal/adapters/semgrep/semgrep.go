package semgrep

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/NIRODH/devshield/internal/scanner"
	"github.com/NIRODH/devshield/pkg/schema"
)

type Scanner struct{}

func init() {
	scanner.Register(&Scanner{})
}

func (s *Scanner) Name() string {
	return "semgrep"
}

func (s *Scanner) Category() schema.Category {
	return schema.CategorySAST
}

func (s *Scanner) IsAvailable() bool {
	_, err := exec.LookPath("semgrep")
	return err == nil
}

func (s *Scanner) Version() (string, error) {
	cmd := exec.Command("semgrep", "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(out)), nil
}

type semgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Lines    string `json:"lines"`
			Metadata struct {
				CWE []string `json:"cwe"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

func (s *Scanner) Scan(ctx context.Context, sc schema.ScanContext) ([]schema.Finding, error) {
	// Run semgrep with auto config emitting JSON
	// semgrep scan --config auto --json <path>
	cmd := exec.CommandContext(ctx, "semgrep", "scan", "--config", "auto", "--json", "--quiet", sc.RootPath)

	out, err := cmd.Output()
	// Semgrep returns exit code 1 if it finds vulnerabilities. We still want to parse the output.
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, fmt.Errorf("failed to run semgrep: %w", err)
		}
	}

	var output semgrepOutput
	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep json: %w", err)
	}

	var findings []schema.Finding
	for _, r := range output.Results {
		// Map Semgrep 'ERROR', 'WARNING', 'INFO' to schema severities
		var sev schema.Severity
		switch r.Extra.Severity {
		case "ERROR":
			sev = schema.SeverityHigh
		case "WARNING":
			sev = schema.SeverityMedium
		case "INFO":
			sev = schema.SeverityLow
		default:
			sev = schema.SeverityInfo
		}

		cwe := ""
		if len(r.Extra.Metadata.CWE) > 0 {
			cwe = r.Extra.Metadata.CWE[0]
		}

		fp := computeFingerprint(r.CheckID, r.Path, r.Start.Line)

		findings = append(findings, schema.Finding{
			ID:          fmt.Sprintf("semgrep:%s:%s:%d", r.CheckID, r.Path, r.Start.Line),
			Tool:        s.Name(),
			Category:    s.Category(),
			Severity:    sev,
			Title:       r.CheckID,
			Description: r.Extra.Message,
			File:        r.Path,
			Line:        r.Start.Line,
			RuleID:      r.CheckID,
			CWEID:       cwe,
			Fingerprint: fp,
			Extra: map[string]interface{}{
				"snippet": r.Extra.Lines,
			},
		})
	}

	return findings, nil
}

func computeFingerprint(ruleID, file string, line int) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", ruleID, file, line)))
	return hex.EncodeToString(hash[:])
}
