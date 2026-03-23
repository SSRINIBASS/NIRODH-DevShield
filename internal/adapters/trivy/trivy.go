package trivy

import (
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
	return "trivy"
}

func (s *Scanner) Category() schema.Category {
	return schema.CategorySCA
}

func (s *Scanner) IsAvailable() bool {
	_, err := exec.LookPath("trivy")
	return err == nil
}

func (s *Scanner) Version() (string, error) {
	cmd := exec.Command("trivy", "--version")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	// trivy --version outputs multiple lines, just take the first
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0]), nil
	}
	return "unknown", nil
}

type trivyOutput struct {
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
			Severity         string `json:"Severity"`
			PrimaryURL       string `json:"PrimaryURL"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func (s *Scanner) Scan(ctx context.Context, sc schema.ScanContext) ([]schema.Finding, error) {
	// trivy fs . --scanners vuln --format json --quiet
	cmd := exec.CommandContext(ctx, "trivy", "fs", sc.RootPath, "--scanners", "vuln", "--format", "json", "--quiet")

	out, err := cmd.Output()
	if err != nil && out == nil {
		return nil, fmt.Errorf("failed to run trivy: %w", err)
	}

	var parsed trivyOutput
	if unmarshalErr := json.Unmarshal(out, &parsed); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to parse trivy json: %w", unmarshalErr)
	}

	var findings []schema.Finding
	for _, result := range parsed.Results {
		for _, v := range result.Vulnerabilities {
			sev := mapSeverity(v.Severity)

			// Fallback title to VulnID if missing
			title := v.Title
			if title == "" {
				title = v.VulnerabilityID
			}

			fp := computeFingerprint(v.VulnerabilityID, result.Target, v.PkgName)

			findings = append(findings, schema.Finding{
				ID:          fmt.Sprintf("trivy:%s:%s", v.VulnerabilityID, result.Target),
				Tool:        s.Name(),
				Category:    s.Category(),
				Severity:    sev,
				Title:       title,
				Description: v.Description,
				File:        result.Target,
				Line:        0, // SCA usually doesn't have exact lines
				RuleID:      v.VulnerabilityID,
				CWEID:       "",
				Fingerprint: fp,
				Extra: map[string]interface{}{
					"package":          v.PkgName,
					"installedVersion": v.InstalledVersion,
					"fixedVersion":     v.FixedVersion,
					"url":              v.PrimaryURL,
					"type":             result.Type,
				},
			})
		}
	}

	return findings, nil
}

func mapSeverity(trivySev string) schema.Severity {
	switch strings.ToUpper(trivySev) {
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

func computeFingerprint(vulnID, file, pkg string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", vulnID, file, pkg)))
	return hex.EncodeToString(hash[:])
}
