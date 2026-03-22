// Package gitleaks implements the Gitleaks scanner adapter using the Go library.
// Gitleaks detects secrets (API keys, tokens, passwords) in source code and git history.
package gitleaks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/fatih/semgroup"
	"github.com/spf13/viper"

	gitleaksConfig "github.com/zricethezav/gitleaks/v8/config"
	gitleaksDetect "github.com/zricethezav/gitleaks/v8/detect"
	gitleaksReport "github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"

	"github.com/NIRODH/devshield/internal/scanner"
	"github.com/NIRODH/devshield/pkg/schema"
)

const (
	scannerName    = "gitleaks"
	scannerVersion = "8.30.1" // pinned version
)

// Scanner implements the DevShield Scanner interface for Gitleaks.
type Scanner struct{}

func init() {
	scanner.Register(&Scanner{})
}

// Name returns the scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Category returns the scanner's security category.
func (s *Scanner) Category() schema.Category { return schema.CategorySecrets }

// IsAvailable reports whether Gitleaks is ready. Always true since it's a Go lib.
func (s *Scanner) IsAvailable() bool { return true }

// Version returns the Gitleaks version.
func (s *Scanner) Version() (string, error) { return scannerVersion, nil }

// Scan runs Gitleaks secret scanning on the scan context.
// Per FR-SEC-1: scans the full git history, not just the working tree.
// Per FR-SEC-2: invoked as a Go library import, not a subprocess.
func (s *Scanner) Scan(ctx context.Context, sc schema.ScanContext) ([]schema.Finding, error) {
	// Load default Gitleaks config
	cfg, err := loadDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("gitleaks config error: %w", err)
	}

	// Create detector
	detector := gitleaksDetect.NewDetectorContext(ctx, cfg)

	var gFindings []gitleaksReport.Finding

	if sc.HasGit {
		// Scan git history (FR-SEC-1) using GitCmd + Git source
		gitCmd, err := sources.NewGitLogCmdContext(ctx, sc.RootPath, "")
		if err != nil {
			// Fall back to filesystem scan if git log fails
			return s.scanFiles(ctx, sc, detector, cfg)
		}

		sema := semgroup.NewGroup(ctx, 10)
		gitSource := &sources.Git{
			Cmd:    gitCmd,
			Config: &cfg,
			Sema:   sema,
		}

		gFindings, err = detector.DetectSource(ctx, gitSource)
		if err != nil {
			// Fall back to filesystem scan on error
			return s.scanFiles(ctx, sc, detector, cfg)
		}
	} else {
		// No git — scan filesystem only
		return s.scanFiles(ctx, sc, detector, cfg)
	}

	return normalizeFindings(gFindings, sc.RootPath), nil
}

// scanFiles performs a filesystem-only scan using the Files source.
func (s *Scanner) scanFiles(ctx context.Context, sc schema.ScanContext, detector *gitleaksDetect.Detector, cfg gitleaksConfig.Config) ([]schema.Finding, error) {
	sema := semgroup.NewGroup(ctx, 10)
	filesSource := &sources.Files{
		Config: &cfg,
		Path:   sc.RootPath,
		Sema:   sema,
	}

	gFindings, err := detector.DetectSource(ctx, filesSource)
	if err != nil {
		return nil, fmt.Errorf("gitleaks filesystem scan failed: %w", err)
	}

	return normalizeFindings(gFindings, sc.RootPath), nil
}

// loadDefaultConfig loads the default Gitleaks configuration.
func loadDefaultConfig() (gitleaksConfig.Config, error) {
	vp := viper.New()
	vp.SetConfigType("toml")
	err := vp.ReadConfig(strings.NewReader(gitleaksConfig.DefaultConfig))
	if err != nil {
		return gitleaksConfig.Config{}, err
	}
	var vc gitleaksConfig.ViperConfig
	err = vp.Unmarshal(&vc)
	if err != nil {
		return gitleaksConfig.Config{}, err
	}
	return vc.Translate()
}

// normalizeFindings converts Gitleaks findings to DevShield's unified Finding schema.
func normalizeFindings(gFindings []gitleaksReport.Finding, rootPath string) []schema.Finding {
	findings := make([]schema.Finding, 0, len(gFindings))

	for _, gf := range gFindings {
		relFile := gf.File
		if filepath.IsAbs(relFile) {
			if rel, err := filepath.Rel(rootPath, relFile); err == nil {
				relFile = rel
			}
		}

		// Generate fingerprint (FR-SEC-5: for deduplication)
		fingerprint := computeFingerprint(gf.RuleID, relFile, gf.Match)

		f := schema.Finding{
			ID:          fmt.Sprintf("gitleaks:%s:%s:%d", gf.RuleID, relFile, gf.StartLine),
			Tool:        scannerName,
			Category:    schema.CategorySecrets,
			Severity:    mapSeverity(gf.RuleID),
			Title:       fmt.Sprintf("Secret detected: %s", gf.Description),
			Description: fmt.Sprintf("A potential secret (%s) was found. Secret type: %s", gf.Description, gf.RuleID),
			Remediation: "Remove the secret from the codebase. Rotate the compromised credential immediately. Use environment variables or a secrets manager instead.",
			File:        relFile,
			Line:        gf.StartLine,
			RuleID:      gf.RuleID,
			CWEID:       "CWE-798", // Use of Hard-coded Credentials
			Tags:        []string{"owasp:A07", "secrets"},
			Fingerprint: fingerprint,
			CommitSHA:   gf.Commit,
			Extra: map[string]interface{}{
				"match":   truncateSecret(gf.Match),
				"entropy": gf.Entropy,
				"author":  gf.Author,
				"email":   gf.Email,
				"date":    gf.Date,
			},
		}

		findings = append(findings, f)
	}

	return findings
}

// mapSeverity maps Gitleaks rule IDs to DevShield severity levels.
// Secrets are generally HIGH or CRITICAL severity.
func mapSeverity(ruleID string) schema.Severity {
	// Known critical patterns
	criticalPatterns := map[string]bool{
		"aws-access-key-id":       true,
		"aws-secret-access-key":   true,
		"github-pat":              true,
		"github-fine-grained-pat": true,
		"github-oauth":            true,
		"gcp-api-key":             true,
		"gcp-service-account":     true,
		"private-key":             true,
		"stripe-api-key":          true,
	}

	if criticalPatterns[ruleID] {
		return schema.SeverityCritical
	}

	return schema.SeverityHigh
}

// computeFingerprint generates a deduplication fingerprint for a finding.
func computeFingerprint(ruleID, file, match string) string {
	data := fmt.Sprintf("%s:%s:%s", ruleID, file, match)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:16]) // first 16 bytes = 32 hex chars
}

// truncateSecret redacts secret values for safe reporting (SR-5).
func truncateSecret(match string) string {
	if len(match) <= 8 {
		return "***REDACTED***"
	}
	return match[:4] + "***REDACTED***" + match[len(match)-4:]
}
