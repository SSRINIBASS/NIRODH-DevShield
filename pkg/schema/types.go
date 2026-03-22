// Package schema defines the public types shared across DevShield's scanner ecosystem.
// These types form the primary public API and MUST remain stable within a MAJOR version.
package schema

import (
	"context"
	"strings"
	"time"
)

// =============================================================================
// Category — security scan category
// =============================================================================

// Category represents a security scanning category.
type Category string

const (
	CategorySecrets   Category = "secrets"
	CategorySAST      Category = "sast"
	CategorySCA       Category = "sca"
	CategoryIaC       Category = "iac"
	CategoryContainer Category = "container"
	CategorySBOM      Category = "sbom"
	CategoryDAST      Category = "dast"
	CategoryCloud     Category = "cloud"
	CategoryK8s       Category = "k8s"
	CategoryCICD      Category = "cicd"
)

// AllCategories returns all valid categories.
func AllCategories() []Category {
	return []Category{
		CategorySecrets, CategorySAST, CategorySCA, CategoryIaC,
		CategoryContainer, CategorySBOM, CategoryDAST, CategoryCloud,
		CategoryK8s, CategoryCICD,
	}
}

// =============================================================================
// Severity — finding severity level
// =============================================================================

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Weight returns a numeric weight for sorting (higher = more severe).
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// MeetsThreshold returns true if this severity is >= the given threshold.
func (s Severity) MeetsThreshold(threshold Severity) bool {
	return s.Weight() >= threshold.Weight()
}

// ParseSeverity parses a string into a Severity, case-insensitive.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// AllSeverities returns all severity levels from highest to lowest.
func AllSeverities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
}

// =============================================================================
// Language — detected programming language
// =============================================================================

// Language represents a detected programming language.
type Language string

const (
	LangGo         Language = "go"
	LangPython     Language = "python"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangJava       Language = "java"
	LangRust       Language = "rust"
	LangRuby       Language = "ruby"
	LangPHP        Language = "php"
	LangCSharp     Language = "csharp"
	LangCpp        Language = "cpp"
	LangC          Language = "c"
	LangSwift      Language = "swift"
	LangKotlin     Language = "kotlin"
	LangScala      Language = "scala"
)

// =============================================================================
// ScanContext — context passed to each scanner
// =============================================================================

// ScanContext contains all detected project metadata passed to each scanner on invocation.
type ScanContext struct {
	// RootPath is the absolute path to the scan root.
	RootPath string

	// Languages detected in the project.
	Languages []Language

	// HasTerraform indicates Terraform files were found.
	HasTerraform bool

	// HasK8s indicates Kubernetes manifests were found.
	HasK8s bool

	// HasDocker indicates Dockerfiles or docker-compose files were found.
	HasDocker bool

	// HasGit indicates a .git directory was found.
	HasGit bool

	// GitRemote is the resolved Git remote URL (e.g., github.com/org/repo).
	GitRemote string

	// Config is the loaded .devshield.yaml configuration.
	Config interface{} // Will be typed as *config.Config — using interface to avoid circular imports.

	// TempDir is a writable temporary directory for tool outputs.
	TempDir string

	// Timeout is the per-scanner timeout.
	Timeout time.Duration

	// Ctx is the parent context for cancellation.
	Ctx context.Context
}

// HasLanguage returns true if the given language was detected.
func (sc *ScanContext) HasLanguage(lang Language) bool {
	for _, l := range sc.Languages {
		if l == lang {
			return true
		}
	}
	return false
}

// =============================================================================
// Finding — unified finding schema
// =============================================================================

// Finding represents a single security finding from any scanner.
type Finding struct {
	// ID is a unique finding identifier (tool:ruleID:file:line).
	ID string `json:"id"`

	// Tool is the source scanner name (e.g., "gitleaks").
	Tool string `json:"tool"`

	// Category is the security category (secrets, sast, sca, etc.).
	Category Category `json:"category"`

	// Severity is the finding severity level.
	Severity Severity `json:"severity"`

	// Title is a short human-readable title.
	Title string `json:"title"`

	// Description is the full finding description.
	Description string `json:"description"`

	// Remediation is the fix guidance.
	Remediation string `json:"remediation,omitempty"`

	// File is the relative file path.
	File string `json:"file"`

	// Line is the line number (0 if N/A).
	Line int `json:"line"`

	// Column is the column number (0 if N/A).
	Column int `json:"column,omitempty"`

	// RuleID is the tool-specific rule identifier.
	RuleID string `json:"rule_id"`

	// CWEID is the CWE identifier if applicable (e.g., "CWE-798").
	CWEID string `json:"cwe_id,omitempty"`

	// CVEID is the CVE identifier if applicable (e.g., "CVE-2024-12345").
	CVEID string `json:"cve_id,omitempty"`

	// Tags are metadata tags (e.g., ["owasp:A03","pci-dss"]).
	Tags []string `json:"tags,omitempty"`

	// Fingerprint is a SHA256 hash of rule+file+content for deduplication.
	Fingerprint string `json:"fingerprint"`

	// Suppressed is true if user-suppressed via .devshield-ignore.
	Suppressed bool `json:"suppressed"`

	// CommitSHA is the git commit hash if the finding is from git history scanning.
	CommitSHA string `json:"commit_sha,omitempty"`

	// Extra holds tool-specific metadata.
	Extra map[string]interface{} `json:"extra,omitempty"`
}

// =============================================================================
// ScanResult — wraps findings from a scan run
// =============================================================================

// ScanResult contains the complete output of a DevShield scan.
type ScanResult struct {
	// Version is the DevShield version.
	Version string `json:"devshield_version"`

	// ScanTimestamp is the ISO 8601 scan start time.
	ScanTimestamp string `json:"scan_timestamp"`

	// ScanDurationSeconds is the total scan wall-clock time.
	ScanDurationSeconds float64 `json:"scan_duration_seconds"`

	// ProjectPath is the absolute path of the scanned project.
	ProjectPath string `json:"project_path"`

	// Context describes the detected project context.
	Context ScanResultContext `json:"context"`

	// Summary is the finding count by severity.
	Summary SeveritySummary `json:"summary"`

	// ToolsUsed lists all scanners that ran with their versions and finding counts.
	ToolsUsed []ToolInfo `json:"tools_used"`

	// Findings is the complete list of findings.
	Findings []Finding `json:"findings"`
}

// ScanResultContext describes the detected project context in output.
type ScanResultContext struct {
	Languages []Language `json:"languages"`
	HasK8s    bool       `json:"has_k8s"`
	HasDocker bool       `json:"has_docker"`
	HasIaC    bool       `json:"has_iac"`
	HasGit    bool       `json:"has_git"`
}

// SeveritySummary holds counts by severity.
type SeveritySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// ComputeSummary calculates the severity summary from a list of findings.
func ComputeSummary(findings []Finding) SeveritySummary {
	var s SeveritySummary
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
		s.Total++
	}
	return s
}

// ToolInfo describes a scanner that participated in the scan.
type ToolInfo struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	FindingsCount int    `json:"findings_count"`
	DurationMs    int64  `json:"duration_ms"`
	Error         string `json:"error,omitempty"`
}
