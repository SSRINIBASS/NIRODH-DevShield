// Package config handles loading and parsing of DevShield's configuration files.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config represents the complete DevShield configuration from .devshield.yaml.
type Config struct {
	Version  string        `mapstructure:"version" json:"version"`
	Scan     ScanConfig    `mapstructure:"scan" json:"scan"`
	Scanners ScannersConfig `mapstructure:"scanners" json:"scanners"`
	Thresholds ThresholdConfig `mapstructure:"thresholds" json:"thresholds"`
	Output   OutputConfig  `mapstructure:"output" json:"output"`
	Suppressions []SuppressionEntry `mapstructure:"suppressions" json:"suppressions"`
}

// ScanConfig holds scan path and exclusion patterns.
type ScanConfig struct {
	Path    string   `mapstructure:"path" json:"path"`
	Exclude []string `mapstructure:"exclude" json:"exclude"`
}

// ScannerCategoryConfig configures a category of scanners.
type ScannerCategoryConfig struct {
	Enabled interface{} `mapstructure:"enabled" json:"enabled"` // bool or "auto"
	Tools   []string    `mapstructure:"tools" json:"tools"`
	Target  string      `mapstructure:"target,omitempty" json:"target,omitempty"`
	Provider string     `mapstructure:"provider,omitempty" json:"provider,omitempty"`
}

// IsEnabled returns whether this scanner category is enabled.
// Returns true for "auto" (will be resolved by context detection).
func (s ScannerCategoryConfig) IsEnabled() bool {
	switch v := s.Enabled.(type) {
	case bool:
		return v
	case string:
		return v == "auto" || v == "true"
	default:
		return true
	}
}

// IsAuto returns whether this scanner category is in auto-detect mode.
func (s ScannerCategoryConfig) IsAuto() bool {
	if v, ok := s.Enabled.(string); ok {
		return v == "auto"
	}
	return false
}

// ScannersConfig maps each security category to its configuration.
type ScannersConfig struct {
	Secrets   ScannerCategoryConfig `mapstructure:"secrets" json:"secrets"`
	SAST      ScannerCategoryConfig `mapstructure:"sast" json:"sast"`
	SCA       ScannerCategoryConfig `mapstructure:"sca" json:"sca"`
	IaC       ScannerCategoryConfig `mapstructure:"iac" json:"iac"`
	Container ScannerCategoryConfig `mapstructure:"container" json:"container"`
	SBOM      ScannerCategoryConfig `mapstructure:"sbom" json:"sbom"`
	DAST      ScannerCategoryConfig `mapstructure:"dast" json:"dast"`
	Cloud     ScannerCategoryConfig `mapstructure:"cloud" json:"cloud"`
	K8s       ScannerCategoryConfig `mapstructure:"k8s" json:"k8s"`
	CICD      ScannerCategoryConfig `mapstructure:"cicd" json:"cicd"`
}

// ThresholdConfig holds severity thresholds for CI/CD exit codes.
type ThresholdConfig struct {
	FailOn      string `mapstructure:"fail_on" json:"fail_on"`
	MaxCritical int    `mapstructure:"max_critical" json:"max_critical"`
	MaxHigh     int    `mapstructure:"max_high" json:"max_high"`
}

// OutputConfig holds output format and directory configuration.
type OutputConfig struct {
	Formats []string `mapstructure:"formats" json:"formats"`
	Dir     string   `mapstructure:"dir" json:"dir"`
}

// SuppressionEntry defines a suppressed finding in the config.
type SuppressionEntry struct {
	ID      string `mapstructure:"id" json:"id"`
	Reason  string `mapstructure:"reason" json:"reason"`
	Expires string `mapstructure:"expires" json:"expires"`
}

// DefaultConfig returns the default DevShield configuration.
func DefaultConfig() *Config {
	return &Config{
		Version: "1",
		Scan: ScanConfig{
			Path:    ".",
			Exclude: []string{"vendor/**", "**/*_test.go", "node_modules/**"},
		},
		Scanners: ScannersConfig{
			Secrets:   ScannerCategoryConfig{Enabled: true, Tools: []string{"gitleaks"}},
			SAST:      ScannerCategoryConfig{Enabled: true, Tools: []string{"semgrep"}},
			SCA:       ScannerCategoryConfig{Enabled: true, Tools: []string{"osv-scanner", "govulncheck"}},
			IaC:       ScannerCategoryConfig{Enabled: true, Tools: []string{"trivy", "kics"}},
			Container: ScannerCategoryConfig{Enabled: true, Tools: []string{"trivy", "grype"}},
			SBOM:      ScannerCategoryConfig{Enabled: true, Tools: []string{"syft"}},
			DAST:      ScannerCategoryConfig{Enabled: false, Tools: []string{"nuclei"}},
			Cloud:     ScannerCategoryConfig{Enabled: false, Tools: []string{"prowler"}},
			K8s:       ScannerCategoryConfig{Enabled: "auto", Tools: []string{"kubescape", "kyverno"}},
			CICD:      ScannerCategoryConfig{Enabled: "auto", Tools: []string{"legitify"}},
		},
		Thresholds: ThresholdConfig{
			FailOn:      "high",
			MaxCritical: 0,
			MaxHigh:     5,
		},
		Output: OutputConfig{
			Formats: []string{"sarif", "html", "json"},
			Dir:     ".devshield-reports",
		},
	}
}

// Load reads the DevShield configuration from the given path or auto-discovers it.
// If configPath is empty, it searches for .devshield.yaml in the current directory
// and parent directories up to the filesystem root.
func Load(configPath string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigName(".devshield")

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Search in current directory and common locations
		cwd, err := os.Getwd()
		if err == nil {
			v.AddConfigPath(cwd)
		}
		v.AddConfigPath(".")
	}

	// Set defaults from DefaultConfig
	setViperDefaults(v)

	// Environment variable overrides with DEVSHIELD_ prefix
	v.SetEnvPrefix("DEVSHIELD")
	v.AutomaticEnv()

	cfg := DefaultConfig()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("config error: %w", err)
		}
		// Config file not found — use defaults, which is fine
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}

	return cfg, nil
}

// WriteDefault writes the default configuration to the given directory.
func WriteDefault(dir string) (string, error) {
	path := filepath.Join(dir, ".devshield.yaml")
	content := `# .devshield.yaml — DevShield project configuration
# Generated by: devshield init
# Docs: https://github.com/NIRODH/devshield

version: "1"

scan:
  path: "."
  exclude:
    - "vendor/**"
    - "**/*_test.go"
    - "node_modules/**"

scanners:
  secrets:   { enabled: true,  tools: [gitleaks] }
  sast:      { enabled: true,  tools: [semgrep] }
  sca:       { enabled: true,  tools: [osv-scanner, govulncheck] }
  iac:       { enabled: true,  tools: [trivy, kics] }
  container: { enabled: true,  tools: [trivy, grype] }
  sbom:      { enabled: true,  tools: [syft] }
  dast:      { enabled: false, tools: [nuclei], target: "" }
  cloud:     { enabled: false, tools: [prowler], provider: "" }
  k8s:       { enabled: auto,  tools: [kubescape, kyverno] }
  cicd:      { enabled: auto,  tools: [legitify] }

thresholds:
  fail_on: high
  max_critical: 0
  max_high: 5

output:
  formats: [sarif, html, json]
  dir: ".devshield-reports"

suppressions: []
  # - id: "gitleaks:generic-api-key:config/test.yaml:42"
  #   reason: "Test fixture — not a real secret"
  #   expires: "2025-12-31"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}
	return path, nil
}

func setViperDefaults(v *viper.Viper) {
	v.SetDefault("version", "1")
	v.SetDefault("scan.path", ".")
	v.SetDefault("scan.exclude", []string{"vendor/**", "**/*_test.go", "node_modules/**"})
	v.SetDefault("thresholds.fail_on", "high")
	v.SetDefault("thresholds.max_critical", 0)
	v.SetDefault("thresholds.max_high", 5)
	v.SetDefault("output.formats", []string{"sarif", "html", "json"})
	v.SetDefault("output.dir", ".devshield-reports")
}
