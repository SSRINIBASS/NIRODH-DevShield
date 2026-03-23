package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Version != "1" {
		t.Errorf("Version = %q, want %q", cfg.Version, "1")
	}
	if cfg.Scan.Path != "." {
		t.Errorf("Scan.Path = %q, want %q", cfg.Scan.Path, ".")
	}
	if len(cfg.Scan.Exclude) != 3 {
		t.Errorf("Scan.Exclude has %d entries, want 3", len(cfg.Scan.Exclude))
	}
	if cfg.Thresholds.FailOn != "high" {
		t.Errorf("Thresholds.FailOn = %q, want %q", cfg.Thresholds.FailOn, "high")
	}
	if cfg.Thresholds.MaxCritical != 0 {
		t.Errorf("Thresholds.MaxCritical = %d, want 0", cfg.Thresholds.MaxCritical)
	}
	if cfg.Thresholds.MaxHigh != 5 {
		t.Errorf("Thresholds.MaxHigh = %d, want 5", cfg.Thresholds.MaxHigh)
	}
	if len(cfg.Output.Formats) != 3 {
		t.Errorf("Output.Formats has %d entries, want 3", len(cfg.Output.Formats))
	}
	if cfg.Output.Dir != ".devshield-reports" {
		t.Errorf("Output.Dir = %q, want %q", cfg.Output.Dir, ".devshield-reports")
	}
}

func TestDefaultConfig_Scanners(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Scanners.Secrets.IsEnabled() {
		t.Error("Secrets scanner should be enabled by default")
	}
	if cfg.Scanners.DAST.IsEnabled() {
		t.Error("DAST scanner should be disabled by default")
	}
	if !cfg.Scanners.K8s.IsAuto() {
		t.Error("K8s scanner should be set to 'auto' by default")
	}
}

func TestScannerCategoryConfig_IsEnabled(t *testing.T) {
	tests := []struct {
		name    string
		enabled interface{}
		want    bool
	}{
		{"bool true", true, true},
		{"bool false", false, false},
		{"string auto", "auto", true},
		{"string true", "true", true},
		{"string false", "false", false},
		{"nil defaults to true", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := ScannerCategoryConfig{Enabled: tc.enabled}
			if got := c.IsEnabled(); got != tc.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScannerCategoryConfig_IsAuto(t *testing.T) {
	tests := []struct {
		name    string
		enabled interface{}
		want    bool
	}{
		{"string auto", "auto", true},
		{"string true", "true", false},
		{"bool true", true, false},
		{"bool false", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := ScannerCategoryConfig{Enabled: tc.enabled}
			if got := c.IsAuto(); got != tc.want {
				t.Errorf("IsAuto() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLoad_NoConfigFile(t *testing.T) {
	// Load from a temp dir with no config file
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
	// Should return defaults
	if cfg.Version != "1" {
		t.Errorf("Version = %q, want %q", cfg.Version, "1")
	}
}

func TestLoad_WithConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	configContent := `
version: "2"
scan:
  path: "./src"
thresholds:
  fail_on: critical
output:
  dir: "my-reports"
  formats: [json]
`
	configPath := filepath.Join(tmpDir, ".devshield.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load(%q) error: %v", configPath, err)
	}
	if cfg.Version != "2" {
		t.Errorf("Version = %q, want %q", cfg.Version, "2")
	}
	if cfg.Thresholds.FailOn != "critical" {
		t.Errorf("Thresholds.FailOn = %q, want %q", cfg.Thresholds.FailOn, "critical")
	}
	if cfg.Output.Dir != "my-reports" {
		t.Errorf("Output.Dir = %q, want %q", cfg.Output.Dir, "my-reports")
	}
}

func TestWriteDefault(t *testing.T) {
	tmpDir := t.TempDir()

	path, err := WriteDefault(tmpDir)
	if err != nil {
		t.Fatalf("WriteDefault() error: %v", err)
	}

	expectedPath := filepath.Join(tmpDir, ".devshield.yaml")
	if path != expectedPath {
		t.Errorf("path = %q, want %q", path, expectedPath)
	}

	// File should exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("WriteDefault() did not create the file")
	}

	// File should be loadable
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}
	if len(content) == 0 {
		t.Error("Config file is empty")
	}
}
