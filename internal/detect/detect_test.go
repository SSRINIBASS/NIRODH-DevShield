package detect

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NIRODH/devshield/internal/config"
)

func TestDetectContext_GoProject(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a .go file
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}

	sc, err := DetectContext(tmpDir, config.DefaultConfig(), 5*time.Minute)
	if err != nil {
		t.Fatalf("DetectContext() error: %v", err)
	}

	if sc.RootPath == "" {
		t.Error("RootPath is empty")
	}

	foundGo := false
	for _, lang := range sc.Languages {
		if lang == "go" {
			foundGo = true
		}
	}
	if !foundGo {
		t.Error("Go language not detected, want detected")
	}
}

func TestDetectContext_MultiLanguage(t *testing.T) {
	tmpDir := t.TempDir()

	files := map[string]string{
		"main.go":     "package main",
		"app.py":      "print('hello')",
		"index.js":    "console.log('hi')",
		"style.css":   "body {}",
		"README.md":   "# test",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	sc, err := DetectContext(tmpDir, config.DefaultConfig(), 5*time.Minute)
	if err != nil {
		t.Fatalf("DetectContext() error: %v", err)
	}

	langs := make(map[string]bool)
	for _, l := range sc.Languages {
		langs[string(l)] = true
	}

	if !langs["go"] {
		t.Error("Go not detected")
	}
	if !langs["python"] {
		t.Error("Python not detected")
	}
	if !langs["javascript"] {
		t.Error("JavaScript not detected")
	}
}

func TestDetectContext_DockerDetection(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte("FROM alpine"), 0644); err != nil {
		t.Fatal(err)
	}

	sc, err := DetectContext(tmpDir, config.DefaultConfig(), 5*time.Minute)
	if err != nil {
		t.Fatalf("DetectContext() error: %v", err)
	}

	if !sc.HasDocker {
		t.Error("HasDocker = false, want true")
	}
}

func TestDetectContext_TerraformDetection(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("resource {}"), 0644); err != nil {
		t.Fatal(err)
	}

	sc, err := DetectContext(tmpDir, config.DefaultConfig(), 5*time.Minute)
	if err != nil {
		t.Fatalf("DetectContext() error: %v", err)
	}

	if !sc.HasTerraform {
		t.Error("HasTerraform = false, want true")
	}
}

func TestDetectContext_GitDetection(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a fake .git directory
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}

	sc, err := DetectContext(tmpDir, config.DefaultConfig(), 5*time.Minute)
	if err != nil {
		t.Fatalf("DetectContext() error: %v", err)
	}

	if !sc.HasGit {
		t.Error("HasGit = false, want true")
	}
}

func TestDetectContext_NoGit(t *testing.T) {
	tmpDir := t.TempDir()

	sc, err := DetectContext(tmpDir, config.DefaultConfig(), 5*time.Minute)
	if err != nil {
		t.Fatalf("DetectContext() error: %v", err)
	}

	if sc.HasGit {
		t.Error("HasGit = true, want false")
	}
}

func TestDetectContext_NilConfig(t *testing.T) {
	tmpDir := t.TempDir()

	sc, err := DetectContext(tmpDir, nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("DetectContext() error: %v", err)
	}

	if sc == nil {
		t.Error("ScanContext is nil")
	}
}

func TestShouldSkipDir(t *testing.T) {
	skip := []string{".git", "node_modules", "vendor", ".devshield-reports", "__pycache__", ".tox", ".venv", "venv", ".terraform"}
	for _, d := range skip {
		if !shouldSkipDir(d) {
			t.Errorf("shouldSkipDir(%q) = false, want true", d)
		}
	}

	allowed := []string{"src", "cmd", "internal", "pkg", "lib", "docs"}
	for _, d := range allowed {
		if shouldSkipDir(d) {
			t.Errorf("shouldSkipDir(%q) = true, want false", d)
		}
	}
}

func TestShouldExclude(t *testing.T) {
	cfg := &config.Config{
		Scan: config.ScanConfig{
			Exclude: []string{"vendor/**", "*_test.go"},
		},
	}

	// Should exclude
	if !shouldExclude("foo_test.go", cfg) {
		t.Error("shouldExclude(foo_test.go) = false, want true")
	}

	// Should not exclude
	if shouldExclude("main.go", cfg) {
		t.Error("shouldExclude(main.go) = true, want false")
	}

	// Nil config should not exclude anything
	if shouldExclude("anything.go", nil) {
		t.Error("shouldExclude with nil config = true, want false")
	}
}

func TestLooksLikeK8sManifest(t *testing.T) {
	tmpDir := t.TempDir()

	// K8s manifest
	k8sContent := `apiVersion: v1
kind: Pod
metadata:
  name: test-pod`
	k8sPath := filepath.Join(tmpDir, "pod.yaml")
	if err := os.WriteFile(k8sPath, []byte(k8sContent), 0644); err != nil {
		t.Fatal(err)
	}
	if !looksLikeK8sManifest(k8sPath) {
		t.Error("looksLikeK8sManifest(pod.yaml) = false, want true")
	}

	// Regular YAML (not K8s)
	regularContent := `name: my-app
version: 1.0.0`
	regularPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(regularPath, []byte(regularContent), 0644); err != nil {
		t.Fatal(err)
	}
	if looksLikeK8sManifest(regularPath) {
		t.Error("looksLikeK8sManifest(config.yaml) = true, want false")
	}
}
