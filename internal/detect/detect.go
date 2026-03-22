// Package detect implements the project context detection engine.
// It scans the target directory to identify languages, infrastructure files,
// and other characteristics that determine which scanners should activate.
package detect

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NIRODH/devshield/internal/config"
	"github.com/NIRODH/devshield/pkg/schema"
)

// extensionToLanguage maps file extensions to languages.
var extensionToLanguage = map[string]schema.Language{
	".go":   schema.LangGo,
	".py":   schema.LangPython,
	".js":   schema.LangJavaScript,
	".jsx":  schema.LangJavaScript,
	".ts":   schema.LangTypeScript,
	".tsx":  schema.LangTypeScript,
	".java": schema.LangJava,
	".rs":   schema.LangRust,
	".rb":   schema.LangRuby,
	".php":  schema.LangPHP,
	".cs":   schema.LangCSharp,
	".cpp":  schema.LangCpp,
	".cc":   schema.LangCpp,
	".cxx":  schema.LangCpp,
	".c":    schema.LangC,
	".h":    schema.LangC,
	".swift": schema.LangSwift,
	".kt":   schema.LangKotlin,
	".kts":  schema.LangKotlin,
	".scala": schema.LangScala,
}

// terraformExtensions are file patterns indicating Terraform usage.
var terraformExtensions = []string{".tf", ".tfvars", ".tf.json"}

// dockerFiles are exact filenames indicating Docker usage.
var dockerFiles = []string{
	"Dockerfile", "dockerfile",
	"docker-compose.yml", "docker-compose.yaml",
	"compose.yml", "compose.yaml",
	"Containerfile",
}

// DetectContext scans the target directory and builds a ScanContext
// containing all detected project metadata.
func DetectContext(rootPath string, cfg *config.Config, timeout time.Duration) (*schema.ScanContext, error) {
	absPath, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, err
	}

	sc := &schema.ScanContext{
		RootPath: absPath,
		Config:   cfg,
		Timeout:  timeout,
	}

	langSet := make(map[schema.Language]bool)
	var hasTerraform, hasK8s, hasDocker, hasGit bool
	var gitRemote string

	// Check for .git directory
	if _, err := os.Stat(filepath.Join(absPath, ".git")); err == nil {
		hasGit = true
		gitRemote = detectGitRemote(absPath)
	}

	// Walk the directory tree (respecting exclude patterns)
	err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip files we can't access
		}

		// Skip hidden directories (except .git which we already checked)
		name := info.Name()
		if info.IsDir() {
			if shouldSkipDir(name) {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(absPath, path)
		if shouldExclude(rel, cfg) {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(name))

		// Language detection
		if lang, ok := extensionToLanguage[ext]; ok {
			langSet[lang] = true
		}

		// Terraform detection
		for _, tfExt := range terraformExtensions {
			if strings.HasSuffix(strings.ToLower(name), tfExt) {
				hasTerraform = true
				break
			}
		}

		// Docker detection
		for _, df := range dockerFiles {
			if name == df {
				hasDocker = true
				break
			}
		}

		// Kubernetes detection — look for YAML files with apiVersion
		if (ext == ".yaml" || ext == ".yml") && !hasTerraform {
			if looksLikeK8sManifest(path) {
				hasK8s = true
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Convert language set to slice
	languages := make([]schema.Language, 0, len(langSet))
	for lang := range langSet {
		languages = append(languages, lang)
	}

	sc.Languages = languages
	sc.HasTerraform = hasTerraform
	sc.HasK8s = hasK8s
	sc.HasDocker = hasDocker
	sc.HasGit = hasGit
	sc.GitRemote = gitRemote

	return sc, nil
}

// shouldSkipDir returns true for directories that should not be walked.
func shouldSkipDir(name string) bool {
	skip := map[string]bool{
		".git":         true,
		"node_modules": true,
		"vendor":       true,
		".devshield-reports": true,
		"__pycache__":  true,
		".tox":         true,
		".venv":        true,
		"venv":         true,
		".terraform":   true,
	}
	return skip[name]
}

// shouldExclude checks if a relative path matches any configured exclude pattern.
func shouldExclude(relPath string, cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, pattern := range cfg.Scan.Exclude {
		matched, err := filepath.Match(pattern, relPath)
		if err == nil && matched {
			return true
		}
		// Also try matching just the filename
		matched, err = filepath.Match(pattern, filepath.Base(relPath))
		if err == nil && matched {
			return true
		}
	}
	return false
}

// looksLikeK8sManifest checks if a YAML file contains apiVersion and kind fields,
// which are telltale signs of a Kubernetes manifest.
func looksLikeK8sManifest(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	hasAPIVersion := false
	hasKind := false
	lineCount := 0

	for scanner.Scan() && lineCount < 30 {
		line := strings.TrimSpace(scanner.Text())
		lineCount++
		if strings.HasPrefix(line, "apiVersion:") {
			hasAPIVersion = true
		}
		if strings.HasPrefix(line, "kind:") {
			hasKind = true
		}
		if hasAPIVersion && hasKind {
			return true
		}
	}
	return false
}

// detectGitRemote parses the git config to find the origin remote URL.
func detectGitRemote(rootPath string) string {
	configPath := filepath.Join(rootPath, ".git", "config")
	f, err := os.Open(configPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	inOrigin := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == `[remote "origin"]` {
			inOrigin = true
			continue
		}
		if inOrigin && strings.HasPrefix(line, "url = ") {
			url := strings.TrimPrefix(line, "url = ")
			// Normalize SSH URLs to HTTPS format for display
			url = strings.TrimSuffix(url, ".git")
			url = strings.Replace(url, "git@github.com:", "github.com/", 1)
			url = strings.Replace(url, "git@gitlab.com:", "gitlab.com/", 1)
			return url
		}
		if strings.HasPrefix(line, "[") && inOrigin {
			break // moved past [remote "origin"]
		}
	}
	return ""
}
