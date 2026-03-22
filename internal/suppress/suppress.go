// Package suppress implements the finding suppression engine.
// It parses .devshield-ignore files and applies suppression rules
// to findings, respecting expiry dates.
package suppress

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NIRODH/devshield/pkg/schema"
)

// Suppression represents a single suppression rule.
type Suppression struct {
	ID      string     // Finding fingerprint or ID to suppress
	Reason  string     // Human-readable reason for suppression
	Expires *time.Time // Expiry date (nil = never expires)
}

// Engine manages finding suppressions.
type Engine struct {
	suppressions []Suppression
}

// NewEngine creates a suppression engine from the .devshield-ignore file
// and any inline suppressions from the config.
func NewEngine(rootPath string, configSuppressions []ConfigSuppression) (*Engine, error) {
	e := &Engine{}

	// Load from .devshield-ignore file
	ignorePath := filepath.Join(rootPath, ".devshield-ignore")
	if _, err := os.Stat(ignorePath); err == nil {
		sups, err := parseIgnoreFile(ignorePath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse .devshield-ignore: %w", err)
		}
		e.suppressions = append(e.suppressions, sups...)
	}

	// Load from config suppressions
	for _, cs := range configSuppressions {
		s := Suppression{
			ID:     cs.ID,
			Reason: cs.Reason,
		}
		if cs.Expires != "" {
			t, err := time.Parse("2006-01-02", cs.Expires)
			if err == nil {
				s.Expires = &t
			}
		}
		e.suppressions = append(e.suppressions, s)
	}

	return e, nil
}

// ConfigSuppression represents a suppression entry from the config file.
type ConfigSuppression struct {
	ID      string
	Reason  string
	Expires string
}

// Apply marks matching findings as suppressed.
// Expired suppressions are ignored (findings remain active).
func (e *Engine) Apply(findings []schema.Finding) []schema.Finding {
	now := time.Now()
	activeSuppressions := make(map[string]Suppression)

	for _, s := range e.suppressions {
		// Skip expired suppressions
		if s.Expires != nil && s.Expires.Before(now) {
			continue
		}
		activeSuppressions[s.ID] = s
	}

	for i := range findings {
		// Match by fingerprint or by ID
		if _, ok := activeSuppressions[findings[i].Fingerprint]; ok {
			findings[i].Suppressed = true
		} else if _, ok := activeSuppressions[findings[i].ID]; ok {
			findings[i].Suppressed = true
		}
	}

	return findings
}

// parseIgnoreFile parses a .devshield-ignore file.
// Format:
//
//	# Comment
//	<finding-id-or-fingerprint> # reason: <reason> expires: <YYYY-MM-DD>
func parseIgnoreFile(path string) ([]Suppression, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var suppressions []Suppression
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		s := Suppression{}

		// Split on # to separate ID from metadata
		parts := strings.SplitN(line, "#", 2)
		s.ID = strings.TrimSpace(parts[0])

		if len(parts) > 1 {
			metadata := parts[1]
			// Parse reason
			if idx := strings.Index(metadata, "reason:"); idx >= 0 {
				rest := metadata[idx+7:]
				if expIdx := strings.Index(rest, "expires:"); expIdx >= 0 {
					s.Reason = strings.TrimSpace(rest[:expIdx])
				} else {
					s.Reason = strings.TrimSpace(rest)
				}
			}
			// Parse expires
			if idx := strings.Index(metadata, "expires:"); idx >= 0 {
				dateStr := strings.TrimSpace(metadata[idx+8:])
				// Take first word as date
				if spaceIdx := strings.IndexByte(dateStr, ' '); spaceIdx >= 0 {
					dateStr = dateStr[:spaceIdx]
				}
				t, err := time.Parse("2006-01-02", dateStr)
				if err == nil {
					s.Expires = &t
				}
			}
		}

		if s.ID != "" {
			suppressions = append(suppressions, s)
		}
	}

	return suppressions, scanner.Err()
}
