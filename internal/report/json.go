package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/NIRODH/devshield/pkg/schema"
)

// WriteJSON generates a JSON report from scan results per SRS Section 14.3.
func WriteJSON(result *schema.ScanResult, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}
