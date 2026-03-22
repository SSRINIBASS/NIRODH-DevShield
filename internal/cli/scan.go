package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/NIRODH/devshield/internal/config"
	"github.com/NIRODH/devshield/internal/detect"
	"github.com/NIRODH/devshield/internal/report"
	"github.com/NIRODH/devshield/internal/scanner"
	"github.com/NIRODH/devshield/internal/suppress"
	"github.com/NIRODH/devshield/internal/tui"
	"github.com/NIRODH/devshield/pkg/schema"
)

var (
	scanOnly string
	scanSkip string
	scanFull bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Run security scanners on the target path",
	Long: `Run all auto-detected security scanners on the target directory.
By default, DevShield detects the project type and activates relevant scanners.

Examples:
  devshield scan .
  devshield scan --full
  devshield scan --only secrets
  devshield scan --skip sast
  devshield scan --fail-on critical`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanOnly, "only", "", "Run only specified scanner categories (comma-separated)")
	scanCmd.Flags().StringVar(&scanSkip, "skip", "", "Skip specified scanner categories (comma-separated)")
	scanCmd.Flags().BoolVar(&scanFull, "full", false, "Run every scanner including opt-in")
}

func runScan(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	// Determine scan path
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	// Verify path exists
	if _, err := os.Stat(scanPath); err != nil {
		return fmt.Errorf("scan path does not exist: %s", scanPath)
	}

	// Load config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	// Override config with CLI flags
	if outputDir != "" {
		cfg.Output.Dir = outputDir
	}
	if formats != "" {
		cfg.Output.Formats = strings.Split(formats, ",")
	}
	if failOn != "" {
		cfg.Thresholds.FailOn = failOn
	}

	// Parse timeout
	scanTimeout, err := time.ParseDuration(timeout)
	if err != nil {
		return fmt.Errorf("invalid timeout: %w", err)
	}

	// Detect project context
	log.Debug().Str("path", scanPath).Msg("Detecting project context...")
	sc, err := detect.DetectContext(scanPath, cfg, scanTimeout)
	if err != nil {
		return fmt.Errorf("context detection failed: %w", err)
	}

	// Create temp dir
	tmpDir, err := os.MkdirTemp("", "devshield-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	sc.TempDir = tmpDir

	log.Debug().
		Strs("languages", languageStrings(sc.Languages)).
		Bool("git", sc.HasGit).
		Bool("docker", sc.HasDocker).
		Bool("terraform", sc.HasTerraform).
		Bool("k8s", sc.HasK8s).
		Str("remote", sc.GitRemote).
		Msg("Context detected")

	// Get available scanners
	allScanners := scanner.Available()
	activeScanners := filterScanners(allScanners, cfg, sc)

	if len(activeScanners) == 0 {
		fmt.Println("⚠  No scanners available. Run 'devshield install' to set up scanner tools.")
		return nil
	}

	// Determine concurrency
	maxConcurrency := concurrency
	if maxConcurrency <= 0 {
		maxConcurrency = runtime.NumCPU() / 2
		if maxConcurrency < 1 {
			maxConcurrency = 1
		}
	}

	// Set up scan context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sc.Ctx = ctx

	// Determine whether to use TUI or plain text
	isTTY := isTerminal()
	useTUI := isTTY && !noTUI

	var allFindings []schema.Finding
	var toolInfos []schema.ToolInfo
	var mu sync.Mutex

	if useTUI {
		// Run with TUI
		allFindings, toolInfos, err = tui.RunWithTUI(ctx, activeScanners, *sc, maxConcurrency)
		if err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
	} else {
		// Plain text mode
		fmt.Printf("DevShield %s — Scanning: %s\n", Version, sc.RootPath)
		fmt.Printf("Scanners: %d active\n\n", len(activeScanners))

		sem := make(chan struct{}, maxConcurrency)
		var wg sync.WaitGroup

		for _, s := range activeScanners {
			wg.Add(1)
			go func(sc2 schema.ScanContext, scnr scanner.Scanner) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				scannerStart := time.Now()
				name := scnr.Name()
				fmt.Printf("  [⟳] %s running...\n", name)

				// Create per-scanner context with timeout
				scanCtx, scanCancel := context.WithTimeout(ctx, sc2.Timeout)
				defer scanCancel()
				sc2.Ctx = scanCtx

				findings, scanErr := scnr.Scan(scanCtx, sc2)
				duration := time.Since(scannerStart)

				v, _ := scnr.Version()
				ti := schema.ToolInfo{
					Name:          name,
					Version:       v,
					FindingsCount: len(findings),
					DurationMs:    duration.Milliseconds(),
				}

				if scanErr != nil {
					ti.Error = scanErr.Error()
					fmt.Printf("  [✗] %s failed: %v\n", name, scanErr)
				} else {
					fmt.Printf("  [✓] %s completed (%d findings, %s)\n", name, len(findings), duration.Round(time.Millisecond))
				}

				mu.Lock()
				allFindings = append(allFindings, findings...)
				toolInfos = append(toolInfos, ti)
				mu.Unlock()
			}(*sc, s)
		}

		wg.Wait()
	}

	// Apply suppressions
	suppressEngine, err := suppress.NewEngine(sc.RootPath, toConfigSuppressions(cfg.Suppressions))
	if err != nil {
		log.Warn().Err(err).Msg("Suppression engine init failed")
	} else {
		allFindings = suppressEngine.Apply(allFindings)
	}

	// Compute summary
	summary := schema.ComputeSummary(allFindings)
	duration := time.Since(startTime)

	// Build scan result
	result := &schema.ScanResult{
		Version:             Version,
		ScanTimestamp:        startTime.UTC().Format(time.RFC3339),
		ScanDurationSeconds: duration.Seconds(),
		ProjectPath:         sc.RootPath,
		Context: schema.ScanResultContext{
			Languages: sc.Languages,
			HasK8s:    sc.HasK8s,
			HasDocker: sc.HasDocker,
			HasIaC:    sc.HasTerraform,
			HasGit:    sc.HasGit,
		},
		Summary:   summary,
		ToolsUsed: toolInfos,
		Findings:  allFindings,
	}

	// Generate reports
	if err := report.Generate(result, cfg); err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	// Print summary
	fmt.Println()
	fmt.Printf("── Scan Complete (%s) ──\n", duration.Round(time.Millisecond))
	fmt.Printf("  Critical: %d  High: %d  Medium: %d  Low: %d  Info: %d  Total: %d\n",
		summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info, summary.Total)
	fmt.Printf("  Reports: %s\n", cfg.Output.Dir)

	// Exit code based on thresholds
	threshold := schema.ParseSeverity(cfg.Thresholds.FailOn)
	for _, f := range allFindings {
		if !f.Suppressed && f.Severity.MeetsThreshold(threshold) {
			return fmt.Errorf("findings exceed threshold (%s): %d total findings", cfg.Thresholds.FailOn, summary.Total)
		}
	}

	return nil
}

// filterScanners selects scanners based on config, CLI flags, and detected context.
func filterScanners(all []scanner.Scanner, cfg *config.Config, sc *schema.ScanContext) []scanner.Scanner {
	// Parse --only and --skip
	onlySet := parseCategories(scanOnly)
	skipSet := parseCategories(scanSkip)

	var result []scanner.Scanner
	for _, s := range all {
		cat := string(s.Category())

		// --only filter
		if len(onlySet) > 0 {
			if _, ok := onlySet[cat]; !ok {
				continue
			}
		}

		// --skip filter
		if _, ok := skipSet[cat]; ok {
			continue
		}

		result = append(result, s)
	}

	return result
}

func parseCategories(s string) map[string]bool {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	m := make(map[string]bool, len(parts))
	for _, p := range parts {
		m[strings.TrimSpace(p)] = true
	}
	return m
}

func languageStrings(langs []schema.Language) []string {
	out := make([]string, len(langs))
	for i, l := range langs {
		out[i] = string(l)
	}
	return out
}

func toConfigSuppressions(entries []config.SuppressionEntry) []suppress.ConfigSuppression {
	result := make([]suppress.ConfigSuppression, len(entries))
	for i, e := range entries {
		result[i] = suppress.ConfigSuppression{
			ID:      e.ID,
			Reason:  e.Reason,
			Expires: e.Expires,
		}
	}
	return result
}

// isTerminal checks if stdout is connected to a terminal.
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
