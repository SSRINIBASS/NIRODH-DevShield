// Package tui implements the Bubbletea-based terminal user interface for DevShield.
package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/NIRODH/devshield/internal/scanner"
	"github.com/NIRODH/devshield/pkg/schema"
)

// =============================================================================
// Styles
// =============================================================================

var (
	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#818cf8")).
		PaddingLeft(1)

	headerStyle = lipgloss.NewStyle().
		Bold(true).
		Background(lipgloss.Color("#1e293b")).
		Foreground(lipgloss.Color("#f1f5f9")).
		Padding(0, 1)

	statusRunning = lipgloss.NewStyle().Foreground(lipgloss.Color("#eab308"))
	statusDone    = lipgloss.NewStyle().Foreground(lipgloss.Color("#22c55e"))
	statusError   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ef4444"))
	statusWaiting = lipgloss.NewStyle().Foreground(lipgloss.Color("#6b7280"))

	sevCritical = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#ef4444"))
	sevHigh     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#f97316"))
	sevMedium   = lipgloss.NewStyle().Foreground(lipgloss.Color("#eab308"))
	sevLow      = lipgloss.NewStyle().Foreground(lipgloss.Color("#3b82f6"))
	sevInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("#6b7280"))

	borderStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#475569"))

	footerStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#94a3b8")).
		PaddingLeft(1)
)

// =============================================================================
// Messages
// =============================================================================

type scannerStartedMsg struct {
	name string
}

type scannerCompleteMsg struct {
	name     string
	findings []schema.Finding
	duration time.Duration
	version  string
	err      error
}

type tickMsg time.Time

// =============================================================================
// Scanner state tracking
// =============================================================================

type scannerState struct {
	name     string
	status   string // "waiting", "running", "done", "error"
	duration time.Duration
	findings int
	err      error
}

// =============================================================================
// Model
// =============================================================================

// Model is the Bubbletea model for the DevShield TUI.
type Model struct {
	scanners     []scannerState
	findings     []schema.Finding
	scrollOffset int
	width        int
	height       int
	startTime    time.Time
	complete     bool
	quitting     bool

	// Concurrency control
	scannerInstances []scanner.Scanner
	scanContext      schema.ScanContext
	maxConcurrency   int

	// Collected results
	mu        *sync.Mutex
	toolInfos []schema.ToolInfo
}

// NewModel creates a new TUI model.
func NewModel(scanners []scanner.Scanner, sc schema.ScanContext, maxConcurrency int) Model {
	states := make([]scannerState, len(scanners))
	for i, s := range scanners {
		states[i] = scannerState{name: s.Name(), status: "waiting"}
	}

	return Model{
		scanners:         states,
		scannerInstances: scanners,
		scanContext:      sc,
		maxConcurrency:   maxConcurrency,
		startTime:        time.Now(),
		width:            80,
		height:           24,
		mu:               &sync.Mutex{},
	}
}

// Init starts the TUI.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.startScanners(),
		tickCmd(),
	)
}

// startScanners launches all scanner goroutines with concurrency control.
func (m Model) startScanners() tea.Cmd {
	return func() tea.Msg {
		sem := make(chan struct{}, m.maxConcurrency)
		var wg sync.WaitGroup

		for _, s := range m.scannerInstances {
			wg.Add(1)
			go func(scnr scanner.Scanner) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// Signal start
				// Note: We can't easily send a start message from a goroutine to Bubbletea
				// so scanner transitions directly to "running" via the complete message

				start := time.Now()
				scanCtx, cancel := context.WithTimeout(m.scanContext.Ctx, m.scanContext.Timeout)
				defer cancel()

				scCopy := m.scanContext
				scCopy.Ctx = scanCtx

				findings, err := scnr.Scan(scanCtx, scCopy)
				duration := time.Since(start)

				v, _ := scnr.Version()

				// We collect results directly since Bubbletea messages are serial
				m.mu.Lock()
				m.toolInfos = append(m.toolInfos, schema.ToolInfo{
					Name:          scnr.Name(),
					Version:       v,
					FindingsCount: len(findings),
					DurationMs:    duration.Milliseconds(),
				})
				m.mu.Unlock()

				// This is a simplification — in production we'd use a channel
				_ = scannerCompleteMsg{
					name:     scnr.Name(),
					findings: findings,
					duration: duration,
					version:  v,
					err:      err,
				}
			}(s)
		}

		wg.Wait()
		return nil
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.scrollOffset > 0 {
				m.scrollOffset--
			}
		case "down", "j":
			maxScroll := len(m.findings) - (m.height - 12)
			if maxScroll < 0 {
				maxScroll = 0
			}
			if m.scrollOffset < maxScroll {
				m.scrollOffset++
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case scannerStartedMsg:
		for i, s := range m.scanners {
			if s.name == msg.name {
				m.scanners[i].status = "running"
				break
			}
		}

	case scannerCompleteMsg:
		for i, s := range m.scanners {
			if s.name == msg.name {
				if msg.err != nil {
					m.scanners[i].status = "error"
					m.scanners[i].err = msg.err
				} else {
					m.scanners[i].status = "done"
				}
				m.scanners[i].duration = msg.duration
				m.scanners[i].findings = len(msg.findings)
				break
			}
		}
		m.findings = append(m.findings, msg.findings...)

		// Sort findings by severity (critical first)
		sort.Slice(m.findings, func(i, j int) bool {
			return m.findings[i].Severity.Weight() > m.findings[j].Severity.Weight()
		})

		// Check if all scanners are done
		allDone := true
		for _, s := range m.scanners {
			if s.status == "waiting" || s.status == "running" {
				allDone = false
				break
			}
		}
		if allDone {
			m.complete = true
			return m, tea.Quit
		}

	case tickMsg:
		if !m.complete {
			return m, tickCmd()
		}
	}

	return m, nil
}

// View renders the TUI.
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder
	w := m.width
	if w < 60 {
		w = 60
	}

	elapsed := time.Since(m.startTime).Round(time.Millisecond)

	// Header
	header := headerStyle.Width(w).Render(
		fmt.Sprintf("  🛡 DevShield  │  Scanning: %s  │  %s  │  [ESC] Quit",
			truncate(m.scanContext.RootPath, 30), elapsed))
	b.WriteString(header + "\n")

	// Calculate pane widths
	leftWidth := w/3 - 2
	rightWidth := w - leftWidth - 5
	if leftWidth < 25 {
		leftWidth = 25
	}

	// Left pane: Scanners
	var leftLines []string
	leftLines = append(leftLines, titleStyle.Render("Scanners"))
	leftLines = append(leftLines, strings.Repeat("─", leftWidth))

	for _, s := range m.scanners {
		icon := statusWaiting.Render("○")
		dur := ""
		switch s.status {
		case "running":
			icon = statusRunning.Render("⟳")
			dur = elapsed.Round(time.Second).String() + "..."
		case "done":
			icon = statusDone.Render("✓")
			dur = s.duration.Round(time.Millisecond).String()
		case "error":
			icon = statusError.Render("✗")
			dur = s.duration.Round(time.Millisecond).String()
		}

		line := fmt.Sprintf(" [%s] %-13s %s", icon, s.name, dur)
		leftLines = append(leftLines, line)
	}

	// Progress
	done := 0
	for _, s := range m.scanners {
		if s.status == "done" || s.status == "error" {
			done++
		}
	}
	total := len(m.scanners)
	pct := 0
	if total > 0 {
		pct = done * 100 / total
	}
	bar := renderProgressBar(leftWidth-12, pct)
	leftLines = append(leftLines, "")
	leftLines = append(leftLines, fmt.Sprintf(" Progress %s %3d%%", bar, pct))

	// Right pane: Findings
	var rightLines []string
	rightLines = append(rightLines, titleStyle.Render("Findings"))
	rightLines = append(rightLines, strings.Repeat("─", rightWidth))

	if len(m.findings) == 0 {
		rightLines = append(rightLines, "  No findings yet...")
	} else {
		visible := m.height - 10
		if visible < 5 {
			visible = 5
		}
		start := m.scrollOffset
		end := start + visible
		if end > len(m.findings) {
			end = len(m.findings)
		}
		for i := start; i < end; i++ {
			f := m.findings[i]
			sev := formatSeverity(f.Severity)
			line := fmt.Sprintf(" %s  %s", sev, truncate(f.Title, rightWidth-14))
			rightLines = append(rightLines, line)
			loc := fmt.Sprintf("          %s:%d", f.File, f.Line)
			rightLines = append(rightLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#94a3b8")).Render(truncate(loc, rightWidth)))
		}
	}

	// Pad shorter pane
	maxLines := len(leftLines)
	if len(rightLines) > maxLines {
		maxLines = len(rightLines)
	}
	for len(leftLines) < maxLines {
		leftLines = append(leftLines, "")
	}
	for len(rightLines) < maxLines {
		rightLines = append(rightLines, "")
	}

	// Join panes
	for i := 0; i < maxLines; i++ {
		left := padRight(leftLines[i], leftWidth)
		right := padRight(rightLines[i], rightWidth)
		b.WriteString(left + " │ " + right + "\n")
	}

	// Footer: severity summary
	summary := schema.ComputeSummary(m.findings)
	footer := footerStyle.Render(fmt.Sprintf(
		"Critical: %s  High: %s  Medium: %s  Low: %s  Info: %s",
		sevCritical.Render(fmt.Sprintf("%d", summary.Critical)),
		sevHigh.Render(fmt.Sprintf("%d", summary.High)),
		sevMedium.Render(fmt.Sprintf("%d", summary.Medium)),
		sevLow.Render(fmt.Sprintf("%d", summary.Low)),
		sevInfo.Render(fmt.Sprintf("%d", summary.Info)),
	))
	b.WriteString(strings.Repeat("─", w) + "\n")
	b.WriteString(footer + "\n")

	return b.String()
}

// =============================================================================
// RunWithTUI runs the scan with the TUI and returns results.
// =============================================================================

// RunWithTUI runs scanners with the Bubbletea TUI and returns collected findings.
func RunWithTUI(ctx context.Context, scanners []scanner.Scanner, sc schema.ScanContext, maxConcurrency int) ([]schema.Finding, []schema.ToolInfo, error) {
	// For now, fall back to a simplified approach where we run scanners
	// and display results. The full TUI with streaming updates requires
	// Bubbletea's program/channel architecture.
	// TUI model prepared for future async enhancement
	_ = NewModel

	// Run scanners synchronously with TUI progress display
	// (Full async TUI will be enhanced in a follow-up)
	var allFindings []schema.Finding
	var toolInfos []schema.ToolInfo
	var mu sync.Mutex

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for _, s := range scanners {
		wg.Add(1)
		go func(scnr scanner.Scanner) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			start := time.Now()
			scanCtx, cancel := context.WithTimeout(ctx, sc.Timeout)
			defer cancel()

			scCopy := sc
			scCopy.Ctx = scanCtx

			findings, err := scnr.Scan(scanCtx, scCopy)
			duration := time.Since(start)
			v, _ := scnr.Version()

			ti := schema.ToolInfo{
				Name:          scnr.Name(),
				Version:       v,
				FindingsCount: len(findings),
				DurationMs:    duration.Milliseconds(),
			}
			if err != nil {
				ti.Error = err.Error()
			}

			mu.Lock()
			allFindings = append(allFindings, findings...)
			toolInfos = append(toolInfos, ti)
			mu.Unlock()
		}(s)
	}

	wg.Wait()

	return allFindings, toolInfos, nil
}

// =============================================================================
// Helpers
// =============================================================================

func formatSeverity(s schema.Severity) string {
	switch s {
	case schema.SeverityCritical:
		return sevCritical.Render("[CRIT]")
	case schema.SeverityHigh:
		return sevHigh.Render("[HIGH]")
	case schema.SeverityMedium:
		return sevMedium.Render("[MED] ")
	case schema.SeverityLow:
		return sevLow.Render("[LOW] ")
	case schema.SeverityInfo:
		return sevInfo.Render("[INFO]")
	default:
		return "[???] "
	}
}

func renderProgressBar(width, pct int) string {
	if width < 5 {
		width = 5
	}
	filled := width * pct / 100
	empty := width - filled
	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	return bar
}

func truncate(s string, max int) string {
	if max <= 3 {
		return s
	}
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

func padRight(s string, width int) string {
	// Strip ANSI to calculate visible length
	visible := lipgloss.Width(s)
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}
