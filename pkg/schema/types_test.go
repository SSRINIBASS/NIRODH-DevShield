package schema

import (
	"context"
	"testing"
)

// =============================================================================
// Severity tests
// =============================================================================

func TestSeverityWeight(t *testing.T) {
	tests := []struct {
		sev    Severity
		expect int
	}{
		{SeverityCritical, 5},
		{SeverityHigh, 4},
		{SeverityMedium, 3},
		{SeverityLow, 2},
		{SeverityInfo, 1},
		{Severity("unknown"), 0},
	}
	for _, tc := range tests {
		if got := tc.sev.Weight(); got != tc.expect {
			t.Errorf("Severity(%q).Weight() = %d, want %d", tc.sev, got, tc.expect)
		}
	}
}

func TestSeverityMeetsThreshold(t *testing.T) {
	tests := []struct {
		sev       Severity
		threshold Severity
		expect    bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityCritical, SeverityCritical, true},
		{SeverityHigh, SeverityCritical, false},
		{SeverityMedium, SeverityLow, true},
		{SeverityLow, SeverityMedium, false},
		{SeverityInfo, SeverityInfo, true},
	}
	for _, tc := range tests {
		if got := tc.sev.MeetsThreshold(tc.threshold); got != tc.expect {
			t.Errorf("%q.MeetsThreshold(%q) = %v, want %v", tc.sev, tc.threshold, got, tc.expect)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input  string
		expect Severity
	}{
		{"critical", SeverityCritical},
		{"CRITICAL", SeverityCritical},
		{"Critical", SeverityCritical},
		{"high", SeverityHigh},
		{"HIGH", SeverityHigh},
		{"medium", SeverityMedium},
		{"low", SeverityLow},
		{"info", SeverityInfo},
		{"", SeverityInfo},       // default
		{"garbage", SeverityInfo}, // default
	}
	for _, tc := range tests {
		if got := ParseSeverity(tc.input); got != tc.expect {
			t.Errorf("ParseSeverity(%q) = %q, want %q", tc.input, got, tc.expect)
		}
	}
}

func TestAllCategories(t *testing.T) {
	cats := AllCategories()
	if len(cats) != 10 {
		t.Errorf("AllCategories() returned %d items, want 10", len(cats))
	}
	// Verify secrets is first
	if cats[0] != CategorySecrets {
		t.Errorf("AllCategories()[0] = %q, want %q", cats[0], CategorySecrets)
	}
}

func TestAllSeverities(t *testing.T) {
	sevs := AllSeverities()
	if len(sevs) != 5 {
		t.Errorf("AllSeverities() returned %d items, want 5", len(sevs))
	}
	// Should be ordered critical → info
	if sevs[0] != SeverityCritical {
		t.Errorf("AllSeverities()[0] = %q, want %q", sevs[0], SeverityCritical)
	}
	if sevs[4] != SeverityInfo {
		t.Errorf("AllSeverities()[4] = %q, want %q", sevs[4], SeverityInfo)
	}
}

// =============================================================================
// ComputeSummary tests
// =============================================================================

func TestComputeSummary(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
		{Severity: SeverityLow},
		{Severity: SeverityInfo},
		{Severity: SeverityHigh, Suppressed: true}, // should be excluded
	}

	s := ComputeSummary(findings)

	if s.Critical != 2 {
		t.Errorf("Critical = %d, want 2", s.Critical)
	}
	if s.High != 1 {
		t.Errorf("High = %d, want 1", s.High)
	}
	if s.Medium != 1 {
		t.Errorf("Medium = %d, want 1", s.Medium)
	}
	if s.Low != 1 {
		t.Errorf("Low = %d, want 1", s.Low)
	}
	if s.Info != 1 {
		t.Errorf("Info = %d, want 1", s.Info)
	}
	if s.Total != 6 {
		t.Errorf("Total = %d, want 6 (suppressed excluded)", s.Total)
	}
}

func TestComputeSummary_Empty(t *testing.T) {
	s := ComputeSummary(nil)
	if s.Total != 0 {
		t.Errorf("Total = %d, want 0", s.Total)
	}
}

func TestComputeSummary_AllSuppressed(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical, Suppressed: true},
		{Severity: SeverityHigh, Suppressed: true},
	}
	s := ComputeSummary(findings)
	if s.Total != 0 {
		t.Errorf("Total = %d, want 0 (all suppressed)", s.Total)
	}
}

// =============================================================================
// ScanContext tests
// =============================================================================

func TestScanContext_HasLanguage(t *testing.T) {
	sc := &ScanContext{
		Languages: []Language{LangGo, LangPython, LangJavaScript},
		Ctx:       context.Background(),
	}

	if !sc.HasLanguage(LangGo) {
		t.Error("HasLanguage(Go) = false, want true")
	}
	if !sc.HasLanguage(LangPython) {
		t.Error("HasLanguage(Python) = false, want true")
	}
	if sc.HasLanguage(LangRust) {
		t.Error("HasLanguage(Rust) = true, want false")
	}
}

func TestScanContext_HasLanguage_Empty(t *testing.T) {
	sc := &ScanContext{Ctx: context.Background()}
	if sc.HasLanguage(LangGo) {
		t.Error("HasLanguage(Go) on empty context = true, want false")
	}
}
