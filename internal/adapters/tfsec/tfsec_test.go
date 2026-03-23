package tfsec

import (
	"testing"
	"github.com/NIRODH/devshield/pkg/schema"
)

func TestScanner_Name(t *testing.T) {
	s := &Scanner{}
	if s.Name() != "tfsec" {
		t.Errorf("Name() = %q, want %q", s.Name(), "tfsec")
	}
}

func TestScanner_Category(t *testing.T) {
	s := &Scanner{}
	if s.Category() != schema.CategoryIaC {
		t.Errorf("Category() = %q, want IaC", s.Category())
	}
}

func TestMapSeverity(t *testing.T) {
	tests := []struct{
		input  string
		expect schema.Severity
	}{
		{"CRITICAL", schema.SeverityCritical},
		{"HIGH", schema.SeverityHigh},
		{"MEDIUM", schema.SeverityMedium},
		{"LOW", schema.SeverityLow},
		{"CUSTOM", schema.SeverityInfo},
	}
	for _, tc := range tests {
		if got := mapSeverity(tc.input); got != tc.expect {
			t.Errorf("mapSeverity(%q) = %q, want %q", tc.input, got, tc.expect)
		}
	}
}
