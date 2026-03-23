package semgrep

import (
	"testing"
	"github.com/NIRODH/devshield/pkg/schema"
)

func TestScanner_Name(t *testing.T) {
	s := &Scanner{}
	if s.Name() != "semgrep" {
		t.Errorf("Name() = %q, want %q", s.Name(), "semgrep")
	}
}

func TestScanner_Category(t *testing.T) {
	s := &Scanner{}
	if s.Category() != schema.CategorySAST {
		t.Errorf("Category() = %q, want SAST", s.Category())
	}
}

func TestScanner_IsAvailable(t *testing.T) {
	s := &Scanner{}
	// This might be false or true depending on the environment, just check it doesn't panic
	_ = s.IsAvailable()
}
