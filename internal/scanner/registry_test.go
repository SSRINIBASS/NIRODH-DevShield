package scanner

import (
	"context"
	"testing"

	"github.com/NIRODH/devshield/pkg/schema"
)

// mockScanner is a test double that implements the Scanner interface.
type mockScanner struct {
	name      string
	category  schema.Category
	available bool
	version   string
}

func (m *mockScanner) Name() string              { return m.name }
func (m *mockScanner) Category() schema.Category { return m.category }
func (m *mockScanner) IsAvailable() bool          { return m.available }
func (m *mockScanner) Version() (string, error)   { return m.version, nil }
func (m *mockScanner) Scan(ctx context.Context, sc schema.ScanContext) ([]schema.Finding, error) {
	return nil, nil
}

func setup() {
	Reset()
}

func TestRegisterAndGet(t *testing.T) {
	setup()
	s := &mockScanner{name: "test-scanner", category: schema.CategorySecrets, available: true, version: "1.0.0"}
	Register(s)

	got := Get("test-scanner")
	if got == nil {
		t.Fatal("Get(test-scanner) returned nil")
	}
	if got.Name() != "test-scanner" {
		t.Errorf("Name() = %q, want %q", got.Name(), "test-scanner")
	}
}

func TestGet_NotFound(t *testing.T) {
	setup()
	if got := Get("nonexistent"); got != nil {
		t.Errorf("Get(nonexistent) = %v, want nil", got)
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	setup()
	s := &mockScanner{name: "dup-scanner", available: true}
	Register(s)

	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic on duplicate registration, got none")
		}
	}()
	Register(s) // should panic
}

func TestAll_OrderPreserved(t *testing.T) {
	setup()
	s1 := &mockScanner{name: "alpha", available: true}
	s2 := &mockScanner{name: "beta", available: true}
	s3 := &mockScanner{name: "gamma", available: true}
	Register(s1)
	Register(s2)
	Register(s3)

	all := All()
	if len(all) != 3 {
		t.Fatalf("All() returned %d scanners, want 3", len(all))
	}
	expected := []string{"alpha", "beta", "gamma"}
	for i, s := range all {
		if s.Name() != expected[i] {
			t.Errorf("All()[%d].Name() = %q, want %q", i, s.Name(), expected[i])
		}
	}
}

func TestAvailable_FiltersUnavailable(t *testing.T) {
	setup()
	Register(&mockScanner{name: "avail", available: true})
	Register(&mockScanner{name: "unavail", available: false})
	Register(&mockScanner{name: "avail2", available: true})

	avail := Available()
	if len(avail) != 2 {
		t.Fatalf("Available() returned %d, want 2", len(avail))
	}
	if avail[0].Name() != "avail" || avail[1].Name() != "avail2" {
		t.Errorf("Available() returned wrong scanners: %v, %v", avail[0].Name(), avail[1].Name())
	}
}

func TestNames(t *testing.T) {
	setup()
	Register(&mockScanner{name: "foo", available: true})
	Register(&mockScanner{name: "bar", available: true})

	names := Names()
	if len(names) != 2 {
		t.Fatalf("Names() returned %d items, want 2", len(names))
	}
	if names[0] != "foo" || names[1] != "bar" {
		t.Errorf("Names() = %v, want [foo bar]", names)
	}
}

func TestReset(t *testing.T) {
	setup()
	Register(&mockScanner{name: "will-be-cleared", available: true})
	Reset()

	if len(All()) != 0 {
		t.Errorf("After Reset(), All() returned %d items, want 0", len(All()))
	}
	if Get("will-be-cleared") != nil {
		t.Error("After Reset(), Get() still returned a scanner")
	}
}
