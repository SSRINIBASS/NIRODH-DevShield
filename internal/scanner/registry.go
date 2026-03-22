package scanner

import (
	"fmt"
	"sync"
)

// registry holds all registered scanners. Thread-safe for concurrent access.
var (
	mu       sync.RWMutex
	scanners = make(map[string]Scanner)
	order    []string // preserves registration order
)

// Register adds a scanner to the global registry.
// Panics if a scanner with the same name is already registered.
func Register(s Scanner) {
	mu.Lock()
	defer mu.Unlock()

	name := s.Name()
	if _, exists := scanners[name]; exists {
		panic(fmt.Sprintf("scanner already registered: %s", name))
	}
	scanners[name] = s
	order = append(order, name)
}

// Get returns a registered scanner by name, or nil if not found.
func Get(name string) Scanner {
	mu.RLock()
	defer mu.RUnlock()
	return scanners[name]
}

// All returns all registered scanners in registration order.
func All() []Scanner {
	mu.RLock()
	defer mu.RUnlock()

	result := make([]Scanner, 0, len(order))
	for _, name := range order {
		result = append(result, scanners[name])
	}
	return result
}

// Available returns all registered scanners that report IsAvailable() == true.
func Available() []Scanner {
	mu.RLock()
	defer mu.RUnlock()

	result := make([]Scanner, 0, len(order))
	for _, name := range order {
		s := scanners[name]
		if s.IsAvailable() {
			result = append(result, s)
		}
	}
	return result
}

// Names returns the names of all registered scanners.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, len(order))
	copy(out, order)
	return out
}

// Reset clears the registry. Intended for testing only.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	scanners = make(map[string]Scanner)
	order = nil
}
