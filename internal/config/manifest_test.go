package config

import "testing"

func validManifest() *PluginManifest {
	return &PluginManifest{
		Name:     "demo",
		Image:    "demo:latest",
		Version:  "0.1.0",
		Schedule: ScheduleConfig{Mode: "daemon"},
	}
}

// An unset access level defaults to read-only (least privilege).
func TestManifest_AccessDefaultsReadonly(t *testing.T) {
	m := validManifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if m.Access != AccessReadOnly {
		t.Errorf("Access = %q, want %q", m.Access, AccessReadOnly)
	}
}

// Both explicit levels are accepted and preserved.
func TestManifest_AccessExplicitValues(t *testing.T) {
	for _, want := range []string{AccessReadOnly, AccessReadWrite} {
		m := validManifest()
		m.Access = want
		if err := m.Validate(); err != nil {
			t.Fatalf("validate %q: %v", want, err)
		}
		if m.Access != want {
			t.Errorf("Access = %q, want %q", m.Access, want)
		}
	}
}

// An unknown access level is rejected.
func TestManifest_AccessRejectsUnknown(t *testing.T) {
	m := validManifest()
	m.Access = "admin"
	if err := m.Validate(); err == nil {
		t.Error("expected error for unknown access level, got nil")
	}
}
