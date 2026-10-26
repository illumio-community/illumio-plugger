package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeRepos persists a repos.json into a fresh dataDir and returns a Manager.
func writeRepos(t *testing.T, repos []RepoEntry) *Manager {
	t.Helper()
	dir := t.TempDir()
	if repos != nil {
		data, err := json.Marshal(RepoConfig{Repos: repos})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "repos.json"), data, 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return NewManager(dir)
}

func officialURL(t *testing.T, cfg *RepoConfig) string {
	t.Helper()
	for _, r := range cfg.Repos {
		if r.Name == OfficialRegistryName {
			return r.URL
		}
	}
	t.Fatalf("official registry missing from %+v", cfg.Repos)
	return ""
}

// A stale official URL (e.g. persisted before the alexgoller -> illumio-community
// move) must be reconciled to the canonical URL, not frozen forever. Existing
// users can't fix it themselves: official is non-removable.
func TestLoadRepos_ReconcilesStaleOfficialURL(t *testing.T) {
	m := writeRepos(t, []RepoEntry{
		{Name: OfficialRegistryName, URL: "https://alexgoller.github.io/illumio-plugger/registry.json"},
	})
	cfg, err := m.loadRepos()
	if err != nil {
		t.Fatalf("loadRepos: %v", err)
	}
	if got := officialURL(t, cfg); got != OfficialRegistryURL {
		t.Errorf("official URL not reconciled: got %q, want %q", got, OfficialRegistryURL)
	}
}

// Reconciling the official entry must not drop or reorder custom repos.
func TestLoadRepos_PreservesCustomRepos(t *testing.T) {
	custom := RepoEntry{Name: "myco", URL: "https://internal.example.com/registry.json"}
	m := writeRepos(t, []RepoEntry{
		{Name: OfficialRegistryName, URL: "https://old.example.com/registry.json"},
		custom,
	})
	cfg, err := m.loadRepos()
	if err != nil {
		t.Fatalf("loadRepos: %v", err)
	}
	if got := officialURL(t, cfg); got != OfficialRegistryURL {
		t.Errorf("official URL not reconciled: got %q, want %q", got, OfficialRegistryURL)
	}
	found := false
	for _, r := range cfg.Repos {
		if r.Name == custom.Name {
			found = true
			if r.URL != custom.URL {
				t.Errorf("custom repo URL changed: got %q, want %q", r.URL, custom.URL)
			}
		}
	}
	if !found {
		t.Errorf("custom repo %q dropped from %+v", custom.Name, cfg.Repos)
	}
}

// A config with no official entry must get one prepended.
func TestLoadRepos_AddsMissingOfficial(t *testing.T) {
	m := writeRepos(t, []RepoEntry{
		{Name: "myco", URL: "https://internal.example.com/registry.json"},
	})
	cfg, err := m.loadRepos()
	if err != nil {
		t.Fatalf("loadRepos: %v", err)
	}
	if got := officialURL(t, cfg); got != OfficialRegistryURL {
		t.Errorf("official URL: got %q, want %q", got, OfficialRegistryURL)
	}
}

// No repos.json at all yields the official default.
func TestLoadRepos_DefaultWhenMissing(t *testing.T) {
	m := writeRepos(t, nil)
	cfg, err := m.loadRepos()
	if err != nil {
		t.Fatalf("loadRepos: %v", err)
	}
	if got := officialURL(t, cfg); got != OfficialRegistryURL {
		t.Errorf("official URL: got %q, want %q", got, OfficialRegistryURL)
	}
}
