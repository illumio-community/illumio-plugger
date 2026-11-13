package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/illumio/plugger/internal/registry"
)

// seedRegistryCache writes a cached official registry so accessLevels can fall
// back to it without any network access.
func seedRegistryCache(t *testing.T, dataDir string, plugins ...registry.Plugin) {
	t.Helper()
	dir := filepath.Join(dataDir, "cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(registry.Registry{Name: registry.OfficialRegistryName, Plugins: plugins})
	if err := os.WriteFile(filepath.Join(dir, registry.OfficialRegistryName+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAccessLevels_ManifestWinsThenRegistryThenDefault(t *testing.T) {
	h := newTestHandler(t, stubRuntime{})
	seedRegistryCache(t, h.deps.Config.Plugger.DataDir,
		registry.Plugin{Name: "declared", Access: "readonly"}, // manifest says readwrite -> manifest wins
		registry.Plugin{Name: "legacy", Access: "readwrite"},  // stored manifest predates the field
		registry.Plugin{Name: "untagged"},                     // registry predates the field too
	)

	declared := &plugin.Plugin{Name: "declared"}
	declared.Manifest.Access = config.AccessReadWrite
	plugins := []*plugin.Plugin{declared, {Name: "legacy"}, {Name: "untagged"}, {Name: "unknown"}}

	got := h.accessLevels(plugins)
	want := map[string]string{
		"declared": "readwrite",
		"legacy":   "readwrite",
		"untagged": "readonly",
		"unknown":  "readonly",
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: access = %q, want %q", name, got[name], w)
		}
	}
}

// Every page that lists plugins must show the badge, including for a plugin
// whose stored manifest has no access field (the pre-field install case).
func TestPages_RenderAccessBadge(t *testing.T) {
	h := newTestHandler(t, stubRuntime{})
	seedRegistryCache(t, h.deps.Config.Plugger.DataDir, registry.Plugin{Name: "legacy", Access: "readwrite"})

	legacy := &plugin.Plugin{Name: "legacy", State: plugin.StateStopped}
	legacy.Manifest.Env = []config.EnvVar{{Name: "POLL_INTERVAL", Default: "60"}} // gives it a config section
	ro := &plugin.Plugin{Name: "ro", State: plugin.StateRunning}
	ro.Manifest.Access = config.AccessReadOnly
	ro.Manifest.Env = legacy.Manifest.Env
	for _, p := range []*plugin.Plugin{legacy, ro} {
		if err := h.deps.Store.Put(p); err != nil {
			t.Fatal(err)
		}
	}

	pages := map[string]http.HandlerFunc{
		"/":               h.handleIndex,
		"/config":         h.handleConfigAll,
		"/plugins/legacy": h.handlePluginDetail,
	}
	for path, fn := range pages {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.SetPathValue("name", "legacy")
		rec := httptest.NewRecorder()
		fn(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, ">read-write<") {
			t.Errorf("%s: missing read-write badge for the registry-backed plugin", path)
		}
		if path != "/plugins/legacy" && !strings.Contains(body, ">read-only<") {
			t.Errorf("%s: missing read-only badge", path)
		}
	}
}

// The config page wraps each plugin in a collapsible section whose inputs are
// still part of the form (closed <details> content is submitted by browsers).
func TestConfigAll_CollapsibleSections(t *testing.T) {
	h := newTestHandler(t, stubRuntime{})
	p := &plugin.Plugin{Name: "demo", State: plugin.StateRunning, EnvOverrides: map[string]string{"POLL_INTERVAL": "30"}}
	p.Manifest.Env = []config.EnvVar{{Name: "POLL_INTERVAL", Default: "60"}, {Name: "TOKEN", Secret: true}}
	if err := h.deps.Store.Put(p); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.handleConfigAll(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	body := rec.Body.String()

	for _, want := range []string{
		`<details class="cfg-section`, `data-plugin="demo"`, `2 settings`, `1 modified`,
		`name="demo::POLL_INTERVAL"`, `name="demo::TOKEN"`, `setAllSections`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("config page missing %q", want)
		}
	}
	if idx := strings.Index(body, "<details"); idx < 0 || strings.Index(body, "<form") > idx {
		t.Error("sections must be inside the form so collapsed inputs are submitted")
	}
}
