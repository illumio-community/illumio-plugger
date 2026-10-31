package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/container"
	"github.com/illumio/plugger/internal/plugin"
)

// stubRuntime is a no-op container.Runtime for handler tests that never reach
// the Docker socket. Only Stats matters here; the rest return zero values.
type stubRuntime struct {
	stats *container.ContainerStats
}

func (s stubRuntime) Pull(context.Context, string) error                           { return nil }
func (s stubRuntime) Create(context.Context, container.CreateOpts) (string, error) { return "", nil }
func (s stubRuntime) Start(context.Context, string) error                          { return nil }
func (s stubRuntime) Stop(context.Context, string, time.Duration) error            { return nil }
func (s stubRuntime) Remove(context.Context, string) error                         { return nil }
func (s stubRuntime) Inspect(context.Context, string) (*container.ContainerInfo, error) {
	return &container.ContainerInfo{}, nil
}
func (s stubRuntime) Logs(context.Context, string, container.LogOpts) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}
func (s stubRuntime) Wait(context.Context, string) (<-chan container.WaitResult, error) {
	return nil, nil
}
func (s stubRuntime) EnsureNetwork(context.Context, string) error { return nil }
func (s stubRuntime) ListManaged(context.Context) ([]container.ContainerInfo, error) {
	return nil, nil
}
func (s stubRuntime) CopyFromImage(context.Context, string, string) ([]byte, error) {
	return nil, nil
}
func (s stubRuntime) ImageDigest(context.Context, string) (string, error) { return "", nil }
func (s stubRuntime) Stats(context.Context, string) (*container.ContainerStats, error) {
	return s.stats, nil
}

func newTestHandler(t *testing.T, rt container.Runtime) *Handler {
	t.Helper()
	store := plugin.NewStore(t.TempDir())
	cfg := &config.Config{}
	cfg.Plugger.DataDir = t.TempDir()
	return NewHandler(store, rt, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// The metrics page must render through the layout without a template error and
// contain its heading, even with no plugins and no collector attached.
func TestHandleMetricsPage_Renders(t *testing.T) {
	h := newTestHandler(t, stubRuntime{})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.handleMetricsPage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Runtime Metrics") {
		t.Error("rendered page missing the 'Runtime Metrics' heading")
	}
	if !strings.Contains(body, "/api/metrics") {
		t.Error("rendered page missing the metrics API fetch")
	}
	// Layout wrapping (nav) must be present — confirms layout+content composed.
	if !strings.Contains(body, `href="/metrics"`) {
		t.Error("rendered page missing the nav link from layout")
	}
}

// The API returns an empty array (not null, not 500) before the collector runs.
func TestHandleAPIMetrics_EmptyBeforeCollector(t *testing.T) {
	h := newTestHandler(t, stubRuntime{})

	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	rec := httptest.NewRecorder()
	h.handleAPIMetrics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out []pluginMetric
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response not a JSON array: %v (body=%q)", err, rec.Body.String())
	}
	if len(out) != 0 {
		t.Errorf("len = %d, want 0 with no plugins", len(out))
	}
}

// With the collector attached and a plugin present, the API reports it with the
// health derived from its state.
func TestHandleAPIMetrics_WithCollector(t *testing.T) {
	h := newTestHandler(t, stubRuntime{stats: &container.ContainerStats{CPUPercent: 12, MemoryUsage: 1024}})
	started := time.Now().Add(-90 * time.Second)
	if err := h.deps.Store.Put(&plugin.Plugin{
		Name: "demo", State: plugin.StateRunning, ContainerID: "abc", LastStarted: &started,
	}); err != nil {
		t.Fatalf("seed plugin: %v", err)
	}
	h.metrics = newMetricsCollector(h)

	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	rec := httptest.NewRecorder()
	h.handleAPIMetrics(rec, req)

	var out []pluginMetric
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	if out[0].Name != "demo" || out[0].Health != "healthy" {
		t.Errorf("got %+v, want name=demo health=healthy", out[0])
	}
	if out[0].UptimeSecond < 80 {
		t.Errorf("uptime = %d, want ~90s", out[0].UptimeSecond)
	}
}
