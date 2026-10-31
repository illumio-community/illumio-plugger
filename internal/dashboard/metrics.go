package dashboard

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/illumio/plugger/internal/plugin"
)

// metricWindow is how many samples the collector keeps per plugin. At the
// sample interval below this is the length of the sparkline history shown on
// the dashboard. It is an in-memory ring only — nothing is persisted, so a
// daemon restart starts the history fresh (matching how plugger already
// treats runtime state).
const (
	metricWindow   = 60
	metricInterval = 10 * time.Second
)

// RestartCounter is the subset of the scheduler set the metrics collector needs:
// lifetime restart counts per plugin. run.go's schedulerRestarter implements it.
// It is optional — when absent, restart counts render as 0.
type RestartCounter interface {
	RestartCounts() map[string]int
}

// sample is one point-in-time reading for a plugin.
type sample struct {
	T           time.Time `json:"t"`
	CPUPercent  float64   `json:"cpu"`
	MemoryUsage uint64    `json:"mem"`
	MemoryLimit uint64    `json:"memLimit"`
}

// ring is a fixed-capacity buffer of the most recent samples, oldest evicted
// first. Not safe for concurrent use on its own — the collector guards it.
type ring struct {
	buf []sample
	cap int
}

func newRing(capacity int) *ring { return &ring{cap: capacity} }

func (r *ring) add(s sample) {
	r.buf = append(r.buf, s)
	if len(r.buf) > r.cap {
		r.buf = r.buf[len(r.buf)-r.cap:]
	}
}

// snapshot returns a copy of the samples, oldest first.
func (r *ring) snapshot() []sample {
	out := make([]sample, len(r.buf))
	copy(out, r.buf)
	return out
}

func (r *ring) last() (sample, bool) {
	if len(r.buf) == 0 {
		return sample{}, false
	}
	return r.buf[len(r.buf)-1], true
}

// MetricsCollector samples running plugins on a ticker and keeps a short
// in-memory history per plugin for the dashboard to chart.
type MetricsCollector struct {
	h *Handler

	mu    sync.Mutex
	rings map[string]*ring
}

func newMetricsCollector(h *Handler) *MetricsCollector {
	return &MetricsCollector{h: h, rings: map[string]*ring{}}
}

// Start runs the sampling loop until ctx is cancelled. It takes one sample
// immediately so the first page load has data, then every metricInterval.
func (m *MetricsCollector) Start(ctx context.Context) {
	go func() {
		m.sampleOnce(ctx)
		t := time.NewTicker(metricInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.sampleOnce(ctx)
			}
		}
	}()
}

// sampleOnce reads CPU/memory for every running plugin and appends to its ring.
// Plugins that aren't running, or whose stats can't be read, are skipped rather
// than failing the whole pass.
func (m *MetricsCollector) sampleOnce(ctx context.Context) {
	plugins, err := m.h.deps.Store.List()
	if err != nil {
		return
	}
	for _, p := range plugins {
		if p.State != plugin.StateRunning || p.ContainerID == "" {
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		stats, err := m.h.deps.Runtime.Stats(sctx, p.ContainerID)
		cancel()
		if err != nil || stats == nil {
			continue
		}
		m.mu.Lock()
		r, ok := m.rings[p.Name]
		if !ok {
			r = newRing(metricWindow)
			m.rings[p.Name] = r
		}
		r.add(sample{
			T:           time.Now().UTC(),
			CPUPercent:  stats.CPUPercent,
			MemoryUsage: stats.MemoryUsage,
			MemoryLimit: stats.MemoryLimit,
		})
		m.mu.Unlock()
	}
}

func (m *MetricsCollector) history(name string) []sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rings[name]; ok {
		return r.snapshot()
	}
	return nil
}

// pluginMetric is the per-plugin view returned by the metrics API.
type pluginMetric struct {
	Name         string   `json:"name"`
	Title        string   `json:"title"`
	State        string   `json:"state"`
	Health       string   `json:"health"` // healthy | unhealthy | idle
	CPUPercent   float64  `json:"cpu"`
	MemoryUsage  uint64   `json:"mem"`
	MemoryLimit  uint64   `json:"memLimit"`
	UptimeSecond int64    `json:"uptimeSeconds"`
	Restarts     int      `json:"restarts"`
	Reports      int      `json:"reports"`
	History      []sample `json:"history"`
}

// collect builds the current per-plugin metric views for the API/page.
func (m *MetricsCollector) collect() []pluginMetric {
	plugins, err := m.h.deps.Store.List()
	if err != nil {
		return nil
	}

	restarts := map[string]int{}
	if rc, ok := m.h.restarter.(RestartCounter); ok && rc != nil {
		restarts = rc.RestartCounts()
	}

	reportCounts := map[string]int{}
	if m.h.reports != nil {
		for _, rec := range m.h.reports.RecentReports() {
			reportCounts[rec.Report.Plugin]++
		}
	}

	now := time.Now()
	out := make([]pluginMetric, 0, len(plugins))
	for _, p := range plugins {
		pm := pluginMetric{
			Name:     p.Name,
			Title:    pluginTitle(p),
			State:    string(p.State),
			Health:   healthFor(p),
			Restarts: restarts[p.Name],
			Reports:  reportCounts[p.Name],
			History:  m.history(p.Name),
		}
		if p.State == plugin.StateRunning && p.LastStarted != nil {
			pm.UptimeSecond = int64(now.Sub(*p.LastStarted).Seconds())
		}
		if s, ok := lastSample(pm.History); ok {
			pm.CPUPercent = s.CPUPercent
			pm.MemoryUsage = s.MemoryUsage
			pm.MemoryLimit = s.MemoryLimit
		}
		out = append(out, pm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func lastSample(h []sample) (sample, bool) {
	if len(h) == 0 {
		return sample{}, false
	}
	return h[len(h)-1], true
}

// healthFor maps a plugin's lifecycle state to a coarse health signal for the
// dashboard dot. We key off State (maintained by the schedulers) rather than
// re-probing, so the metrics page never adds load to the plugins themselves.
func healthFor(p *plugin.Plugin) string {
	switch p.State {
	case plugin.StateRunning:
		return "healthy"
	case plugin.StateErrored:
		return "unhealthy"
	default:
		return "idle"
	}
}

func pluginTitle(p *plugin.Plugin) string {
	if p.Metadata != nil && p.Metadata.Info != nil && p.Metadata.Info.Title != "" {
		return p.Metadata.Info.Title
	}
	return p.Name
}

// handleMetricsPage renders the metrics dashboard shell; the numbers and
// sparklines are filled client-side from /api/metrics.
func (h *Handler) handleMetricsPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, "layout.html", "metrics.html", map[string]any{})
}

// handleAPIMetrics returns the current per-plugin metrics as JSON.
func (h *Handler) handleAPIMetrics(w http.ResponseWriter, r *http.Request) {
	if h.metrics == nil {
		h.json(w, http.StatusOK, []pluginMetric{})
		return
	}
	h.json(w, http.StatusOK, h.metrics.collect())
}
