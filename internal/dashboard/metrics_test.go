package dashboard

import (
	"testing"
	"time"

	"github.com/illumio/plugger/internal/plugin"
)

// The ring keeps only the most recent `cap` samples, evicting oldest first,
// and reports them oldest-first so a sparkline reads left-to-right in time.
func TestRing_EvictsOldestBeyondCap(t *testing.T) {
	r := newRing(3)
	for i := 0; i < 5; i++ {
		r.add(sample{CPUPercent: float64(i)})
	}
	snap := r.snapshot()
	if len(snap) != 3 {
		t.Fatalf("len = %d, want 3 (capacity)", len(snap))
	}
	// Oldest two (0,1) evicted; remaining are 2,3,4 in order.
	for i, want := range []float64{2, 3, 4} {
		if snap[i].CPUPercent != want {
			t.Errorf("snap[%d].CPU = %v, want %v", i, snap[i].CPUPercent, want)
		}
	}
	last, ok := r.last()
	if !ok || last.CPUPercent != 4 {
		t.Errorf("last = %v (ok=%v), want 4", last.CPUPercent, ok)
	}
}

func TestRing_EmptyLast(t *testing.T) {
	if _, ok := newRing(3).last(); ok {
		t.Error("empty ring reported a last sample")
	}
}

// snapshot must return a copy — mutating it must not corrupt the ring.
func TestRing_SnapshotIsCopy(t *testing.T) {
	r := newRing(3)
	r.add(sample{CPUPercent: 1})
	snap := r.snapshot()
	snap[0].CPUPercent = 999
	again, _ := r.last()
	if again.CPUPercent != 1 {
		t.Errorf("ring mutated through snapshot: got %v, want 1", again.CPUPercent)
	}
}

func TestHealthFor(t *testing.T) {
	cases := map[plugin.State]string{
		plugin.StateRunning:   "healthy",
		plugin.StateErrored:   "unhealthy",
		plugin.StateStopped:   "idle",
		plugin.StateStarting:  "idle",
		plugin.StateInstalled: "idle",
	}
	for state, want := range cases {
		if got := healthFor(&plugin.Plugin{State: state}); got != want {
			t.Errorf("healthFor(%q) = %q, want %q", state, got, want)
		}
	}
}

// parseTemplates must compile the whole embedded set, including the new
// metrics page. A syntax error in metrics.html would panic here (it panics at
// NewHandler in production), so this fails fast in CI instead.
func TestParseTemplates_IncludesMetrics(t *testing.T) {
	tmpl := parseTemplates()
	if tmpl.Lookup("metrics.html") == nil {
		t.Fatal("metrics.html not present in parsed template set")
	}
}

// lastSample returns the newest point, or false for an empty history.
func TestLastSample(t *testing.T) {
	if _, ok := lastSample(nil); ok {
		t.Error("lastSample(nil) reported a value")
	}
	s, ok := lastSample([]sample{{T: time.Unix(1, 0), CPUPercent: 10}, {T: time.Unix(2, 0), CPUPercent: 20}})
	if !ok || s.CPUPercent != 20 {
		t.Errorf("lastSample = %v (ok=%v), want newest 20", s.CPUPercent, ok)
	}
}
