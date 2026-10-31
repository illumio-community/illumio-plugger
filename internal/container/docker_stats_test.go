package container

import "testing"

func TestCPUPercent(t *testing.T) {
	tests := []struct {
		name       string
		cpuDelta   float64
		sysDelta   float64
		onlineCPUs uint32
		want       float64
	}{
		// Half of all system cycles on this container, across 4 CPUs -> 200%.
		{"half of four cpus", 50, 100, 4, 200},
		// Full utilization of a single core.
		{"one full core", 100, 100, 1, 100},
		// A quarter of one core.
		{"quarter core", 25, 100, 1, 25},
		// First sample has no previous frame -> no system delta -> 0.
		{"no system delta", 100, 0, 4, 0},
		// Container used nothing in the interval.
		{"no cpu delta", 0, 100, 4, 0},
		// Daemon didn't report CPU count and we couldn't infer one.
		{"zero cpus", 50, 100, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cpuPercent(tt.cpuDelta, tt.sysDelta, tt.onlineCPUs)
			if got != tt.want {
				t.Errorf("cpuPercent(%v, %v, %d) = %v, want %v",
					tt.cpuDelta, tt.sysDelta, tt.onlineCPUs, got, tt.want)
			}
		})
	}
}
