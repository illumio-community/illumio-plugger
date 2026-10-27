package lifecycle

import (
	"testing"

	"github.com/illumio/plugger/internal/config"
)

func TestResolvePortMapping(t *testing.T) {
	tests := []struct {
		name          string
		ps            config.PortSpec
		env           []string
		wantContainer int
		wantHost      int
	}{
		{
			name:          "portEnv unset in env falls back to Port default",
			ps:            config.PortSpec{Port: 2055, PortEnv: "NETFLOW_PORT"},
			env:           []string{"PCE_HOST=x"},
			wantContainer: 2055,
			wantHost:      2055, // host == container
		},
		{
			name:          "portEnv override tracks on both container and host",
			ps:            config.PortSpec{Port: 2055, PortEnv: "NETFLOW_PORT"},
			env:           []string{"NETFLOW_PORT=9995"},
			wantContainer: 9995,
			wantHost:      9995,
		},
		{
			name:          "portEnv default then user override (last wins)",
			ps:            config.PortSpec{Port: 2055, PortEnv: "NETFLOW_PORT"},
			env:           []string{"NETFLOW_PORT=2055", "NETFLOW_PORT=6000"},
			wantContainer: 6000,
			wantHost:      6000,
		},
		{
			name:          "invalid env value falls back to Port",
			ps:            config.PortSpec{Port: 2055, PortEnv: "NETFLOW_PORT"},
			env:           []string{"NETFLOW_PORT=not-a-number"},
			wantContainer: 2055,
			wantHost:      2055,
		},
		{
			name:          "empty env value falls back to Port",
			ps:            config.PortSpec{Port: 2055, PortEnv: "NETFLOW_PORT"},
			env:           []string{"NETFLOW_PORT="},
			wantContainer: 2055,
			wantHost:      2055,
		},
		{
			name:          "no portEnv, fixed hostPort pins host only",
			ps:            config.PortSpec{Port: 2055, HostPort: 3055},
			env:           nil,
			wantContainer: 2055,
			wantHost:      3055,
		},
		{
			name:          "no portEnv, no hostPort auto-assigns (host 0)",
			ps:            config.PortSpec{Port: 8080},
			env:           nil,
			wantContainer: 8080,
			wantHost:      0,
		},
		{
			name:          "portEnv takes precedence over hostPort",
			ps:            config.PortSpec{Port: 2055, HostPort: 3055, PortEnv: "NETFLOW_PORT"},
			env:           []string{"NETFLOW_PORT=9995"},
			wantContainer: 9995,
			wantHost:      9995,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotC, gotH := resolvePortMapping(tt.ps, tt.env)
			if gotC != tt.wantContainer || gotH != tt.wantHost {
				t.Errorf("resolvePortMapping = (container %d, host %d), want (container %d, host %d)",
					gotC, gotH, tt.wantContainer, tt.wantHost)
			}
		})
	}
}
