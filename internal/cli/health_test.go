package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/illumio/plugger/internal/container"
	"github.com/illumio/plugger/internal/plugin"
)

func fakeInspect(ports map[string]map[int]int) func(context.Context, string) (*container.ContainerInfo, error) {
	return func(_ context.Context, id string) (*container.ContainerInfo, error) {
		p, ok := ports[id]
		if !ok {
			return nil, errors.New("no such container")
		}
		return &container.ContainerInfo{ID: id, Ports: p}, nil
	}
}

func TestHealthURLUsesPublishedHostPort(t *testing.T) {
	inspect := fakeInspect(map[string]map[int]int{"c1": {2055: 2055, 8080: 64717}})
	current := func() *plugin.Plugin { return &plugin.Plugin{ContainerID: "c1"} }

	url, err := healthURLFunc(inspect, current, 8080, "/api/health")(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if url != "http://127.0.0.1:64717/api/health" {
		t.Fatalf("got %q", url)
	}
}

func TestHealthURLFollowsRecreatedContainer(t *testing.T) {
	inspect := fakeInspect(map[string]map[int]int{
		"old": {8080: 50001},
		"new": {8080: 50002},
	})
	p := &plugin.Plugin{ContainerID: "old"}
	resolve := healthURLFunc(inspect, func() *plugin.Plugin { return p }, 8080, "/healthz")

	first, _ := resolve(context.Background())
	p = &plugin.Plugin{ContainerID: "new"} // scheduler swapped in a fresh plugin after a restart
	second, err := resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != "http://127.0.0.1:50001/healthz" || second != "http://127.0.0.1:50002/healthz" {
		t.Fatalf("got %q then %q", first, second)
	}
}

func TestHealthURLErrors(t *testing.T) {
	inspect := fakeInspect(map[string]map[int]int{"c1": {2055: 2055}})
	tests := []struct {
		name    string
		plugin  *plugin.Plugin
		wantErr string
	}{
		{"no container yet", &plugin.Plugin{}, "no running container"},
		{"inspect fails", &plugin.Plugin{ContainerID: "gone"}, "no such container"},
		{"port not published", &plugin.Plugin{ContainerID: "c1"}, "container port 8080 is not published"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := healthURLFunc(inspect, func() *plugin.Plugin { return tt.plugin }, 8080, "/healthz")(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
