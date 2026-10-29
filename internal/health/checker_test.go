package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const tick = 10 * time.Millisecond

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(tick)
	}
}

func statusServer(t *testing.T, code int, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestURLResolvedBeforeEveryCheck(t *testing.T) {
	// The first container dies; its replacement is published on a new host port.
	var oldHits, newHits atomic.Int32
	oldSrv := statusServer(t, http.StatusOK, &oldHits)
	newSrv := statusServer(t, http.StatusOK, &newHits)

	var calls atomic.Int32
	resolve := func(context.Context) (string, error) {
		if calls.Add(1) == 1 {
			return oldSrv.URL, nil
		}
		return newSrv.URL, nil
	}

	c := NewChecker("p", resolve, tick, time.Second, 3, nil)
	c.Start(context.Background())
	defer c.Stop()

	waitFor(t, func() bool { return newHits.Load() >= 2 })
	if oldHits.Load() != 1 {
		t.Fatalf("old URL hit %d times, want 1", oldHits.Load())
	}
}

func TestUnresolvableURLSkipsCheckWithoutRestart(t *testing.T) {
	var calls atomic.Int32
	resolve := func(context.Context) (string, error) {
		calls.Add(1)
		return "", errors.New("container port 8080 is not published on the host")
	}
	var failures atomic.Int32
	c := NewChecker("p", resolve, tick, time.Second, 2, func(string, error) { failures.Add(1) })
	c.Start(context.Background())

	waitFor(t, func() bool { return calls.Load() >= 6 })
	c.Stop()
	if failures.Load() != 0 {
		t.Fatalf("onFailure called %d times for an unresolvable URL, want 0", failures.Load())
	}
}

func TestUnhealthyTriggersFailureAfterRetries(t *testing.T) {
	var hits atomic.Int32
	srv := statusServer(t, http.StatusServiceUnavailable, &hits)
	resolve := func(context.Context) (string, error) { return srv.URL, nil }

	var failures atomic.Int32
	c := NewChecker("p", resolve, tick, time.Second, 3, func(string, error) { failures.Add(1) })
	c.Start(context.Background())
	defer c.Stop()

	waitFor(t, func() bool { return failures.Load() >= 1 })
	if hits.Load() < 3 {
		t.Fatalf("failure reported after %d checks, want at least 3", hits.Load())
	}
}

func TestHealthyNeverTriggersFailure(t *testing.T) {
	var hits atomic.Int32
	srv := statusServer(t, http.StatusOK, &hits)
	resolve := func(context.Context) (string, error) { return srv.URL, nil }

	var failures atomic.Int32
	c := NewChecker("p", resolve, tick, time.Second, 1, func(string, error) { failures.Add(1) })
	c.Start(context.Background())

	waitFor(t, func() bool { return hits.Load() >= 5 })
	c.Stop()
	if failures.Load() != 0 {
		t.Fatalf("onFailure called %d times for a healthy plugin", failures.Load())
	}
}
