package health

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheck_ResolvesURLPerProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	calls := 0
	c := NewChecker("p", func() (string, error) {
		calls++
		return srv.URL + "/healthz", nil
	}, 0, 0, 0, nil)

	for i := 0; i < 3; i++ {
		if err := c.check(context.Background()); err != nil {
			t.Fatalf("probe %d: unexpected error: %v", i, err)
		}
	}
	if calls != 3 {
		t.Fatalf("expected URL resolved once per probe (3), got %d", calls)
	}
}

func TestCheck_ResolverErrorIsFailure(t *testing.T) {
	c := NewChecker("p", func() (string, error) {
		return "", fmt.Errorf("no host mapping for container port 8080")
	}, 0, 0, 0, nil)

	if err := c.check(context.Background()); err == nil {
		t.Fatal("expected a resolver error to count as a failed probe, got nil")
	}
}

func TestCheck_Non2xxIsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewChecker("p", func() (string, error) { return srv.URL, nil }, 0, 0, 0, nil)
	if err := c.check(context.Background()); err == nil {
		t.Fatal("expected HTTP 500 to be unhealthy, got nil")
	}
}
