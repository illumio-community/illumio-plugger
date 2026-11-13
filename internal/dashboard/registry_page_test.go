package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The registry page renders through the layout and carries one toggle pill per
// filter value, grouped so the page can AND them (e.g. read-write + installed).
func TestHandleRegistryPage_CombinableFilters(t *testing.T) {
	h := newTestHandler(t, stubRuntime{})

	rec := httptest.NewRecorder()
	h.handleRegistryPage(rec, httptest.NewRequest(http.MethodGet, "/registry", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`data-group="mode" data-value="daemon"`,
		`data-group="mode" data-value="cron"`,
		`data-group="ui" data-value="yes"`,
		`data-group="installed" data-value="yes"`,
		`data-group="installed" data-value="no"`,
		`data-group="access" data-value="readonly"`,
		`data-group="access" data-value="readwrite"`,
		`function accessBadge`,
		`function maturityBadge`,
		`filters.access`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("registry page missing %q", want)
		}
	}
	if strings.Contains(body, "currentFilter") {
		t.Error("single-value filter state still present; filters must combine")
	}
}
