package reports

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/illumio/plugger/internal/config"
)

func sampleReport() *Report {
	return &Report{
		ID:        "r1",
		Plugin:    "pce-expiry-watch",
		Title:     "1 PCE object expiring critically",
		Severity:  SeverityCritical,
		Body:      "## Critical\n- cert",
		Tags:      []string{"expiry", "pce"},
		Data:      map[string]any{"count": 1},
		CreatedAt: time.Now(),
	}
}

func TestSplunk_SendPostsStructuredEvent(t *testing.T) {
	var gotPath, gotAuth, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	out, err := NewSplunkOutput(config.OutputConfig{
		Name: "splunk", HECURL: srv.URL, HECToken: "tok-123", Index: "illumio",
	})
	if err != nil {
		t.Fatalf("NewSplunkOutput: %v", err)
	}
	if err := out.Send(context.Background(), sampleReport()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if gotPath != "/services/collector/event" {
		t.Errorf("path = %q, want /services/collector/event", gotPath)
	}
	if gotAuth != "Splunk tok-123" {
		t.Errorf("auth = %q, want 'Splunk tok-123'", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q", gotCT)
	}

	var env map[string]any
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if env["sourcetype"] != "plugger:report" {
		t.Errorf("sourcetype = %v, want plugger:report", env["sourcetype"])
	}
	if env["index"] != "illumio" {
		t.Errorf("index = %v, want illumio", env["index"])
	}
	if tm, ok := env["time"].(float64); !ok || tm <= 0 {
		t.Errorf("time = %v, want positive epoch", env["time"])
	}
	ev, ok := env["event"].(map[string]any)
	if !ok {
		t.Fatalf("event missing or wrong type: %v", env["event"])
	}
	if ev["severity"] != "critical" || ev["plugin"] != "pce-expiry-watch" {
		t.Errorf("event fields wrong: %v", ev)
	}
}

func TestSplunk_SendBatchNewlineDelimited(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	out, _ := NewSplunkOutput(config.OutputConfig{Name: "s", HECURL: srv.URL, HECToken: "t"})
	reports := []*Report{sampleReport(), sampleReport(), sampleReport()}
	if err := out.SendBatch(context.Background(), reports); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}

	// Each line must be an independent JSON event object (HEC format, not an array).
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(gotBody))
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var env map[string]any
		if err := json.Unmarshal(line, &env); err != nil {
			t.Fatalf("line %d not JSON: %v", n, err)
		}
		if _, ok := env["event"]; !ok {
			t.Fatalf("line %d missing event", n)
		}
		n++
	}
	if n != 3 {
		t.Errorf("got %d events, want 3", n)
	}
}

func TestSplunk_Non200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"text":"Invalid token","code":4}`))
	}))
	defer srv.Close()

	out, _ := NewSplunkOutput(config.OutputConfig{Name: "s", HECURL: srv.URL, HECToken: "t"})
	if err := out.Send(context.Background(), sampleReport()); err == nil {
		t.Fatal("expected error on HEC 403, got nil")
	}
}

func TestSplunk_TLSSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Default (verify on): the self-signed test cert must be rejected.
	strict, _ := NewSplunkOutput(config.OutputConfig{Name: "s", HECURL: srv.URL, HECToken: "t"})
	if err := strict.Send(context.Background(), sampleReport()); err == nil {
		t.Fatal("expected TLS verification failure against self-signed HEC, got nil")
	}

	// Opt-in skip: connects successfully.
	lax, _ := NewSplunkOutput(config.OutputConfig{Name: "s", HECURL: srv.URL, HECToken: "t", TLSSkipVerify: true})
	if err := lax.Send(context.Background(), sampleReport()); err != nil {
		t.Fatalf("tlsSkipVerify should allow self-signed HEC: %v", err)
	}
}

func TestSplunk_TokenFromEnvAndExpansion(t *testing.T) {
	t.Setenv("SPLUNK_HEC_TOKEN", "env-tok")
	// hecTokenEnv takes precedence
	if got := resolveSplunkToken(config.OutputConfig{HECTokenEnv: "SPLUNK_HEC_TOKEN", HECToken: "ignored"}); got != "env-tok" {
		t.Errorf("hecTokenEnv = %q, want env-tok", got)
	}
	// ${ENV} expansion in hecToken
	if got := resolveSplunkToken(config.OutputConfig{HECToken: "${SPLUNK_HEC_TOKEN}"}); got != "env-tok" {
		t.Errorf("expanded hecToken = %q, want env-tok", got)
	}
	// literal token
	if got := resolveSplunkToken(config.OutputConfig{HECToken: "literal"}); got != "literal" {
		t.Errorf("literal hecToken = %q, want literal", got)
	}
}

func TestSplunk_EventURLNormalization(t *testing.T) {
	cases := map[string]string{
		"https://h:8088":                          "https://h:8088/services/collector/event",
		"https://h:8088/":                         "https://h:8088/services/collector/event",
		"https://h:8088/services/collector/event": "https://h:8088/services/collector/event",
		"https://h:8088/services/collector/raw":   "https://h:8088/services/collector/raw",
	}
	for in, want := range cases {
		if got := splunkEventURL(in); got != want {
			t.Errorf("splunkEventURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplunk_RequiresURLAndToken(t *testing.T) {
	if _, err := NewSplunkOutput(config.OutputConfig{Name: "s", HECToken: "t"}); err == nil {
		t.Error("expected error when hecUrl missing")
	}
	if _, err := NewSplunkOutput(config.OutputConfig{Name: "s", HECURL: "https://h:8088"}); err == nil {
		t.Error("expected error when token missing")
	}
}
