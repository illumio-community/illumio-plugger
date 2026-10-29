package reports

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/illumio/plugger/internal/config"
)

// SplunkOutput sends reports to a Splunk HTTP Event Collector (HEC).
//
// Each report is delivered to the HEC /services/collector/event endpoint as a
// structured event, so Splunk indexes the report fields (plugin, severity,
// title, data) directly — no sourcetype field-extraction required.
type SplunkOutput struct {
	name       string
	url        string
	token      string
	index      string
	sourcetype string
	source     string
	client     *http.Client
}

func NewSplunkOutput(cfg config.OutputConfig) (*SplunkOutput, error) {
	if cfg.HECURL == "" {
		return nil, fmt.Errorf("splunk output %q: hecUrl required", cfg.Name)
	}
	token := resolveSplunkToken(cfg)
	if token == "" {
		return nil, fmt.Errorf("splunk output %q: HEC token required (set hecTokenEnv or hecToken)", cfg.Name)
	}

	sourcetype := cfg.SourceType
	if sourcetype == "" {
		sourcetype = "plugger:report"
	}
	source := cfg.Source
	if source == "" {
		source = "plugger"
	}

	client := &http.Client{Timeout: 15 * time.Second}
	if cfg.TLSSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in for self-signed lab HEC
		}
	}

	return &SplunkOutput{
		name:       cfg.Name,
		url:        splunkEventURL(cfg.HECURL),
		token:      token,
		index:      cfg.Index,
		sourcetype: sourcetype,
		source:     source,
		client:     client,
	}, nil
}

// resolveSplunkToken prefers the env-var-name form (hecTokenEnv), falling back
// to hecToken with ${ENV} expansion so the secret stays out of the config file.
func resolveSplunkToken(cfg config.OutputConfig) string {
	if cfg.HECTokenEnv != "" {
		if v := os.Getenv(cfg.HECTokenEnv); v != "" {
			return v
		}
	}
	return strings.TrimSpace(os.Expand(cfg.HECToken, os.Getenv))
}

// splunkEventURL normalizes a HEC base URL to the /event collector endpoint.
// A URL that already points at a /services/collector path is used verbatim.
func splunkEventURL(raw string) string {
	u := strings.TrimRight(raw, "/")
	if strings.Contains(u, "/services/collector") {
		return u
	}
	return u + "/services/collector/event"
}

func (s *SplunkOutput) Name() string { return s.name }
func (s *SplunkOutput) Type() string { return "splunk" }

// event builds a single HEC event envelope for a report.
func (s *SplunkOutput) event(r *Report) map[string]any {
	when := r.CreatedAt
	if when.IsZero() {
		when = time.Now()
	}

	ev := map[string]any{
		"plugin":   r.Plugin,
		"title":    r.Title,
		"severity": r.Severity,
	}
	if r.ID != "" {
		ev["id"] = r.ID
	}
	if r.Body != "" {
		ev["body"] = r.Body
	}
	if len(r.Tags) > 0 {
		ev["tags"] = r.Tags
	}
	if len(r.Data) > 0 {
		ev["data"] = r.Data
	}

	payload := map[string]any{
		"time":       float64(when.UnixNano()) / 1e9,
		"sourcetype": s.sourcetype,
		"source":     s.source,
		"event":      ev,
	}
	if s.index != "" {
		payload["index"] = s.index
	}
	return payload
}

func (s *SplunkOutput) Send(ctx context.Context, report *Report) error {
	body, err := json.Marshal(s.event(report))
	if err != nil {
		return err
	}
	return s.post(ctx, body)
}

func (s *SplunkOutput) SendBatch(ctx context.Context, reports []*Report) error {
	if len(reports) == 0 {
		return nil
	}
	// HEC accepts multiple events as concatenated JSON objects (newline-delimited),
	// not a JSON array — json.Encoder writes exactly that.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range reports {
		if err := enc.Encode(s.event(r)); err != nil {
			return err
		}
	}
	return s.post(ctx, buf.Bytes())
}

func (s *SplunkOutput) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("splunk %s: %w", s.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("splunk %s: HEC returned %d: %s", s.name, resp.StatusCode,
			strings.TrimSpace(string(snippet)))
	}
	return nil
}
