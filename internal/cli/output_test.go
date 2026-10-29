package cli

import (
	"testing"

	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/reports"
)

// withTempApp points the global app at a throwaway data dir for the duration
// of a test, restoring whatever was there before.
func withTempApp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := app
	app = &App{Config: &config.Config{Plugger: config.PluggerConfig{DataDir: dir}}}
	t.Cleanup(func() { app = prev })
	return dir
}

func runOutputAdd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newOutputAddCmd()
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}

func TestOutputAdd_Splunk(t *testing.T) {
	dir := withTempApp(t)

	err := runOutputAdd(t, "siem",
		"--type", "splunk",
		"--hec-url", "https://splunk.corp.com:8088",
		"--hec-token-env", "SPLUNK_HEC_TOKEN",
		"--index", "illumio",
		"--sourcetype", "plugger:report",
		"--tls-skip-verify",
		"--plugins", "pce-expiry-watch",
		"--severity", "warning,critical",
	)
	if err != nil {
		t.Fatalf("output add splunk: %v", err)
	}

	stored, err := reports.NewOutputStore(dir).List()
	if err != nil {
		t.Fatalf("list store: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored output, got %d", len(stored))
	}
	o := stored[0]
	if o.Name != "siem" || o.Type != "splunk" {
		t.Errorf("name/type = %q/%q", o.Name, o.Type)
	}
	if o.HECURL != "https://splunk.corp.com:8088" {
		t.Errorf("hecUrl = %q", o.HECURL)
	}
	if o.HECTokenEnv != "SPLUNK_HEC_TOKEN" {
		t.Errorf("hecTokenEnv = %q", o.HECTokenEnv)
	}
	if o.Index != "illumio" || o.SourceType != "plugger:report" || !o.TLSSkipVerify {
		t.Errorf("index/sourcetype/tlsSkipVerify = %q/%q/%v", o.Index, o.SourceType, o.TLSSkipVerify)
	}
	if len(o.Filter.Plugins) != 1 || o.Filter.Plugins[0] != "pce-expiry-watch" {
		t.Errorf("plugins filter = %v", o.Filter.Plugins)
	}
	if len(o.Filter.Severity) != 2 {
		t.Errorf("severity filter = %v", o.Filter.Severity)
	}
	// The built config must satisfy the splunk output constructor.
	t.Setenv("SPLUNK_HEC_TOKEN", "tok")
	if _, err := reports.NewSplunkOutput(o); err != nil {
		t.Errorf("stored config rejected by NewSplunkOutput: %v", err)
	}
}

func TestOutputAdd_SplunkRequiresURLAndToken(t *testing.T) {
	withTempApp(t)
	if err := runOutputAdd(t, "s", "--type", "splunk", "--hec-token-env", "T"); err == nil {
		t.Error("expected error when --hec-url missing")
	}
	withTempApp(t)
	if err := runOutputAdd(t, "s", "--type", "splunk", "--hec-url", "https://h:8088"); err == nil {
		t.Error("expected error when --hec-token-env missing")
	}
}
