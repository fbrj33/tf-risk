package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "tf-risk.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfigValidPolicy(t *testing.T) {
	path := writeTestConfig(t, `
disabled_rules:
  - tf003
severity_overrides:
  tf002: critical
`)

	config, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if len(config.DisabledRules) != 1 || config.DisabledRules[0] != "TF003" {
		t.Errorf("unexpected disabled rules: %#v", config.DisabledRules)
	}

	if config.SeverityOverrides["TF002"] != "CRITICAL" {
		t.Errorf("expected TF002 severity CRITICAL, got %q",
			config.SeverityOverrides["TF002"])
	}
}

func TestLoadConfigRejectsUnknownRule(t *testing.T) {
	path := writeTestConfig(t, `
disabled_rules:
  - TF999
`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected an error for unknown rule ID")
	}
}

func TestLoadConfigRejectsInvalidSeverity(t *testing.T) {
	path := writeTestConfig(t, `
severity_overrides:
  TF003: URGENT
`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected an error for invalid severity")
	}
}

func TestLoadConfigRejectsDuplicateDisabledRules(t *testing.T) {
	path := writeTestConfig(t, `
disabled_rules:
  - TF003
  - tf003
`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected an error for duplicate disabled rules")
	}
}

func TestLoadConfigRejectsUnknownYAMLField(t *testing.T) {
	path := writeTestConfig(t, `
unknown_option: true
`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected an error for unknown YAML field")
	}
}

func TestApplyPolicyDisablesRule(t *testing.T) {
	findings := []Finding{
		{RuleID: "TF003", Severity: "HIGH"},
		{RuleID: "TF004", Severity: "HIGH"},
	}

	config := PolicyConfig{
		DisabledRules: []string{"TF003"},
	}

	got := ApplyPolicy(findings, config)

	if len(got) != 1 {
		t.Fatalf("expected 1 finding after disabling TF003, got %d", len(got))
	}
	if got[0].RuleID != "TF004" {
		t.Errorf("expected TF004 to remain, got %s", got[0].RuleID)
	}
}

func TestApplyPolicyOverridesSeverity(t *testing.T) {
	findings := []Finding{
		{RuleID: "TF003", Severity: "HIGH"},
	}

	config := PolicyConfig{
		SeverityOverrides: map[string]string{
			"TF003": "CRITICAL",
		},
	}

	got := ApplyPolicy(findings, config)

	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", got[0].Severity)
	}

	// Applying policy should not mutate the original finding.
	if findings[0].Severity != "HIGH" {
		t.Errorf("original finding was unexpectedly modified")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected an error for missing config file")
	}
}

func TestLoadConfigErrorMentionsPath(t *testing.T) {
	path := writeTestConfig(t, `
severity_overrides:
  TF003: URGENT
`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("expected error to mention config path %q; got %v", path, err)
	}
}
