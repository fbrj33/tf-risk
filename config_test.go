package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyPolicy(t *testing.T) {
	findings := []Finding{
		{RuleID: "TF003", Severity: "HIGH", Message: "Public SSH"},
		{RuleID: "TF005", Severity: "HIGH", Message: "Public bucket"},
		{RuleID: "TF006", Severity: "HIGH", Message: "Broad IAM policy"},
	}

	config := PolicyConfig{
		DisabledRules: []string{"TF003"},
		SeverityOverrides: map[string]string{
			"TF005": "MEDIUM",
		},
	}

	got := ApplyPolicy(findings, config)

	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}

	if got[0].RuleID != "TF005" || got[0].Severity != "MEDIUM" {
		t.Errorf("TF005 policy not applied: %+v", got[0])
	}

	if got[1].RuleID != "TF006" || got[1].Severity != "HIGH" {
		t.Errorf("TF006 should remain unchanged: %+v", got[1])
	}
}

func TestLoadConfigInvalidSeverity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.yaml")

	content := []byte(`
disabled_rules: []
severity_overrides:
  TF003: EXTREME
`)

	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected invalid severity to return an error")
	}
}

func TestLoadConfigValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "valid.yaml")

	content := []byte(`
disabled_rules:
  - TF003
severity_overrides:
  TF005: medium
`)

	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	config, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}

	if len(config.DisabledRules) != 1 || config.DisabledRules[0] != "TF003" {
		t.Errorf("unexpected disabled rules: %v", config.DisabledRules)
	}

	if config.SeverityOverrides["TF005"] != "MEDIUM" {
		t.Errorf("expected normalized MEDIUM severity, got %q",
			config.SeverityOverrides["TF005"])
	}
}
func TestLoadConfigRejectsUnknownRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.yaml")

	content := []byte(`
disabled_rules:
  - TF999
severity_overrides: {}
`)

	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected unknown rule ID to return an error")
	}
}

func TestLoadConfigRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.yaml")

	content := []byte(`
disabled_rules: []
severity_overrides: {}
unknown_option: true
`)

	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected unknown YAML field to return an error")
	}
}