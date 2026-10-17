package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type PolicyConfig struct {
	DisabledRules     []string          `yaml:"disabled_rules"`
	SeverityOverrides map[string]string `yaml:"severity_overrides"`
}

var supportedRules = map[string]string{
	"TF001": "Critical database deletion or replacement",
	"TF002": "High-risk resource deletion or replacement",
	"TF003": "SSH exposed to the public internet",
	"TF004": "RDP exposed to the public internet",
	"TF005": "Potentially public S3 bucket configuration",
	"TF006": "Overly permissive IAM policy",
	"TF007": "Unencrypted EBS volume",
	"TF008": "Unencrypted RDS storage",
	"TF009": "Publicly accessible RDS database",
	"TF010": "Missing or invalid S3 encryption configuration",
	"TF011": "Sensitive ingress ports exposed publicly",
	"TF012": "Overly permissive security group ingress",
}

func LoadConfig(path string) (PolicyConfig, error) {
	config := PolicyConfig{
		DisabledRules:     []string{},
		SeverityOverrides: map[string]string{},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("reading config %s: %w", path, err)
	}

	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)

	if err := decoder.Decode(&config); err != nil {
		return config, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if err := validateConfig(&config); err != nil {
		return config, fmt.Errorf("invalid config %s: %w", path, err)
	}

	return config, nil
}

func validateConfig(config *PolicyConfig) error {
	normalizedOverrides := make(map[string]string)

	for ruleID, severity := range config.SeverityOverrides {
		ruleID = strings.ToUpper(strings.TrimSpace(ruleID))
		severity = strings.ToUpper(strings.TrimSpace(severity))

		if _, exists := supportedRules[ruleID]; !exists {
			return fmt.Errorf("unknown rule ID %q in severity_overrides", ruleID)
		}

		switch severity {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
			normalizedOverrides[ruleID] = severity
		default:
			return fmt.Errorf("invalid severity %q for rule %s", severity, ruleID)
		}
	}

	config.SeverityOverrides = normalizedOverrides

	seen := make(map[string]bool)

	for i, ruleID := range config.DisabledRules {
		ruleID = strings.ToUpper(strings.TrimSpace(ruleID))

		if _, exists := supportedRules[ruleID]; !exists {
			return fmt.Errorf("unknown rule ID %q in disabled_rules", ruleID)
		}

		if seen[ruleID] {
			return fmt.Errorf("duplicate rule ID %q in disabled_rules", ruleID)
		}

		seen[ruleID] = true
		config.DisabledRules[i] = ruleID
	}

	return nil
}

func ApplyPolicy(findings []Finding, config PolicyConfig) []Finding {
	disabled := make(map[string]bool, len(config.DisabledRules))

	for _, ruleID := range config.DisabledRules {
		disabled[strings.ToUpper(strings.TrimSpace(ruleID))] = true
	}

	filtered := make([]Finding, 0, len(findings))

	for _, finding := range findings {
		ruleID := strings.ToUpper(strings.TrimSpace(finding.RuleID))

		if disabled[ruleID] {
			continue
		}

		if severity, ok := config.SeverityOverrides[ruleID]; ok {
			finding.Severity = severity
		}

		filtered = append(filtered, finding)
	}

	return filtered
}