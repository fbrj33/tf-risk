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

// LoadConfig reads and validates a YAML security policy.
func LoadConfig(path string) (PolicyConfig, error) {
	config := PolicyConfig{
		DisabledRules:     []string{},
		SeverityOverrides: map[string]string{},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("reading config %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("parsing config %q: %w", path, err)
	}

	if config.SeverityOverrides == nil {
		config.SeverityOverrides = map[string]string{}
	}

	// Validate and normalize severity overrides.
	for ruleID, severity := range config.SeverityOverrides {
		ruleID = strings.ToUpper(strings.TrimSpace(ruleID))
		normalizedSeverity := strings.ToUpper(strings.TrimSpace(severity))

		if ruleID == "" {
			return config, fmt.Errorf("severity override has an empty rule ID")
		}

		switch normalizedSeverity {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
			config.SeverityOverrides[ruleID] = normalizedSeverity
		default:
			return config, fmt.Errorf(
				"invalid severity %q for rule %s",
				severity,
				ruleID,
			)
		}
	}

	// Normalize disabled rule IDs.
	for i, ruleID := range config.DisabledRules {
		config.DisabledRules[i] = strings.ToUpper(strings.TrimSpace(ruleID))

		if config.DisabledRules[i] == "" {
			return config, fmt.Errorf("disabled_rules contains an empty rule ID")
		}
	}

	return config, nil
}

// ApplyPolicy filters disabled rules and applies severity overrides.
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
