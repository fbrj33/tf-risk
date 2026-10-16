package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGetRiskLevel(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{score: 0, want: "LOW"},
		{score: 4, want: "LOW"},
		{score: 5, want: "MEDIUM"},
		{score: 9, want: "MEDIUM"},
		{score: 10, want: "HIGH"},
		{score: 19, want: "HIGH"},
		{score: 20, want: "CRITICAL"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := getRiskLevel(tt.score)
			if got != tt.want {
				t.Errorf("getRiskLevel(%d) = %s, want %s",
					tt.score, got, tt.want)
			}
		})
	}
}

func TestCalculateRiskScore(t *testing.T) {
	findings := []Finding{
		{Severity: "CRITICAL"},
		{Severity: "HIGH"},
		{Severity: "MEDIUM"},
		{Severity: "LOW"},
	}

	got := CalculateRiskScore(findings)
	want := 22 // 10 + 7 + 4 + 1

	if got != want {
		t.Errorf("CalculateRiskScore() = %d, want %d", got, want)
	}
}

func TestCalculateRiskScoreEmpty(t *testing.T) {
	got := CalculateRiskScore([]Finding{})

	if got != 0 {
		t.Errorf("CalculateRiskScore() = %d, want 0", got)
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		input string
		want  int
		valid bool
	}{
		{"low", 1, true},
		{"MEDIUM", 2, true},
		{"High", 3, true},
		{"critical", 4, true},
		{"invalid", 0, false},
		{"", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, valid := severityRank(tt.input)

			if got != tt.want || valid != tt.valid {
				t.Errorf(
					"severityRank(%q) = (%d, %t), want (%d, %t)",
					tt.input, got, valid, tt.want, tt.valid,
				)
			}
		})
	}
}

func TestBuildSARIF(t *testing.T) {
	findings := []Finding{
		{
			RuleID:      "TF003",
			Severity:    "HIGH",
			Resource:    "aws_security_group_rule.unsafe_ssh",
			Message:     "SSH is exposed to the public internet.",
			Remediation: "Restrict SSH to trusted IP addresses.",
		},
		{
			RuleID:      "TF005",
			Severity:    "HIGH",
			Resource:    "aws_s3_bucket.public",
			Message:     "S3 bucket allows public access.",
			Remediation: "Disable public access.",
		},
	}

	planPath := "examples/basic/unsafe-plan.json"
	report := buildSARIF(findings, planPath)

	if report.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", report.Version)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 SARIF run, got %d", len(report.Runs))
	}

	run := report.Runs[0]

	if run.Tool.Driver.Name != "tf-risk" {
		t.Errorf("tool name = %q, want tf-risk", run.Tool.Driver.Name)
	}

	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}

	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}

	for _, result := range run.Results {
		if result.Level != "error" {
			t.Errorf("result %s level = %q, want error",
				result.RuleID, result.Level)
		}

		if len(result.Locations) == 0 {
			t.Errorf("result %s has no locations", result.RuleID)
			continue
		}

		gotPath := result.Locations[0].
			PhysicalLocation.ArtifactLocation.URI

		if gotPath != planPath {
			t.Errorf("location = %q, want %q", gotPath, planPath)
		}

		if strings.TrimSpace(result.Message.Text) == "" {
			t.Errorf("result %s has an empty message", result.RuleID)
		}
	}
}

func TestBuildSARIFSeverityMapping(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			report := buildSARIF([]Finding{
				{
					RuleID:   "TEST001",
					Severity: tt.severity,
					Resource: "test.resource",
					Message:  "Test finding",
				},
			}, "test-plan.json")

			got := report.Runs[0].Results[0].Level

			if got != tt.want {
				t.Errorf("SARIF level = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildSARIFWithNoFindings(t *testing.T) {
	report := buildSARIF([]Finding{}, "safe-plan.json")

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	if report.Runs[0].Results == nil {
		t.Fatal("SARIF results should be an empty array, not null")
	}

	if len(report.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d",
			len(report.Runs[0].Results))
	}
}

func TestSARIFCanBeSerializedToJSON(t *testing.T) {
	report := buildSARIF([]Finding{
		{
			RuleID:   "TF003",
			Severity: "HIGH",
			Resource: "aws_security_group.example",
			Message:  "SSH is exposed.",
		},
	}, "plan.json")

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to serialize SARIF: %v", err)
	}

	var decoded map[string]interface{}

	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("generated SARIF is not valid JSON: %v", err)
	}

	if decoded["version"] != "2.1.0" {
		t.Errorf("serialized SARIF has unexpected version: %v",
			decoded["version"])
	}
}
