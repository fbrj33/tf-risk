package main

import "testing"

func TestAnalyzePlanDetectsDeletion(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_instance.demo",
				Type:    "aws_instance",
				Change: Change{
					Actions: []string{"delete"},
				},
			},
		},
	}

	findings := AnalyzePlan(plan)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].RuleID != "TF002" {
		t.Errorf("expected rule TF002, got %s", findings[0].RuleID)
	}
}

func TestAnalyzePlanSafeCreation(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "terraform_data.demo",
				Type:    "terraform_data",
				Change: Change{
					Actions: []string{"create"},
				},
			},
		},
	}

	findings := AnalyzePlan(plan)

	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}
