package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	planPath := flag.String(
		"plan",
		"examples/basic/plan.json",
		"Path to Terraform plan JSON",
	)

	failOn := flag.String(
		"fail-on",
		"",
		"Fail when findings reach this severity: low, medium, high, critical",
	)

	outputFormat := flag.String(
		"format",
		"text",
		"Output format: text or json, or sarif",
	)

	flag.Parse()

	// Validate options before processing the plan.
	format := strings.ToLower(*outputFormat)
	if format != "text" && format != "json" && format != "sarif" {
		fmt.Fprintln(os.Stderr, "Invalid --format value. Use text, json, or sarif.")
		os.Exit(2)
	}

	var threshold int
	if *failOn != "" {
		var ok bool
		threshold, ok = severityRank(*failOn)
		if !ok {
			fmt.Fprintln(
				os.Stderr,
				"Invalid --fail-on value. Use low, medium, high, or critical.",
			)
			os.Exit(2)
		}
	}

	// Load the Terraform plan.
	plan, err := LoadPlan(*planPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	// Count planned resource changes.
	creates, updates, deletes := 0, 0, 0

	for _, resource := range plan.ResourceChanges {
		actions := resource.Change.Actions

		switch {
		case len(actions) == 1 && actions[0] == "create":
			creates++
		case len(actions) == 1 && actions[0] == "update":
			updates++
		case len(actions) == 1 && actions[0] == "delete":
			deletes++
		case len(actions) == 2 &&
			((actions[0] == "delete" && actions[1] == "create") ||
				(actions[0] == "create" && actions[1] == "delete")):
			creates++
			deletes++
		}
	}

	// Analyze the plan and calculate its risk.
	findings := AnalyzePlan(plan)
	if findings == nil {
		findings = []Finding{}
	}
	score := CalculateRiskScore(findings)

	report := Report{
		RiskScore: score,
		RiskLevel: getRiskLevel(score),
		Findings:  findings,
		Summary: Summary{
			Created: creates,
			Updated: updates,
			Deleted: deletes,
			Total:   len(plan.ResourceChanges),
		},
	}

	// Output the report.
	var output any

	switch format {
	case "json":
		output = report
	case "sarif":
		output = buildSARIF(findings, *planPath)
	default:
		printTextReport(plan, report)
	}

	if output != nil {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")

		if err := encoder.Encode(output); err != nil {
			fmt.Fprintln(os.Stderr, "Error encoding report:", err)
			os.Exit(1)
		}
	}

	// Enforce the configured severity threshold.
	if *failOn == "" {
		return
	}

	for _, finding := range findings {
		rank, _ := severityRank(finding.Severity)

		if rank >= threshold {
			if format == "text" {
				fmt.Printf(
					"\nFAILED: %s finding detected. Rule: %s\n",
					finding.Severity,
					finding.RuleID,
				)
			}
			os.Exit(1)
		}
	}

	if format == "text" {
		fmt.Println("\nPASSED: No findings reached the configured severity.")
	}
}

func printTextReport(plan *Plan, report Report) {
	fmt.Println("tf-risk - Terraform Risk & Security Gate")
	fmt.Println()
	fmt.Println("Terraform plan analysis")
	fmt.Println("-----------------------")

	for _, resource := range plan.ResourceChanges {
		fmt.Printf("%s (%s): %s\n",
			resource.Address,
			resource.Type,
			strings.Join(resource.Change.Actions, ", "),
		)
	}

	fmt.Println()
	fmt.Printf("Resources to create: %d\n", report.Summary.Created)
	fmt.Printf("Resources to update: %d\n", report.Summary.Updated)
	fmt.Printf("Resources to delete: %d\n", report.Summary.Deleted)
	fmt.Printf("Total resource changes: %d\n", report.Summary.Total)

	fmt.Println()
	fmt.Println("Security findings")
	fmt.Println("-----------------")

	if len(report.Findings) == 0 {
		fmt.Println("No findings.")
	}

	for _, finding := range report.Findings {
		fmt.Printf("[%s] %s - %s\n",
			finding.Severity,
			finding.Resource,
			finding.Message,
		)
		fmt.Printf("  Rule: %s\n", finding.RuleID)
		fmt.Printf("  Remediation: %s\n", finding.Remediation)
	}

	fmt.Println()
	fmt.Println("Risk Assessment")
	fmt.Println("----------------")
	fmt.Printf("Risk score: %d\n", report.RiskScore)
	fmt.Printf("Risk level: %s\n", report.RiskLevel)
}

// severityRank assigns an order to finding severities.
func severityRank(severity string) (int, bool) {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "LOW":
		return 1, true
	case "MEDIUM":
		return 2, true
	case "HIGH":
		return 3, true
	case "CRITICAL":
		return 4, true
	default:
		return 0, false
	}
}
