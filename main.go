package main

import (
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

	flag.Parse()

	// Load the Terraform plan.
	plan, err := LoadPlan(*planPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	// Count planned resource changes.
	creates, updates, deletes := 0, 0, 0

	fmt.Println("tf-risk - Terraform Risk & Security Gate")
	fmt.Println()
	fmt.Println("Terraform plan analysis")
	fmt.Println("-----------------------")

	for _, resource := range plan.ResourceChanges {
		actions := resource.Change.Actions

		fmt.Printf("%s (%s): %s\n",
			resource.Address,
			resource.Type,
			strings.Join(actions, ", "),
		)

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

	fmt.Println()
	fmt.Printf("Resources to create: %d\n", creates)
	fmt.Printf("Resources to update: %d\n", updates)
	fmt.Printf("Resources to delete: %d\n", deletes)
	fmt.Printf("Total resource changes: %d\n", len(plan.ResourceChanges))

	// Analyze the plan for security risks.
	findings := AnalyzePlan(plan)

	fmt.Println()
	fmt.Println("Security findings")
	fmt.Println("-----------------")

	if len(findings) == 0 {
		fmt.Println("No findings.")
	}

	for _, finding := range findings {
		fmt.Printf("[%s] %s - %s\n",
			finding.Severity,
			finding.Resource,
			finding.Message,
		)
		fmt.Printf("  Rule: %s\n", finding.RuleID)
		fmt.Printf("  Remediation: %s\n", finding.Remediation)
	}

	// Calculate and display the risk score.
	score := CalculateRiskScore(findings)

	fmt.Println()
	fmt.Println("Risk Assessment")
	fmt.Println("----------------")
	fmt.Printf("Risk score: %d\n", score)

	switch {
	case score >= 20:
		fmt.Println("Risk level: CRITICAL")
	case score >= 10:
		fmt.Println("Risk level: HIGH")
	case score >= 5:
		fmt.Println("Risk level: MEDIUM")
	default:
		fmt.Println("Risk level: LOW")
	}

	// Enforce the configured severity threshold.
	if *failOn == "" {
		return
	}

	threshold, ok := severityRank(*failOn)
	if !ok {
		fmt.Fprintln(
			os.Stderr,
			"Invalid --fail-on value. Use low, medium, high, or critical.",
		)
		os.Exit(2)
	}

	for _, finding := range findings {
		rank, _ := severityRank(finding.Severity)

		if rank >= threshold {
			fmt.Printf(
				"\nFAILED: %s finding detected. Rule: %s\n",
				finding.Severity,
				finding.RuleID,
			)
			os.Exit(1)
		}
	}

	fmt.Println("\nPASSED: No findings reached the configured severity.")
}

// severityRank assigns an order to finding severities.
func severityRank(severity string) (int, bool) {
	switch strings.ToUpper(severity) {
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
