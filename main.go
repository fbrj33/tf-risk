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
		"exemples/basic/plan.json",
		"Path to the Terraform plan JSON file",
	)
	flag.Parse()
	plan, err := LoadPlan(*planPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	creates, updates, deletes := 0, 0, 0

	fmt.Println("tf-risk -terraform risk and security gate")
	fmt.Println()
	fmt.Println("terraform plan summary")
	fmt.Println("--------------------------")

	for _, resource := range plan.ResourceChanges {
		actions := resource.Change.Actions

		fmt.Printf(
			"%s (%s): %s\n",
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
		case len(actions) == 2:
			if actions[0] == "delete" && actions[1] == "create" {
				deletes++
				creates++
			} else if actions[0] == "create" && actions[1] == "delete" {
				creates++
				deletes++
			}
		}
	}
	fmt.Println()
	fmt.Printf("Resources to create: %d\n", creates)
	fmt.Printf("Resources to update: %d\n", updates)
	fmt.Printf("Resources to delete: %d\n", deletes)
	fmt.Printf("Total resource changes: %d\n", len(plan.ResourceChanges))

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

}
