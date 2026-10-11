package main

import "strings"

type Finding struct {
	RuleID      string
	Severity    string
	Resource    string
	Message     string
	Remediation string
}

func AnalyzePlan(plan *Plan) []Finding {
	var findings []Finding

	for _, resource := range plan.ResourceChanges {
		actions := resource.Change.Actions

		hasDelete := false
		for _, action := range actions {
			if action == "delete" {
				hasDelete = true
				break
			}
		}

		if !hasDelete {
			continue
		}

		if isDatabaseResource(resource.Type) {
			findings = append(findings, Finding{
				RuleID:   "TF001",
				Severity: "CRITICAL",
				Resource: resource.Address,
				Message:  "A database resource will be deleted or replaced.",
				Remediation: "Verify backups, data retention, and the migration plan " +
					"before approving this change.",
			})
		}

		findings = append(findings, Finding{
			RuleID:   "TF002",
			Severity: "HIGH",
			Resource: resource.Address,
			Message:  "This resource will be deleted or replaced.",
			Remediation: "Confirm the change is intentional and that dependent " +
				"services will not be disrupted.",
		})
	}

	return findings
}

func isDatabaseResource(resourceType string) bool {
	resourceType = strings.ToLower(resourceType)

	databaseMarkers := []string{
		"aws_db_instance",
		"aws_rds_cluster",
		"aws_dynamodb_table",
		"azurerm_postgresql",
		"azurerm_mssql",
		"azurerm_mysql",
		"google_sql_database_instance",
	}

	for _, marker := range databaseMarkers {
		if strings.Contains(resourceType, marker) {
			return true
		}
	}

	return false
}
