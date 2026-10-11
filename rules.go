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

		if hasDelete {
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

		findings = append(findings, analyzeNetworkResource(resource)...)
	}

	return findings
}

func isDatabaseResource(resourceType string) bool {
	resourceType = strings.ToLower(resourceType)

	markers := []string{
		"aws_db_instance",
		"aws_rds_cluster",
		"aws_dynamodb_table",
		"azurerm_postgresql",
		"azurerm_mssql",
		"azurerm_mysql",
		"google_sql_database_instance",
	}

	for _, marker := range markers {
		if strings.Contains(resourceType, marker) {
			return true
		}
	}

	return false
}

func analyzeNetworkResource(resource ResourceChange) []Finding {
	resourceType := resource.Type
	attrs := resource.Change.After

	if attrs == nil {
		return nil
	}

	var rules []interface{}

	switch resourceType {
	case "aws_security_group":
		// Only inspect ingress rules, not outbound traffic.
		if ingress, ok := attrs["ingress"].([]interface{}); ok {
			rules = ingress
		}
	case "aws_security_group_rule":
		// A security group rule may be inbound or outbound.
		if attrs["type"] != "ingress" {
			return nil
		}
		rules = []interface{}{attrs}
	case "aws_vpc_security_group_ingress_rule":
		rules = []interface{}{attrs}
	default:
		return nil
	}

	var findings []Finding

	for _, item := range rules {
		rule, ok := item.(map[string]interface{})
		if !ok || !isPublicRule(rule) {
			continue
		}

		fromPort := numberValue(rule["from_port"])
		toPort := numberValue(rule["to_port"])

		switch {
		case fromPort <= 22 && toPort >= 22:
			findings = append(findings, Finding{
				RuleID:      "TF003",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "SSH (port 22) is exposed to the public internet.",
				Remediation: "Restrict SSH access to trusted IP addresses or use a secure access service.",
			})
		case fromPort <= 3389 && toPort >= 3389:
			findings = append(findings, Finding{
				RuleID:      "TF004",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "RDP (port 3389) is exposed to the public internet.",
				Remediation: "Restrict RDP access to trusted IP addresses or use a secure access service.",
			})
		}
	}

	return findings
}

func isPublicRule(rule map[string]interface{}) bool {
	for _, key := range []string{
		"cidr_blocks",
		"cidr_ipv4",
		"source_address_prefix",
	} {
		if isPublicValue(rule[key]) {
			return true
		}
	}

	return false
}

func isPublicValue(value interface{}) bool {
	switch v := value.(type) {
	case string:
		return v == "0.0.0.0/0" || v == "::/0"
	case []interface{}:
		for _, item := range v {
			if isPublicValue(item) {
				return true
			}
		}
	}

	return false
}

func numberValue(value interface{}) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	}

	return 0
}
