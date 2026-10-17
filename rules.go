package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Finding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Resource    string `json:"resource"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

func AnalyzePlan(plan *Plan) []Finding {
	var findings []Finding

	if plan == nil {
		return findings
	}

	// Run the existing rules for every resource.
	for _, resource := range plan.ResourceChanges {
		hasDelete := false

		for _, action := range resource.Change.Actions {
			if action == "delete" {
				hasDelete = true
				break
			}
		}

		if hasDelete {
			if isDatabaseResource(resource.Type) {
				findings = append(findings, Finding{
					RuleID:      "TF001",
					Severity:    "CRITICAL",
					Resource:    resource.Address,
					Message:     "A database resource will be deleted or replaced.",
					Remediation: "Verify backups, data retention, and the migration plan before approving this change.",
				})
			}

			findings = append(findings, Finding{
				RuleID:      "TF002",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "This resource will be deleted or replaced.",
				Remediation: "Confirm the change is intentional and dependent services will not be disrupted.",
			})
		}

		findings = append(findings, analyzeNetworkResource(resource)...)
		findings = append(findings, analyzeStorageResource(resource)...)
		findings = append(findings, analyzeIAMResource(resource)...)
	}

	// TF010: Find S3 buckets without a matching encryption configuration.
	encryptionConfigs := make(map[string]bool)

	for _, resource := range plan.ResourceChanges {
		if resource.Type != "aws_s3_bucket_server_side_encryption_configuration" {
			continue
		}

		// Skip configurations whose bucket reference is unknown.
		if attributeUnknown(resource, "bucket") {
			continue
		}

		if resource.Change.After == nil {
			continue
		}

		bucket, _ := resource.Change.After["bucket"].(string)
		if bucket != "" {
			encryptionConfigs[bucket] = true
		}
	}

	for _, resource := range plan.ResourceChanges {
		if resource.Type != "aws_s3_bucket" {
			continue
		}

		// Don't report a bucket if its identity is unknown.
		if attributeUnknown(resource, "bucket") {
			continue
		}

		if resource.Change.After == nil {
			continue
		}

		bucket, _ := resource.Change.After["bucket"].(string)
		if bucket == "" {
			continue
		}

		if !encryptionConfigs[bucket] {
			findings = append(findings, Finding{
				RuleID:      "TF010",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "S3 bucket has no matching server-side encryption configuration in the Terraform plan.",
				Remediation: "Add an aws_s3_bucket_server_side_encryption_configuration resource using AES256 or aws:kms.",
			})
		}
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

// -------------------- Unknown and typed values --------------------

func containsUnknown(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case map[string]interface{}:
		for _, child := range v {
			if containsUnknown(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range v {
			if containsUnknown(child) {
				return true
			}
		}
	}

	return false
}

func attributeUnknown(resource ResourceChange, key string) bool {
	unknown := resource.Change.AfterUnknown
	value, exists := unknown[key]
	return exists && containsUnknown(value)
}

func boolAttribute(attrs map[string]interface{}, key string) (bool, bool) {
	value, exists := attrs[key]
	if !exists || value == nil {
		return false, false
	}

	result, ok := value.(bool)
	return result, ok
}

func intAttribute(attrs map[string]interface{}, key string) (int, bool) {
	value, exists := attrs[key]
	if !exists || value == nil {
		return 0, false
	}

	switch v := value.(type) {
	case int:
		return v, true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case float64:
		return int(v), v == float64(int(v))
	default:
		return 0, false
	}
}

func numberValue(value interface{}) int {
	number, ok := intAttribute(map[string]interface{}{"value": value}, "value")
	if !ok {
		return 0
	}
	return number
}

// -------------------- Network rules: TF003, TF004, TF011, TF012 --------------------

func analyzeNetworkResource(resource ResourceChange) []Finding {
	attrs := resource.Change.After
	if attrs == nil {
		return nil
	}

	var rules []interface{}

	switch resource.Type {
	case "aws_security_group":
		if attributeUnknown(resource, "ingress") {
			return nil
		}

		ingress, ok := attrs["ingress"].([]interface{})
		if !ok {
			return nil
		}
		rules = ingress

	case "aws_security_group_rule":
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

		if attributeUnknown(resource, "from_port") ||
			attributeUnknown(resource, "to_port") ||
			attributeUnknown(resource, "protocol") ||
			attributeUnknown(resource, "ip_protocol") {
			continue
		}

		protocol, _ := rule["protocol"].(string)
		if protocol == "" {
			protocol, _ = rule["ip_protocol"].(string)
		}

		fromPort, fromOK := intAttribute(rule, "from_port")
		toPort, toOK := intAttribute(rule, "to_port")

		// All protocols includes all ports.
		if protocol == "-1" {
			findings = append(findings, Finding{
				RuleID:      "TF012",
				Severity:    "CRITICAL",
				Resource:    resource.Address,
				Message:     "Security group allows all protocols from the public internet.",
				Remediation: "Restrict ingress to required protocols and trusted source CIDRs.",
			})
			continue
		}

		if !fromOK || !toOK {
			continue
		}

		// TF003: SSH.
		if fromPort <= 22 && toPort >= 22 {
			findings = append(findings, Finding{
				RuleID:      "TF003",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "SSH (port 22) is exposed to the public internet.",
				Remediation: "Restrict SSH access to trusted IP addresses or use a secure access service.",
			})
		}

		// TF004: RDP.
		if fromPort <= 3389 && toPort >= 3389 {
			findings = append(findings, Finding{
				RuleID:      "TF004",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "RDP (port 3389) is exposed to the public internet.",
				Remediation: "Restrict RDP access to trusted IP addresses or use a secure access service.",
			})
		}

		// TF011: sensitive services other than SSH/RDP.
		sensitivePorts := map[int]string{
			21:    "FTP",
			23:    "Telnet",
			3306:  "MySQL",
			5432:  "PostgreSQL",
			1433:  "Microsoft SQL Server",
			6379:  "Redis",
			9200:  "Elasticsearch",
			27017: "MongoDB",
		}

		for port, service := range sensitivePorts {
			if fromPort <= port && toPort >= port {
				findings = append(findings, Finding{
					RuleID:      "TF011",
					Severity:    "HIGH",
					Resource:    resource.Address,
					Message:     fmt.Sprintf("%s port %d is exposed to the public internet.", service, port),
					Remediation: "Restrict ingress to trusted source IP addresses or private networks.",
				})
				break
			}
		}

		// TF012: broad port ranges.
		if fromPort == 0 && toPort >= 1024 {
			findings = append(findings, Finding{
				RuleID:      "TF012",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "Security group allows a broad range of ports from the public internet.",
				Remediation: "Allow only the specific ports required by the application.",
			})
		}
	}

	return findings
}

func isPublicRule(rule map[string]interface{}) bool {
	for _, key := range []string{
		"cidr_blocks",
		"cidr_ipv4",
		"cidr_ipv6",
		"ipv6_cidr_blocks",
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

// -------------------- Storage rules: TF005, TF007, TF008, TF009, TF010 --------------------

func analyzeStorageResource(resource ResourceChange) []Finding {
	attrs := resource.Change.After
	if attrs == nil {
		return nil
	}

	var findings []Finding

	switch resource.Type {
	case "aws_s3_bucket_acl":
		if attributeUnknown(resource, "acl") {
			return nil
		}

		acl, _ := attrs["acl"].(string)
		if acl == "public-read" || acl == "public-read-write" {
			findings = append(findings, Finding{
				RuleID:      "TF005",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "S3 bucket ACL allows public access.",
				Remediation: "Remove public ACL permissions and review bucket access policies.",
			})
		}

	case "aws_s3_bucket_public_access_block":
		flags := []string{
			"block_public_acls",
			"ignore_public_acls",
			"block_public_policy",
			"restrict_public_buckets",
		}

		for _, flag := range flags {
			if attributeUnknown(resource, flag) {
				continue
			}

			value, known := boolAttribute(attrs, flag)
			if known && !value {
				findings = append(findings, Finding{
					RuleID:      "TF005",
					Severity:    "HIGH",
					Resource:    resource.Address,
					Message:     "S3 public access protection is disabled: " + flag,
					Remediation: "Enable all four S3 Block Public Access settings unless an explicitly reviewed exception is required.",
				})
				break
			}
		}

	case "aws_ebs_volume":
		if attributeUnknown(resource, "encrypted") {
			return findings
		}

		encrypted, known := boolAttribute(attrs, "encrypted")
		if known && !encrypted {
			findings = append(findings, Finding{
				RuleID:      "TF007",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "EBS volume is configured without encryption.",
				Remediation: "Set encrypted = true on the EBS volume.",
			})
		}

	case "aws_db_instance":
		if !attributeUnknown(resource, "storage_encrypted") {
			encrypted, known := boolAttribute(attrs, "storage_encrypted")
			if known && !encrypted {
				findings = append(findings, Finding{
					RuleID:      "TF008",
					Severity:    "HIGH",
					Resource:    resource.Address,
					Message:     "RDS storage is configured without encryption.",
					Remediation: "Set storage_encrypted = true on the RDS instance.",
				})
			}
		}

		if !attributeUnknown(resource, "publicly_accessible") {
			public, known := boolAttribute(attrs, "publicly_accessible")
			if known && public {
				findings = append(findings, Finding{
					RuleID:      "TF009",
					Severity:    "HIGH",
					Resource:    resource.Address,
					Message:     "RDS instance is configured as publicly accessible.",
					Remediation: "Set publicly_accessible = false and use private networking.",
				})
			}
		}

	case "aws_s3_bucket_server_side_encryption_configuration":
		if attributeUnknown(resource, "rule") {
			return findings
		}

		rules, known := attrs["rule"].([]interface{})
		if !known || len(rules) == 0 {
			findings = append(findings, Finding{
				RuleID:      "TF010",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "S3 encryption configuration has no encryption rules.",
				Remediation: "Configure default server-side encryption using AES256 or aws:kms.",
			})
			return findings
		}

		hasRecognizedEncryption := false
		hasUnknownAlgorithm := false

		for _, item := range rules {
			rule, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			configs, ok := rule["apply_server_side_encryption_by_default"].([]interface{})
			if !ok || len(configs) == 0 {
				continue
			}

			for _, configItem := range configs {
				config, ok := configItem.(map[string]interface{})
				if !ok {
					continue
				}

				algorithm, ok := config["sse_algorithm"].(string)
				if !ok {
					hasUnknownAlgorithm = true
					continue
				}

				if algorithm == "AES256" || algorithm == "aws:kms" {
					hasRecognizedEncryption = true
				}
			}
		}

		if !hasRecognizedEncryption && !hasUnknownAlgorithm {
			findings = append(findings, Finding{
				RuleID:      "TF010",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "S3 encryption configuration does not specify a recognized encryption algorithm.",
				Remediation: "Configure default server-side encryption using AES256 or aws:kms.",
			})
		}
	}

	return findings
}

// -------------------- IAM rule: TF006 --------------------

func analyzeIAMResource(resource ResourceChange) []Finding {
	switch resource.Type {
	case "aws_iam_policy",
		"aws_iam_role_policy",
		"aws_iam_user_policy",
		"aws_iam_group_policy":
	default:
		return nil
	}

	attrs := resource.Change.After
	if attrs == nil || attributeUnknown(resource, "policy") {
		return nil
	}

	policyText, ok := attrs["policy"].(string)
	if !ok || policyText == "" {
		return nil
	}

	var policy struct {
		Statement []struct {
			Action   json.RawMessage `json:"Action"`
			Resource json.RawMessage `json:"Resource"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(policyText), &policy); err != nil {
		return nil
	}

	for _, statement := range policy.Statement {
		if containsWildcard(statement.Action) &&
			containsWildcard(statement.Resource) {
			return []Finding{{
				RuleID:      "TF006",
				Severity:    "HIGH",
				Resource:    resource.Address,
				Message:     "IAM policy grants wildcard actions on all resources.",
				Remediation: "Apply least privilege by limiting allowed actions and resources to what the workload actually needs.",
			}}
		}
	}

	return nil
}

func containsWildcard(value json.RawMessage) bool {
	var single string
	if err := json.Unmarshal(value, &single); err == nil {
		return single == "*"
	}

	var multiple []string
	if err := json.Unmarshal(value, &multiple); err == nil {
		for _, item := range multiple {
			if item == "*" {
				return true
			}
		}
	}

	return false
}
