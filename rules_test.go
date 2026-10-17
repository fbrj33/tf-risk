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

func TestDetectsPublicSSH(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_security_group.web",
				Type:    "aws_security_group",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"ingress": []interface{}{
							map[string]interface{}{
								"from_port":   float64(22),
								"to_port":     float64(22),
								"cidr_blocks": []interface{}{"0.0.0.0/0"},
							},
						},
					},
				},
			},
		},
	}

	findings := AnalyzePlan(plan)

	found := false
	for _, finding := range findings {
		if finding.RuleID == "TF003" {
			found = true
			break
		}
	}

	if !found {
		t.Fatal("expected TF003 finding for public SSH")
	}
}

func TestDoesNotFlagPrivateSSH(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_security_group.internal",
				Type:    "aws_security_group",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"ingress": []interface{}{
							map[string]interface{}{
								"from_port":   float64(22),
								"to_port":     float64(22),
								"cidr_blocks": []interface{}{"10.0.0.0/8"},
							},
						},
					},
				},
			},
		},
	}

	findings := AnalyzePlan(plan)

	for _, finding := range findings {
		if finding.RuleID == "TF003" {
			t.Fatal("unexpected public SSH finding for private CIDR")
		}
	}
}

func TestDetectsPublicS3ACL(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{{
			Address: "aws_s3_bucket_acl.demo",
			Type:    "aws_s3_bucket_acl",
			Change: Change{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"acl": "public-read",
				},
			},
		}},
	}

	findings := AnalyzePlan(plan)

	for _, finding := range findings {
		if finding.RuleID == "TF005" {
			return
		}
	}

	t.Fatal("expected TF005 for public S3 ACL")
}

func TestDetectsWildcardIAMPolicy(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{{
			Address: "aws_iam_policy.admin",
			Type:    "aws_iam_policy",
			Change: Change{
				Actions: []string{"create"},
				After: map[string]interface{}{
					"policy": `{
						"Version": "2012-10-17",
						"Statement": [{
							"Effect": "Allow",
							"Action": "*",
							"Resource": "*"
						}]
					}`,
				},
			},
		}},
	}

	findings := AnalyzePlan(plan)

	for _, finding := range findings {
		if finding.RuleID == "TF006" {
			return
		}
	}

	t.Fatal("expected TF006 for wildcard IAM policy")
}
func TestDetectsPublicIPv6SSH(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_security_group.ipv6_ssh",
				Type:    "aws_security_group",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"ingress": []interface{}{
							map[string]interface{}{
								"from_port": float64(22),
								"to_port":   float64(22),
								"protocol":  "tcp",
								"ipv6_cidr_blocks": []interface{}{
									"::/0",
								},
							},
						},
					},
				},
			},
		},
	}

	findings := AnalyzePlan(plan)
	if !hasRule(findings, "TF003") {
		t.Fatal("expected TF003 for SSH exposed to public IPv6")
	}

}
func TestDetectsPublicIPv6RDP(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_security_group.ipv6_rdp",
				Type:    "aws_security_group",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"ingress": []interface{}{
							map[string]interface{}{
								"from_port": float64(3389),
								"to_port":   float64(3389),
								"protocol":  "tcp",
								"ipv6_cidr_blocks": []interface{}{
									"::/0",
								},
							},
						},
					},
				},
			},
		},
	}

	findings := AnalyzePlan(plan)
	if !hasRule(findings, "TF004") {
		t.Fatal("expected TF004 for RDP exposed to public IPv6")
	}
}
func TestDoesNotFlagPrivateIPv6SSH(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_security_group.private_ipv6",
				Type:    "aws_security_group",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"ingress": []interface{}{
							map[string]interface{}{
								"from_port": float64(22),
								"to_port":   float64(22),
								"protocol":  "tcp",
								"ipv6_cidr_blocks": []interface{}{
									"2001:db8::/64",
								},
							},
						},
					},
				},
			},
		},
	}

	findings := AnalyzePlan(plan)
	if hasRule(findings, "TF003") {
		t.Fatal("unexpected TF003 for restricted IPv6 CIDR")
	}
}

func TestDatabaseDeletionProducesTF001AndTF002(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_db_instance.production",
				Type:    "aws_db_instance",
				Change: Change{
					Actions: []string{"delete"},
				},
			},
		},
	}

	findings := AnalyzePlan(plan)

	if !hasRule(findings, "TF001") {
		t.Fatal("expected TF001 for database deletion")
	}
	if !hasRule(findings, "TF002") {
		t.Fatal("expected TF002 for resource deletion")
	}
}

func TestRegularResourceDeletionProducesTF002Only(t *testing.T) {
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

	if !hasRule(findings, "TF002") {
		t.Fatal("expected TF002 for resource deletion")
	}
	if hasRule(findings, "TF001") {
		t.Fatal("unexpected TF001 for non-database deletion")
	}
}

func TestDatabaseReplacementProducesTF001AndTF002(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_db_instance.production",
				Type:    "aws_db_instance",
				Change: Change{
					Actions: []string{"delete", "create"},
				},
			},
		},
	}

	findings := AnalyzePlan(plan)

	if !hasRule(findings, "TF001") {
		t.Fatal("expected TF001 for database replacement")
	}
	if !hasRule(findings, "TF002") {
		t.Fatal("expected TF002 for resource replacement")
	}
}
