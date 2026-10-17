package main

import "testing"

func hasRule(findings []Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

func analyzeResource(resourceType string, after, unknown map[string]interface{}) []Finding {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "test." + resourceType,
				Type:    resourceType,
				Change: Change{
					Actions:      []string{"create"},
					After:        after,
					AfterUnknown: unknown,
				},
			},
		},
	}
	return AnalyzePlan(plan)
}

func assertRule(t *testing.T, findings []Finding, ruleID string, want bool) {
	t.Helper()
	got := hasRule(findings, ruleID)
	if got != want {
		t.Errorf("rule %s: expected finding=%v, got %v; findings=%+v",
			ruleID, want, got, findings)
	}
}
func TestTF007EBSVolumeEncryption(t *testing.T) {
	tests := []struct {
		name    string
		after   map[string]interface{}
		unknown map[string]interface{}
		want    bool
	}{
		{"encrypted", map[string]interface{}{"encrypted": true}, nil, false},
		{"unencrypted", map[string]interface{}{"encrypted": false}, nil, true},
		{"unknown", nil, map[string]interface{}{"encrypted": true}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeResource("aws_ebs_volume", tt.after, tt.unknown)
			assertRule(t, findings, "TF007", tt.want)
		})
	}
}
func TestTF008RDSStorageEncryption(t *testing.T) {
	tests := []struct {
		name    string
		after   map[string]interface{}
		unknown map[string]interface{}
		want    bool
	}{
		{"encrypted", map[string]interface{}{"storage_encrypted": true}, nil, false},
		{"unencrypted", map[string]interface{}{"storage_encrypted": false}, nil, true},
		{"unknown", nil, map[string]interface{}{"storage_encrypted": true}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeResource("aws_db_instance", tt.after, tt.unknown)
			assertRule(t, findings, "TF008", tt.want)
		})
	}
}

func TestTF009RDSPublicAccess(t *testing.T) {
	tests := []struct {
		name    string
		after   map[string]interface{}
		unknown map[string]interface{}
		want    bool
	}{
		{"public", map[string]interface{}{"publicly_accessible": true}, nil, true},
		{"private", map[string]interface{}{"publicly_accessible": false}, nil, false},
		{"unknown", nil, map[string]interface{}{"publicly_accessible": true}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeResource("aws_db_instance", tt.after, tt.unknown)
			assertRule(t, findings, "TF009", tt.want)
		})
	}
}

func TestTF010S3EncryptionConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		after   map[string]interface{}
		unknown map[string]interface{}
		want    bool
	}{
		{
			name: "valid AES256",
			after: map[string]interface{}{
				"rule": []interface{}{
					map[string]interface{}{
						"apply_server_side_encryption_by_default": []interface{}{
							map[string]interface{}{"sse_algorithm": "AES256"},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "invalid algorithm",
			after: map[string]interface{}{
				"rule": []interface{}{
					map[string]interface{}{
						"apply_server_side_encryption_by_default": []interface{}{
							map[string]interface{}{"sse_algorithm": "INVALID"},
						},
					},
				},
			},
			want: true,
		},
		{
			name:    "unknown configuration",
			after:   nil,
			unknown: map[string]interface{}{"rule": true},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeResource(
				"aws_s3_bucket_server_side_encryption_configuration",
				tt.after, tt.unknown,
			)
			assertRule(t, findings, "TF010", tt.want)
		})
	}
}
func TestTF011SensitivePublicIngress(t *testing.T) {
	tests := []struct {
		name string
		port float64
		cidr string
		want bool
	}{
		{"public MySQL", 3306, "0.0.0.0/0", true},
		{"public Redis", 6379, "0.0.0.0/0", true},
		{"private MySQL", 3306, "10.0.0.0/8", false},
		{"private Redis", 6379, "192.168.0.0/16", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeResource("aws_security_group_rule",
				map[string]interface{}{
					"type":        "ingress",
					"protocol":    "tcp",
					"from_port":   tt.port,
					"to_port":     tt.port,
					"cidr_blocks": []interface{}{tt.cidr},
				}, nil)
			assertRule(t, findings, "TF011", tt.want)
		})
	}
}

// TF012: Unrestricted or overly broad ingress.
func TestTF012BroadIngress(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		fromPort float64
		toPort   float64
		cidr     string
		want     bool
	}{
		{"all protocols public", "-1", 0, 0, "0.0.0.0/0", true},
		{"restricted SSH", "tcp", 22, 22, "10.0.0.0/8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeResource("aws_security_group_rule",
				map[string]interface{}{
					"type":        "ingress",
					"protocol":    tt.protocol,
					"from_port":   tt.fromPort,
					"to_port":     tt.toPort,
					"cidr_blocks": []interface{}{tt.cidr},
				}, nil)
			assertRule(t, findings, "TF012", tt.want)
		})
	}
}

// Integration: multiple rules must be returned by AnalyzePlan.
func TestAnalyzePlanReturnsMultipleSecurityFindings(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_ebs_volume.demo",
				Type:    "aws_ebs_volume",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"encrypted": false,
					},
				},
			},
			{
				Address: "aws_db_instance.demo",
				Type:    "aws_db_instance",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"publicly_accessible": true,
						"storage_encrypted":   false,
					},
				},
			},
		},
	}

	findings := AnalyzePlan(plan)

	for _, ruleID := range []string{"TF007", "TF008", "TF009"} {
		assertRule(t, findings, ruleID, true)
	}
}
func TestTF010DetectsBucketWithoutEncryptionConfiguration(t *testing.T) {
	plan := &Plan{
		ResourceChanges: []ResourceChange{
			{
				Address: "aws_s3_bucket.demo",
				Type:    "aws_s3_bucket",
				Change: Change{
					Actions: []string{"create"},
					After: map[string]interface{}{
						"bucket": "my-demo-bucket",
					},
				},
			},
		},
	}

	findings := AnalyzePlan(plan)
	assertRule(t, findings, "TF010", true)
}
