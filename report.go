package main

import "path/filepath"

type Report struct {
	RiskScore int       `json:"risk_score"`
	RiskLevel string    `json:"risk_level"`
	Findings  []Finding `json:"findings"`
	Summary   Summary   `json:"summary"`
}

type Summary struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	Deleted int `json:"deleted"`
	Total   int `json:"total"`
}

func getRiskLevel(score int) string {
	switch {
	case score >= 20:
		return "CRITICAL"
	case score >= 10:
		return "HIGH"
	case score >= 5:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name  string      `json:"name"`
	Rules []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string `json:"id"`
	ShortDescription Text   `json:"shortDescription"`
}
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   Text            `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

type Text struct {
	Text string `json:"text"`
}

func buildSARIF(findings []Finding, planPath string) SARIFReport {
	rulesByID := make(map[string]SARIFRule)
	results := make([]SARIFResult, 0, len(findings))

	planURI := filepath.ToSlash(filepath.Clean(planPath))

	for _, finding := range findings {
		rulesByID[finding.RuleID] = SARIFRule{
			ID: finding.RuleID,
			ShortDescription: Text{
				Text: finding.Message,
			},
		}

		level := "note"
		switch finding.Severity {
		case "CRITICAL", "HIGH":
			level = "error"
		case "MEDIUM":
			level = "warning"
		}

		results = append(results, SARIFResult{
			RuleID: finding.RuleID,
			Level:  level,
			Message: Text{
				Text: finding.Resource + ": " + finding.Message +
					" Remediation: " + finding.Remediation,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: planURI,
						},
					},
				},
			},
		})
	}

	rules := make([]SARIFRule, 0, len(rulesByID))
	for _, rule := range rulesByID {
		rules = append(rules, rule)
	}

	return SARIFReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:  "tf-risk",
						Rules: rules,
					},
				},
				Results: results,
			},
		},
	}
}
