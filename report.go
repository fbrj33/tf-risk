
package main

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
