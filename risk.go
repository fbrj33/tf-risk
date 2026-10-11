package main

func CalculateRiskScore(findings []Finding) int {
	score := 0
	for _, finding := range findings {
		switch finding.Severity {
		case "CRITICAL":
			score += 10
		case "HIGH":
			score += 7
		case "MEDIUM":
			score += 4
		case "LOW":
			score += 1
		}
	}
	return score
}
