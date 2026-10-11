package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Plan struct {
	FormatVersion   string           `json:"format_version"`
	ResourceChanges []ResourceChange `json:"resource_changes"`
}

type ResourceChange struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Change  Change `json:"change"`
}

type Change struct {
	Actions []string               `json:"actions"`
	After   map[string]interface{} `json:"after"`
}

func LoadPlan(path string) (*Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plan: %w", err)
	}

	var plan Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("parse plan JSON: %w", err)
	}

	return &plan, nil
}
