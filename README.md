# tf-risk — Terraform Risk & Security Gate

**A Go-based DevSecOps CLI that detects security risks in Terraform plans before infrastructure deployment.**

`tf-risk` analyzes Terraform plan JSON files, identifies potentially dangerous infrastructure changes, calculates risk scores, and generates actionable security reports. It integrates with CI/CD pipelines to help teams catch misconfigurations before they reach production.

## Features

- **12 security rules:** Detect risky infrastructure changes and common cloud security misconfigurations.
- **Risk scoring:** Calculate a risk score and classify the overall risk level.
- **Configurable security policies:** Disable rules and override finding severities using YAML.
- **Multiple output formats:** Generate human-readable text, JSON, and SARIF reports.
- **CI/CD enforcement:** Fail a pipeline when findings meet a configurable severity threshold.
- **Actionable remediation:** Include recommendations with detected findings.
- **GitHub Actions integration:** Run security checks as part of an automated workflow.
- **GitHub Code Scanning:** Upload SARIF results so findings can appear in the repository's security alerts.

## Security Checks

The built-in rules cover risks such as:

| Risk category | Examples |
|---|---|
| Infrastructure changes | Deletion or replacement of critical resources |
| Network security | Public SSH/RDP access and unrestricted ingress |
| Storage security | Public storage exposure and missing encryption |
| Database security | Publicly accessible databases and unencrypted storage |
| Identity and access | Overly permissive IAM policies |

The scanner implements 12 rules, identified as `TF001` through `TF012`. Run `--list-rules` to inspect the rules supported by your current version.

## How It Works

1. Generate a Terraform plan.
2. Export the plan to JSON.
3. Analyze resource changes and security-sensitive configuration.
4. Produce findings, remediation guidance, and a risk assessment.
5. Optionally fail the CI/CD workflow when the configured severity threshold is reached.
6. Export SARIF results for integration with GitHub Code Scanning.

## Requirements

- Go version compatible with the project's `go.mod`
- Terraform, when generating plans from Terraform configuration
- A Terraform plan exported as JSON

## Getting Started

Clone the repository:

```bash
git clone https://github.com/fbrj33/tf-risk.git
cd tf-risk
```

Run the test suite:

```bash
go test ./...
go vet ./...
```

Build the CLI.

**Windows PowerShell:**

```powershell
go build -o tf-risk.exe .
```

**Linux/macOS:**

```bash
go build -o tf-risk .
```

## Usage

### 1. Generate a Terraform plan

Run these commands in your Terraform project:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

### 2. Analyze the plan

**Windows PowerShell:**

```powershell
.\tf-risk.exe --plan plan.json
```

**Linux/macOS:**

```bash
./tf-risk --plan plan.json
```

### 3. Enforce a severity threshold

Fail the command when findings reach `HIGH` severity or above:

```bash
tf-risk --plan plan.json --fail-on high
```

Replace `tf-risk` with `.\tf-risk.exe` on Windows PowerShell.

Supported thresholds are `low`, `medium`, `high`, and `critical`.

### 4. Generate reports

Text report:

```bash
tf-risk --plan plan.json --format text
```

JSON report:

```bash
tf-risk --plan plan.json --format json
```

SARIF report:

```bash
tf-risk --plan plan.json --format sarif
```

To save a SARIF report to a file:

```bash
tf-risk --plan plan.json --format sarif > tf-risk.sarif
```

### 5. List security rules

```bash
tf-risk --list-rules
```

### 6. Inspect available options

```bash
tf-risk --help
```

## Example: Detecting Public SSH Exposure

The repository includes an intentionally unsafe example at `examples/basic/unsafe-plan.json`.

Run:

```bash
tf-risk --plan examples/basic/unsafe-plan.json --fail-on high
```

Example finding:

```text
[HIGH] aws_security_group_rule.unsafe_ssh - SSH (port 22) is exposed to the public internet.
  Rule: TF003
  Remediation: Restrict SSH access to trusted IP addresses or use a secure access service.
```

The scanner also reports a risk score and an overall risk level. The example is deliberately insecure and is intended for testing, not deployment.

A safe example is available at `examples/basic/plan.json`.

## Configuration

`tf-risk` supports YAML configuration for disabling rules and overriding their severity.

Example `tf-risk.yaml`:

```yaml
disabled_rules:
  - TF003

severity_overrides:
  TF002: CRITICAL
```

Use a custom policy:

```bash
tf-risk --plan plan.json --config custom-policy.yaml
```

Disabling a rule or changing its severity should be done in accordance with your organization's security policy.

## GitHub Actions Integration

Use `tf-risk` in a GitHub Actions workflow to scan Terraform plan JSON as part of CI/CD.

```yaml
- name: Scan Terraform plan
  uses: fbrj33/tf-risk@v1
  with:
    plan: plan.json
    fail-on: high
    format: sarif

- name: Upload SARIF results
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: tf-risk.sarif
```

**Important:** Generate `plan.json` before running the scanner. The SARIF report path must match the path configured by the action and be accessible to the upload step. The workflow also needs the appropriate `security-events: write` permission and GitHub Code Scanning availability.

An unsafe plan reaching the configured threshold should fail the security scan. In automated tests, handle that expected failure explicitly and verify that the report contains the expected finding.

## Testing and Validation

Run the project's checks:

```bash
go test ./...
go vet ./...
go build .
```

The repository's CI workflow also checks safe and unsafe example plans, validates SARIF output, and tests the security-scanning integration.

## Technology Stack

- **Go** — CLI implementation and security analysis
- **Terraform** — Infrastructure as Code plan input
- **YAML** — Configurable security policies
- **JSON** — Terraform plan input and structured reports
- **SARIF** — Security findings interoperability
- **GitHub Actions** — Continuous integration and automated security gates
- **GitHub Code Scanning** — Security alert visualization

## Project Goal

The goal of `tf-risk` is to make infrastructure security checks repeatable and automatable by detecting risky Terraform changes before deployment, while providing actionable findings that fit into existing DevSecOps workflows.

## Author

**Farah Ben Rejeb**

- GitHub: https://github.com/fbrj33
- Repository: https://github.com/fbrj33/tf-risk
