# Terraform Risk & Security Gate

**tf-risk** is a Go-based command-line tool that analyzes Terraform plan JSON files to identify infrastructure security risks and potentially dangerous changes before deployment.

It helps DevOps and platform engineering teams enforce security policies in their Infrastructure as Code (IaC) workflows.

## Features

- **Security analysis:** Detects risky Terraform changes using 12 security rules.
- **Risk scoring:** Calculates a risk score and classifies the overall risk level.
- **Policy configuration:** Disable specific rules and override finding severities through YAML configuration.
- **Multiple report formats:** Generate text, JSON, and SARIF reports.
- **CI/CD enforcement:** Fail a pipeline when findings meet a configurable severity threshold.
- **Remediation guidance:** Provide recommendations for addressing detected issues.

## Security Checks

The rules cover risks including:

- Deletion or replacement of critical infrastructure.
- Public SSH and RDP access.
- Publicly exposed storage resources.
- Overly permissive IAM policies.
- Unencrypted EBS volumes, RDS storage, and S3 buckets.
- Publicly accessible databases.
- Unrestricted ingress ports and security group rules.

## Requirements

- Go
- Terraform, to generate plan files
- A Terraform plan exported as JSON

## Getting Started

Clone the repository:

```bash
git clone https://github.com/fbrj33/tf-risk.git
cd tf-risk
```

Build the CLI:

```bash
go build -o tf-risk.exe .
```

Run the tests:

```bash
go test ./...
```

## Usage

Generate a Terraform plan in JSON format:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

Analyze the plan:

```bash
.\tf-risk.exe --plan plan.json
```

Set a severity threshold for pipeline enforcement:

```bash
.\tf-risk.exe --plan plan.json --fail-on high
```

Generate a JSON report:

```bash
.\tf-risk.exe --plan plan.json --format json
```

Generate a SARIF report:

```bash
.\tf-risk.exe --plan plan.json --format sarif
```

List the available security rules:

```bash
.\tf-risk.exe --list-rules
```

## Configuration

The tool supports a `tf-risk.yaml` configuration file for disabling rules and overriding their severity.

Example:

```yaml
disabled_rules:
  - TF003

severity_overrides:
  TF002: CRITICAL
```

Pass a custom configuration file with:

```bash
.\tf-risk.exe --plan plan.json --config custom-policy.yaml
```

## Testing

Run the automated test suite:

```bash
go test ./...
go vet ./...
go build -o tf-risk.exe .
```

## Technology Stack

- **Go** — CLI implementation and security analysis
- **Terraform** — Infrastructure as Code plan input
- **YAML** — Configurable security policies
- **JSON and SARIF** — Machine-readable reports and security-tool integration
- **GitHub Actions** — Continuous integration

## Project Goal

The goal is to make infrastructure security checks repeatable and automatable by detecting risky Terraform changes before they reach deployment.

## Author

Farah Ben Rejeb

[GitHub Repository](https://github.com/fbrj33/tf-risk)