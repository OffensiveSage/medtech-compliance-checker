# MedTech Security Compliance Checker

Capstone project, Cloud Security Engineer track (Option A: Security Compliance Checker).

A scheduled AWS Lambda function that checks a MedTech AWS account for five
classes of security misconfiguration, emails a summary through SNS, stores a
JSON report in S3 and keeps an audit trail of every run in DynamoDB.

## What it checks

| ID | Check | Severity |
|---|---|---|
| S3-PUBLIC | Buckets readable by anyone, or without Block Public Access | Critical / Medium |
| SG-OPEN | Security groups exposing database or admin ports to 0.0.0.0/0 | Critical / High |
| IAM-ADMIN | IAM users with wildcard inline policies or AdministratorAccess | Critical / High |
| RDS-EXPOSURE | Databases that are publicly accessible or unencrypted | Critical / High |
| TRAIL-GAPS | CloudTrail missing, stopped, single-region, unvalidated or unencrypted | Critical / High / Medium |

Every check is read-only. Each finding carries the resource, the fix and the
HIPAA Security Rule safeguard it relates to.

## Run the demo (no AWS account needed)

The demo runs against [moto](https://github.com/getmoto/moto), an in-memory AWS
emulator. It recreates the misconfigurations from the course's `main.tf`, runs
the checker, applies two fixes, and runs it again.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python demo/run_demo.py
```

Add `--pause` to wait for Enter between steps while recording. Reports and
notification text are saved to `output/`.

## Run the tests

```bash
.venv/bin/python -m pytest tests -q
```

## Layout

| Path | Purpose |
|---|---|
| `src/compliance_checker/app.py` | Lambda handler and error handling |
| `src/compliance_checker/checks.py` | The five security checks |
| `src/compliance_checker/reporting.py` | Report, S3 storage, audit trail, SNS message |
| `template.yaml` | AWS SAM deployment: Lambda, schedule, SNS, DynamoDB, S3, failure alarm |
| `demo/seed_environment.py` | Builds the vulnerable MedTech environment in the emulator |
| `demo/run_demo.py` | End-to-end demo script |
| `tests/test_checker.py` | Tests for each check and the full run |

## Deploying to real AWS

`template.yaml` passes `cfn-lint` but has not been deployed to a real account.
With the SAM CLI installed it would be:

```bash
sam build
```

```bash
sam deploy --guided
```
