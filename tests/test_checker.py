import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "compliance_checker"))
sys.path.insert(0, str(ROOT / "demo"))

import app  # noqa: E402
import checks  # noqa: E402
import run_demo  # noqa: E402
import seed_environment  # noqa: E402


@pytest.fixture
def session():
    os.environ.update({
        "AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": "us-east-1"})
    with mock_aws(config={"iam": {"load_aws_managed_policies": True}}):
        yield boto3.session.Session()


@pytest.fixture
def medtech(session):
    seed_environment.seed_medtech_environment(session)
    return session


def test_clean_account_has_only_the_missing_trail_finding(session):
    findings, results = app.run_checks(session)
    assert [f.title for f in findings] == ["No CloudTrail trail exists"]
    assert all(r["status"] != "ERROR" for r in results)


def test_public_bucket_is_critical_and_private_buckets_pass(medtech):
    findings = checks.check_s3_public_access(medtech)
    assert [(f.severity, f.resource) for f in findings] == [
        ("CRITICAL", f"s3://{seed_environment.PUBLIC_BUCKET}")]


def test_security_groups_flag_ssh_and_mysql_but_not_web_or_internal_ports(medtech):
    found = {(f.severity, f.title) for f in checks.check_security_groups(medtech)}
    assert found == {
        ("CRITICAL", "MySQL (3306) is open to the internet"),
        ("HIGH", "SSH (22) is open to the internet")}


def test_iam_flags_admin_and_developer_but_not_readonly_student(medtech):
    found = {(f.severity, f.resource) for f in checks.check_iam_admin_users(medtech)}
    assert found == {
        ("CRITICAL", "iam:user/medtech-assessment-developer"),
        ("HIGH", "iam:user/medtech-assessment-admin")}


def test_rds_flags_public_and_unencrypted(medtech):
    found = {(f.severity, f.title) for f in checks.check_rds_instances(medtech)}
    assert found == {
        ("CRITICAL", "Database is publicly accessible"),
        ("HIGH", "Database storage is not encrypted")}


def test_cloudtrail_gaps_are_reported(medtech):
    (finding,) = checks.check_cloudtrail(medtech)
    assert finding.severity == "MEDIUM"
    assert "covers one region only" in finding.detail
    assert "log file validation is off" in finding.detail


def test_full_run_writes_report_audit_trail_and_notification(medtech):
    queue_url = run_demo.deploy_automation(medtech)

    first = app.lambda_handler(run_demo.SCHEDULED_EVENT, None)
    assert first["statusCode"] == 200
    assert first["severity_counts"] == {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 1, "LOW": 0}
    (email,) = run_demo.read_inbox(medtech, queue_url)
    assert "4 critical, 3 high" in email["Subject"]

    seed_environment.remediate_top_findings(medtech)
    second = app.lambda_handler(run_demo.SCHEDULED_EVENT, None)
    assert second["severity_counts"] == {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 1, "LOW": 0}
    (email,) = run_demo.read_inbox(medtech, queue_url)
    assert "Since last run: 0 new, 2 resolved" in email["Message"]

    table = medtech.resource("dynamodb").Table("medtech-compliance-audit")
    items = table.scan()["Items"]
    assert sum(1 for i in items if i["item"] == "RUN" and i["run_id"] != "LATEST") == 2
    assert sum(1 for i in items if i["item"].startswith("FINDING#")) == 14


def test_a_failing_check_is_reported_and_the_others_still_run(medtech, monkeypatch):
    queue_url = run_demo.deploy_automation(medtech)

    def broken(_session):
        raise RuntimeError("AccessDenied")

    monkeypatch.setattr(app, "CHECKS", [
        ("S3-PUBLIC", "S3 buckets exposed to the public", broken), *checks.CHECKS[1:]])
    result = app.lambda_handler(run_demo.SCHEDULED_EVENT, None)

    assert result["statusCode"] == 207
    assert result["check_errors"] == ["S3-PUBLIC"]
    assert result["findings_count"] == 7
    (email,) = run_demo.read_inbox(medtech, queue_url)
    assert "ERROR (RuntimeError: AccessDenied)" in email["Message"]
