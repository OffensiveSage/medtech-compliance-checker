"""MedTech Security Compliance Checker - Lambda entry point.

Triggered on a schedule by EventBridge. Runs every check, stores a JSON report
in S3, writes an audit trail to DynamoDB and sends a summary through SNS.
"""
import logging
import os
import uuid
from datetime import datetime, timezone

import boto3

import reporting
from checks import CHECKS

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_checks(session):
    """Run every check. A check that fails is recorded as ERROR and the rest still run."""
    findings, check_results = [], []
    for check_id, name, check in CHECKS:
        try:
            found = check(session)
        except Exception as exc:  # one broken check must not hide the others
            logger.exception("Check %s failed", check_id)
            check_results.append({
                "check_id": check_id, "name": name, "status": "ERROR",
                "findings": 0, "error": f"{type(exc).__name__}: {exc}"})
            continue
        findings.extend(found)
        check_results.append({
            "check_id": check_id, "name": name,
            "status": "FAIL" if found else "PASS", "findings": len(found)})
    return findings, check_results


def lambda_handler(event, context):
    run_id = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    started_at = _now()
    logger.info("Compliance run %s started", run_id)

    session = boto3.session.Session()
    table = session.resource("dynamodb").Table(os.environ["AUDIT_TABLE"])
    delivery_errors = []

    try:
        previous_keys = reporting.load_previous_keys(table)
    except Exception as exc:
        logger.exception("Could not read the previous run")
        delivery_errors.append(f"load_previous_run: {exc}")
        previous_keys = None

    findings, check_results = run_checks(session)
    report = reporting.build_report(
        run_id, started_at, _now(), check_results, findings, previous_keys)

    # Each output is independent: losing one must not lose the others.
    report_location = None
    try:
        report_location = reporting.store_report(
            session.client("s3"), os.environ["REPORT_BUCKET"], report)
    except Exception as exc:
        logger.exception("Could not store the report")
        delivery_errors.append(f"store_report: {exc}")

    try:
        reporting.write_audit_trail(table, report, report_location)
    except Exception as exc:
        logger.exception("Could not write the audit trail")
        delivery_errors.append(f"write_audit_trail: {exc}")

    try:
        reporting.notify(
            session.client("sns"), os.environ["SNS_TOPIC_ARN"], report, report_location)
    except Exception as exc:
        logger.exception("Could not send the notification")
        delivery_errors.append(f"notify: {exc}")

    check_errors = [c["check_id"] for c in check_results if c["status"] == "ERROR"]
    logger.info("Compliance run %s finished: %s", run_id, report["severity_counts"])
    return {
        "statusCode": 207 if (delivery_errors or check_errors) else 200,
        "run_id": run_id,
        "status": report["status"],
        "findings_count": len(findings),
        "severity_counts": report["severity_counts"],
        "report_location": report_location,
        "check_errors": check_errors,
        "delivery_errors": delivery_errors,
    }
