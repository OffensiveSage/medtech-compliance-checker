"""Report building, storage, audit trail and notification for the compliance checker."""
import json

from checks import SEVERITY_ORDER

LATEST_POINTER = {"run_id": "LATEST", "item": "RUN"}


def build_report(run_id, started_at, finished_at, check_results, findings, previous_keys):
    """Assemble the run report. previous_keys is None on the first ever run."""
    current_keys = {finding.key for finding in findings}
    first_run = previous_keys is None
    previous_keys = set(previous_keys or [])

    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.resource))
    return {
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "status": "NON_COMPLIANT" if findings else "COMPLIANT",
        "first_run": first_run,
        "severity_counts": {
            level: sum(1 for f in findings if f.severity == level) for level in SEVERITY_ORDER},
        "checks": check_results,
        "findings": [
            {**f.to_dict(), "is_new": f.key not in previous_keys} for f in ordered],
        "resolved_since_last_run": sorted(previous_keys - current_keys),
    }


def render_text(report, report_location=None):
    """Plain-text summary, used as the SNS message body."""
    counts = report["severity_counts"]
    lines = [
        "MedTech Security Compliance Check",
        f"Run:    {report['run_id']}",
        f"Time:   {report['finished_at']}",
        f"Status: {report['status']}",
        "",
        "Findings: " + ", ".join(f"{counts[level]} {level}" for level in SEVERITY_ORDER),
    ]
    if not report["first_run"]:
        new = sum(1 for f in report["findings"] if f["is_new"])
        lines.append(f"Since last run: {new} new, "
                     f"{len(report['resolved_since_last_run'])} resolved")

    lines += ["", "Checks:"]
    for check in report["checks"]:
        outcome = (f"ERROR ({check['error']})" if check["status"] == "ERROR"
                   else f"{check['status']}, {check['findings']} finding(s)")
        lines.append(f"  [{check['check_id']}] {check['name']}: {outcome}")

    if report["findings"]:
        lines += ["", "Findings, most severe first:"]
    for finding in report["findings"]:
        marker = " (NEW)" if finding["is_new"] and not report["first_run"] else ""
        lines += [
            f"  {finding['severity']}{marker}: {finding['title']}",
            f"    Resource: {finding['resource']}",
            f"    Detail:   {finding['detail']}",
            f"    Fix:      {finding['remediation']}",
            f"    HIPAA:    {finding['hipaa']}",
        ]

    if report["resolved_since_last_run"]:
        lines += ["", "Resolved since last run:"]
        lines += [f"  {key}" for key in report["resolved_since_last_run"]]

    if report_location:
        lines += ["", f"Full report: {report_location}"]
    return "\n".join(lines)


def store_report(s3, bucket, report):
    day = report["finished_at"][:10].replace("-", "/")
    key = f"reports/{day}/{report['run_id']}.json"
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(report, indent=2).encode(),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )
    return f"s3://{bucket}/{key}"


def load_previous_keys(table):
    """Finding keys from the previous run, or None if there has been no run yet."""
    item = table.get_item(Key=LATEST_POINTER).get("Item")
    return None if item is None else list(item.get("finding_keys", []))


def write_audit_trail(table, report, report_location):
    """One item per run, one per finding, plus a pointer to the latest run."""
    with table.batch_writer() as batch:
        batch.put_item(Item={
            "run_id": report["run_id"],
            "item": "RUN",
            "started_at": report["started_at"],
            "finished_at": report["finished_at"],
            "status": report["status"],
            "severity_counts": report["severity_counts"],
            "checks": report["checks"],
            "report_location": report_location or "NOT_STORED",
        })
        for index, finding in enumerate(report["findings"], start=1):
            batch.put_item(Item={
                "run_id": report["run_id"],
                "item": f"FINDING#{index:03d}",
                **finding,
            })
        batch.put_item(Item={
            **LATEST_POINTER,
            "latest_run_id": report["run_id"],
            "finished_at": report["finished_at"],
            "finding_keys": [finding["key"] for finding in report["findings"]],
        })


def notify(sns, topic_arn, report, report_location):
    counts = report["severity_counts"]
    subject = (f"[MedTech Security] {report['status']}: "
               f"{counts['CRITICAL']} critical, {counts['HIGH']} high")
    sns.publish(
        TopicArn=topic_arn,
        Subject=subject[:100],
        Message=render_text(report, report_location),
    )
