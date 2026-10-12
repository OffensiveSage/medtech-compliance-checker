"""End-to-end demo of the MedTech compliance checker, with no AWS account.

Everything runs against moto, a local in-memory AWS emulator. Nothing here
talks to real AWS.

    .venv/bin/python demo/run_demo.py

Pass --pause to wait for Enter between steps while recording.
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src" / "compliance_checker"))
sys.path.insert(0, str(ROOT / "demo"))

# Dummy credentials so boto3 can never pick up a real AWS profile.
os.environ.update({
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
})
os.environ.pop("AWS_PROFILE", None)

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

import app  # noqa: E402
import seed_environment  # noqa: E402

OUTPUT = ROOT / "output"
PAUSE = "--pause" in sys.argv

SCHEDULED_EVENT = {
    "version": "0",
    "detail-type": "Scheduled Event",
    "source": "aws.events",
    "resources": ["arn:aws:events:us-east-1:123456789012:rule/medtech-compliance-daily"],
    "detail": {},
}


def step(title):
    if PAUSE:
        input("\n(press Enter to continue) ")
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def deploy_automation(session):
    """Create what the SAM template creates: topic, audit table, report bucket."""
    sns = session.client("sns")
    topic_arn = sns.create_topic(Name="medtech-security-alerts")["TopicArn"]

    # An SQS queue stands in for the security team's email inbox.
    sqs = session.client("sqs")
    queue_url = sqs.create_queue(QueueName="security-team-inbox")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

    session.client("dynamodb").create_table(
        TableName="medtech-compliance-audit",
        KeySchema=[{"AttributeName": "run_id", "KeyType": "HASH"},
                   {"AttributeName": "item", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "run_id", "AttributeType": "S"},
                              {"AttributeName": "item", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST")

    s3 = session.client("s3")
    s3.create_bucket(Bucket="medtech-compliance-reports")
    s3.put_public_access_block(
        Bucket="medtech-compliance-reports",
        PublicAccessBlockConfiguration=seed_environment.ALL_BLOCKED)

    os.environ.update({
        "SNS_TOPIC_ARN": topic_arn,
        "AUDIT_TABLE": "medtech-compliance-audit",
        "REPORT_BUCKET": "medtech-compliance-reports",
    })
    return queue_url


def read_inbox(session, queue_url):
    messages = session.client("sqs").receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10).get("Messages", [])
    for message in messages:
        session.client("sqs").delete_message(
            QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
    return [json.loads(message["Body"]) for message in messages]


def run_and_show(session, queue_url, label):
    result = app.lambda_handler(SCHEDULED_EVENT, None)
    print("Lambda return value:")
    print(json.dumps(result, indent=2))

    step(f"{label}: notification delivered through SNS")
    for email in read_inbox(session, queue_url):
        print(f"Subject: {email['Subject']}\n")
        print(email["Message"])
        (OUTPUT / f"{label.lower().replace(' ', '_')}_notification.txt").write_text(
            f"Subject: {email['Subject']}\n\n{email['Message']}\n")

    bucket, key = result["report_location"].removeprefix("s3://").split("/", 1)
    body = session.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()
    (OUTPUT / f"{label.lower().replace(' ', '_')}_report.json").write_bytes(body)
    return result


def show_audit_trail(session):
    table = session.resource("dynamodb").Table("medtech-compliance-audit")
    items = sorted(table.scan()["Items"], key=lambda i: (i["run_id"], i["item"]))
    print(f"{'RUN ID':<28} {'ITEM':<13} DETAIL")
    for item in items:
        if item["run_id"] == "LATEST":
            detail = f"points to {item['latest_run_id']}"
        elif item["item"] == "RUN":
            counts = item["severity_counts"]
            detail = (f"{item['status']}  critical={counts['CRITICAL']} high={counts['HIGH']} "
                      f"medium={counts['MEDIUM']} low={counts['LOW']}")
        else:
            detail = f"{item['severity']:<8} {item['resource']}: {item['title']}"
        print(f"{item['run_id']:<28} {item['item']:<13} {detail}")


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def main():
    OUTPUT.mkdir(exist_ok=True)
    session = boto3.session.Session()

    step("STEP 1  Build the MedTech environment (same misconfigurations as main.tf)")
    seed_environment.seed_medtech_environment(session)
    print("Created: 3 IAM users, 1 role, 1 VPC, 3 security groups, 5 S3 buckets, "
          "1 RDS database, 1 CloudTrail trail")

    step("STEP 2  Deploy the automation (SNS topic, DynamoDB audit table, report bucket)")
    queue_url = deploy_automation(session)
    print("Deployed. The Lambda is triggered daily by an EventBridge schedule.")

    step("STEP 3  Scheduled run 1: EventBridge invokes the Lambda")
    first = run_and_show(session, queue_url, "Run 1")

    step("STEP 4  An engineer fixes the public bucket and the open database port")
    seed_environment.remediate_top_findings(session)
    print("Fixed: Block Public Access on, public bucket policy removed, "
          "MySQL restricted to the private subnet.")

    step("STEP 5  Scheduled run 2: the next day's check")
    second = run_and_show(session, queue_url, "Run 2")

    step("STEP 6  Audit trail in DynamoDB (every run and every finding)")
    show_audit_trail(session)

    step("RESULT")
    print(f"Run 1: {first['findings_count']} findings {first['severity_counts']}")
    print(f"Run 2: {second['findings_count']} findings {second['severity_counts']}")
    print(f"Reports and notifications saved to {OUTPUT.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()
