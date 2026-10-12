"""Read-only security checks for the MedTech compliance checker.

Each check takes a boto3 session and returns a list of Finding objects.
None of the checks change the environment.
"""
import json
from dataclasses import asdict, dataclass

from botocore.exceptions import ClientError

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Ports that should never be reachable from the whole internet.
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DATABASE_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 27017: "MongoDB"}

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


@dataclass
class Finding:
    check_id: str
    severity: str
    resource: str
    title: str
    detail: str
    remediation: str
    hipaa: str

    @property
    def key(self):
        """Stable identity, used to tell new findings from repeat ones."""
        return f"{self.check_id}|{self.resource}|{self.title}"

    def to_dict(self):
        return {**asdict(self), "key": self.key}


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _policy_document(document):
    return json.loads(document) if isinstance(document, str) else document


# --------------------------------------------------------------------------
# Check 1: S3 buckets exposed to the public
# --------------------------------------------------------------------------

def _public_access_blocked(s3, bucket):
    try:
        config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise
    return all(config.get(flag) for flag in (
        "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))


def _public_policy_actions(s3, bucket):
    """Actions a bucket policy grants to everyone, with no condition attached."""
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return []
        raise
    actions = []
    for statement in _as_list(policy.get("Statement")):
        principal = statement.get("Principal")
        is_everyone = principal == "*" or (
            isinstance(principal, dict) and "*" in _as_list(principal.get("AWS")))
        if statement.get("Effect") == "Allow" and is_everyone and not statement.get("Condition"):
            actions.extend(_as_list(statement.get("Action")))
    return actions


def check_s3_public_access(session):
    s3 = session.client("s3")
    findings = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        blocked = _public_access_blocked(s3, name)
        public_actions = _public_policy_actions(s3, name)
        if public_actions and not blocked:
            findings.append(Finding(
                check_id="S3-PUBLIC",
                severity="CRITICAL",
                resource=f"s3://{name}",
                title="Bucket is readable by anyone on the internet",
                detail=("Bucket policy allows Principal '*' to call "
                        f"{', '.join(sorted(public_actions))} and Block Public Access is off."),
                remediation=("Turn on all four S3 Block Public Access settings and remove the "
                             "public statement from the bucket policy."),
                hipaa="164.312(a)(1) Access control",
            ))
        elif not blocked:
            findings.append(Finding(
                check_id="S3-PUBLIC",
                severity="MEDIUM",
                resource=f"s3://{name}",
                title="Block Public Access is not fully enabled",
                detail="The bucket is not public today, but nothing prevents it becoming public.",
                remediation="Turn on all four S3 Block Public Access settings.",
                hipaa="164.312(a)(1) Access control",
            ))
    return findings


# --------------------------------------------------------------------------
# Check 2: security groups open to the world on sensitive ports
# --------------------------------------------------------------------------

def _open_to_world(permission):
    return (any(r.get("CidrIp") == "0.0.0.0/0" for r in permission.get("IpRanges", []))
            or any(r.get("CidrIpv6") == "::/0" for r in permission.get("Ipv6Ranges", [])))


def _exposed_ports(permission, watched):
    if permission.get("IpProtocol") == "-1":
        return dict(watched)
    low, high = permission.get("FromPort"), permission.get("ToPort")
    if low is None or high is None:
        return {}
    return {port: name for port, name in watched.items() if low <= port <= high}


def check_security_groups(session):
    ec2 = session.client("ec2")
    findings = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for group in page["SecurityGroups"]:
            resource = f"{group['GroupId']} ({group['GroupName']})"
            for permission in group.get("IpPermissions", []):
                if not _open_to_world(permission):
                    continue
                for port, service in _exposed_ports(permission, DATABASE_PORTS).items():
                    findings.append(Finding(
                        check_id="SG-OPEN",
                        severity="CRITICAL",
                        resource=resource,
                        title=f"{service} ({port}) is open to the internet",
                        detail=f"Inbound rule allows 0.0.0.0/0 to reach database port {port}.",
                        remediation=("Replace the 0.0.0.0/0 source with the application "
                                     "tier's security group."),
                        hipaa="164.312(e)(1) Transmission security",
                    ))
                for port, service in _exposed_ports(permission, ADMIN_PORTS).items():
                    findings.append(Finding(
                        check_id="SG-OPEN",
                        severity="HIGH",
                        resource=resource,
                        title=f"{service} ({port}) is open to the internet",
                        detail=f"Inbound rule allows 0.0.0.0/0 to reach admin port {port}.",
                        remediation=("Restrict the source to the corporate IP range, or remove "
                                     "the rule and use SSM Session Manager."),
                        hipaa="164.312(a)(1) Access control",
                    ))
    return findings


# --------------------------------------------------------------------------
# Check 3: IAM users holding administrator privileges
# --------------------------------------------------------------------------

def _is_full_wildcard(document):
    for statement in _as_list(_policy_document(document).get("Statement")):
        if (statement.get("Effect") == "Allow"
                and "*" in _as_list(statement.get("Action"))
                and "*" in _as_list(statement.get("Resource"))):
            return True
    return False


def _user_context(iam, user_name):
    has_mfa = bool(iam.list_mfa_devices(UserName=user_name)["MFADevices"])
    keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    active_keys = sum(1 for key in keys if key["Status"] == "Active")
    return f"MFA: {'yes' if has_mfa else 'NO'}, active access keys: {active_keys}."


def check_iam_admin_users(session):
    iam = session.client("iam")
    findings = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            resource = f"iam:user/{name}"

            for policy_name in iam.list_user_policies(UserName=name)["PolicyNames"]:
                document = iam.get_user_policy(
                    UserName=name, PolicyName=policy_name)["PolicyDocument"]
                if _is_full_wildcard(document):
                    findings.append(Finding(
                        check_id="IAM-ADMIN",
                        severity="CRITICAL",
                        resource=resource,
                        title="Inline policy grants every action on every resource",
                        detail=(f"Inline policy '{policy_name}' allows Action '*' on "
                                f"Resource '*'. {_user_context(iam, name)}"),
                        remediation=("Delete the inline policy and grant only the actions "
                                     "the job needs, through a group or role."),
                        hipaa="164.308(a)(4) Information access management",
                    ))

            attached = iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
            if any(policy["PolicyArn"] == ADMIN_POLICY_ARN for policy in attached):
                findings.append(Finding(
                    check_id="IAM-ADMIN",
                    severity="HIGH",
                    resource=resource,
                    title="AdministratorAccess is attached directly to a user",
                    detail=("Long-lived user credentials carry full admin rights. "
                            f"{_user_context(iam, name)}"),
                    remediation=("Move admin rights to a role assumed with MFA and remove "
                                 "the user's access keys."),
                    hipaa="164.308(a)(4) Information access management",
                ))
    return findings


# --------------------------------------------------------------------------
# Check 4: RDS databases that are public or unencrypted
# --------------------------------------------------------------------------

def check_rds_instances(session):
    rds = session.client("rds")
    findings = []
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            resource = f"rds:{db['DBInstanceIdentifier']}"
            if db.get("PubliclyAccessible"):
                findings.append(Finding(
                    check_id="RDS-EXPOSURE",
                    severity="CRITICAL",
                    resource=resource,
                    title="Database is publicly accessible",
                    detail="PubliclyAccessible is true, so the endpoint resolves to a public IP.",
                    remediation=("Set PubliclyAccessible to false and move the instance to "
                                 "private subnets."),
                    hipaa="164.312(a)(1) Access control",
                ))
            if not db.get("StorageEncrypted"):
                findings.append(Finding(
                    check_id="RDS-EXPOSURE",
                    severity="HIGH",
                    resource=resource,
                    title="Database storage is not encrypted",
                    detail="StorageEncrypted is false, so data and snapshots sit unencrypted.",
                    remediation=("Snapshot the instance, copy the snapshot with a KMS key, "
                                 "and restore from the encrypted copy."),
                    hipaa="164.312(a)(2)(iv) Encryption and decryption",
                ))
    return findings


# --------------------------------------------------------------------------
# Check 5: CloudTrail audit logging gaps
# --------------------------------------------------------------------------

def check_cloudtrail(session):
    cloudtrail = session.client("cloudtrail")
    trails = cloudtrail.describe_trails()["trailList"]
    if not trails:
        return [Finding(
            check_id="TRAIL-GAPS",
            severity="CRITICAL",
            resource="cloudtrail",
            title="No CloudTrail trail exists",
            detail="API activity in this account is not being recorded.",
            remediation="Create a multi-region trail with log file validation.",
            hipaa="164.312(b) Audit controls",
        )]

    findings = []
    for trail in trails:
        gaps = []
        logging_on = cloudtrail.get_trail_status(Name=trail["TrailARN"]).get("IsLogging")
        if not logging_on:
            gaps.append("logging is stopped")
        if not trail.get("IsMultiRegionTrail"):
            gaps.append("covers one region only")
        if not trail.get("LogFileValidationEnabled"):
            gaps.append("log file validation is off")
        if not trail.get("KmsKeyId"):
            gaps.append("logs are not encrypted with a KMS key")
        if not trail.get("CloudWatchLogsLogGroupArn"):
            gaps.append("not delivered to CloudWatch Logs, so no alerting")
        if gaps:
            findings.append(Finding(
                check_id="TRAIL-GAPS",
                severity="HIGH" if not logging_on else "MEDIUM",
                resource=f"cloudtrail:{trail['Name']}",
                title="CloudTrail trail has audit logging gaps",
                detail="Gaps: " + "; ".join(gaps) + ".",
                remediation=("Make the trail multi-region, enable log file validation and "
                             "KMS encryption, and send it to CloudWatch Logs."),
                hipaa="164.312(b) Audit controls",
            ))
    return findings


CHECKS = [
    ("S3-PUBLIC", "S3 buckets exposed to the public", check_s3_public_access),
    ("SG-OPEN", "Security groups open to the internet", check_security_groups),
    ("IAM-ADMIN", "IAM users with administrator privileges", check_iam_admin_users),
    ("RDS-EXPOSURE", "RDS databases public or unencrypted", check_rds_instances),
    ("TRAIL-GAPS", "CloudTrail audit logging gaps", check_cloudtrail),
]
