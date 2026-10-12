"""Recreate the MedTech assessment environment inside the local AWS emulator.

Mirrors the misconfigurations in the course's main.tf (IAM, VPC, security
groups, S3, RDS, CloudTrail). The EC2 bastion instance is left out because
none of the checks inspect instances.
"""
import json

PREFIX = "medtech-assessment"
SUFFIX = "a1b2c3d4"  # main.tf uses a random 8-character suffix
PUBLIC_BUCKET = f"{PREFIX}-public-data-{SUFFIX}"

ALL_BLOCKED = {
    "BlockPublicAcls": True, "IgnorePublicAcls": True,
    "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
NONE_BLOCKED = {flag: False for flag in ALL_BLOCKED}


def seed_iam(session):
    iam = session.client("iam")

    iam.create_user(UserName=f"{PREFIX}-student")
    iam.create_access_key(UserName=f"{PREFIX}-student")
    iam.attach_user_policy(
        UserName=f"{PREFIX}-student", PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")

    iam.create_user(UserName=f"{PREFIX}-admin")
    iam.create_access_key(UserName=f"{PREFIX}-admin")
    iam.attach_user_policy(
        UserName=f"{PREFIX}-admin", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")

    iam.create_user(UserName=f"{PREFIX}-developer")
    iam.put_user_policy(
        UserName=f"{PREFIX}-developer",
        PolicyName=f"{PREFIX}-developer-policy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))

    iam.create_role(
        RoleName=f"{PREFIX}-ec2-role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Action": "sts:AssumeRole",
                "Principal": {"Service": "ec2.amazonaws.com"}}]}))
    iam.put_role_policy(
        RoleName=f"{PREFIX}-ec2-role",
        PolicyName=f"{PREFIX}-ec2-policy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:*", "dynamodb:*", "rds:*"],
                "Resource": "*"}]}))


def seed_network(session):
    ec2 = session.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    zones = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"]]
    subnet_ids = [
        ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=zone)["Subnet"]["SubnetId"]
        for cidr, zone in (("10.0.1.0/24", zones[0]), ("10.0.2.0/24", zones[1]))]
    ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.10.0/24", AvailabilityZone=zones[0])

    def security_group(name, description, rules):
        group_id = ec2.create_security_group(
            GroupName=f"{PREFIX}-{name}", Description=description, VpcId=vpc_id)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
             "IpRanges": [{"CidrIp": cidr}]} for port, cidr in rules])
        return group_id

    security_group("web-sg", "Security group for web servers",
                   [(80, "0.0.0.0/0"), (443, "0.0.0.0/0"), (22, "0.0.0.0/0")])
    database_sg = security_group("database-sg", "Security group for database",
                                 [(3306, "0.0.0.0/0")])
    security_group("unused-sg", "Unused security group", [(8080, "10.0.0.0/16")])
    return subnet_ids, database_sg


def seed_s3(session):
    s3 = session.client("s3")

    s3.create_bucket(Bucket=PUBLIC_BUCKET)
    s3.put_public_access_block(
        Bucket=PUBLIC_BUCKET, PublicAccessBlockConfiguration=NONE_BLOCKED)
    s3.put_bucket_policy(Bucket=PUBLIC_BUCKET, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{PUBLIC_BUCKET}", f"arn:aws:s3:::{PUBLIC_BUCKET}/*"]}]}))

    # main.tf sets no public access block on these buckets. Real AWS turns it
    # on by default for new buckets; the emulator does not, so set it here.
    for name in ("patient-records", "ai-training", "logs", "cloudtrail"):
        bucket = f"{PREFIX}-{name}-{SUFFIX}"
        s3.create_bucket(Bucket=bucket)
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=ALL_BLOCKED)


def seed_rds(session, subnet_ids, database_sg):
    rds = session.client("rds")
    rds.create_db_subnet_group(
        DBSubnetGroupName=f"{PREFIX}-db-subnet-group",
        DBSubnetGroupDescription="MedTech database subnets",
        SubnetIds=subnet_ids)
    rds.create_db_instance(
        DBInstanceIdentifier=f"{PREFIX}-mysql",
        Engine="mysql",
        EngineVersion="8.0",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        DBName="medtechdb",
        MasterUsername="admin",
        MasterUserPassword="local-emulator-only",
        VpcSecurityGroupIds=[database_sg],
        DBSubnetGroupName=f"{PREFIX}-db-subnet-group",
        PubliclyAccessible=True,
        StorageEncrypted=False,
        BackupRetentionPeriod=1)


def seed_cloudtrail(session):
    cloudtrail = session.client("cloudtrail")
    cloudtrail.create_trail(
        Name=f"{PREFIX}-trail",
        S3BucketName=f"{PREFIX}-cloudtrail-{SUFFIX}",
        IsMultiRegionTrail=False,
        EnableLogFileValidation=False)
    cloudtrail.start_logging(Name=f"{PREFIX}-trail")


def seed_medtech_environment(session):
    seed_iam(session)
    subnet_ids, database_sg = seed_network(session)
    seed_s3(session)
    seed_rds(session, subnet_ids, database_sg)
    seed_cloudtrail(session)


def remediate_top_findings(session):
    """Stand-in for an engineer fixing the two internet-facing data exposures."""
    s3 = session.client("s3")
    s3.delete_bucket_policy(Bucket=PUBLIC_BUCKET)
    s3.put_public_access_block(Bucket=PUBLIC_BUCKET, PublicAccessBlockConfiguration=ALL_BLOCKED)

    ec2 = session.client("ec2")
    group = ec2.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [f"{PREFIX}-database-sg"]}])["SecurityGroups"][0]
    ec2.revoke_security_group_ingress(GroupId=group["GroupId"], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
         "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    ec2.authorize_security_group_ingress(GroupId=group["GroupId"], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
         "IpRanges": [{"CidrIp": "10.0.10.0/24"}]}])
