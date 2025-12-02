import boto3
from botocore.exceptions import ClientError
import uuid
import requests

def create_s3_bucket():
    s3 = boto3.client("s3")
    region = boto3.session.Session().region_name

    bucket_name = f"cloudsec-private-{uuid.uuid4().hex[:8]}"

    try:
        print(f"Creating private bucket: {bucket_name}")

        # us-east-1 requires no LocationConstraint
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )

        # Block all public access
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        # Enable encryption
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            },
        )

        print(f"Bucket {bucket_name} created securely.")
        return bucket_name

    except ClientError as err:
        print("Error:", err)
        return None


def existing_instance():
    """Return an already running or pending instance ID if exists."""
    ec2 = boto3.client("ec2")
    response = ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["pending", "running"]}]
    )

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            return instance["InstanceId"]
    return None


def create_ec2_instance():
    ec2 = boto3.client("ec2")

    # Check first if instance already exists
    instance_id = existing_instance()
    if instance_id:
        print(f"Existing instance detected: {instance_id}")
        return instance_id

    my_ip = requests.get("https://checkip.amazonaws.com").text.strip()
    print(f"My IP detected: {my_ip}")

    sg_name = "cloudsec-ssh-only"
    sg_desc = "Allow SSH only from my current public IP"

    try:
        response = ec2.create_security_group(
            GroupName=sg_name,
            Description=sg_desc,
        )
        sg_id = response["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": f"{my_ip}/32"}],
                }
            ],
        )

        print(f"Security Group created: {sg_id}")

    except ClientError as err:
        if "InvalidGroup.Duplicate" in str(err):
            print("Security group already exists - fetching Group ID")
            groups = ec2.describe_security_groups(GroupNames=[sg_name])
            sg_id = groups["SecurityGroups"][0]["GroupId"]
        else:
            print(err)
            return None

    print("Launching EC2 instance...")

    instance = ec2.run_instances(
        ImageId="ami-0156001f0548e90b1",
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[sg_id],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Project", "Value": "CloudSecurity"}],
            }
        ],
    )["Instances"][0]

    instance_id = instance["InstanceId"]
    print(f"EC2 instance launched: {instance_id}")
    return instance_id


if __name__ == "__main__":
    bucket = create_s3_bucket()
    print("Created bucket:", bucket)

    instance_id = create_ec2_instance()
    print("EC2 Instance ID:", instance_id)

