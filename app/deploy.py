import boto3
from botocore.exceptions import ClientError
import uuid
from mypy_boto3_ec2.type_defs import TagSpecificationOutputTypeDef
import requests
from urllib3 import response

def create_s3_bucket():
    s3 = boto3.client("s3")
    region = boto3.session.Session().region_name

    bucket_name = f"cloudsec-private-{uuid.uuid4().hex[:8]}"

    try:
        print(f"Creating private bucket: {bucket_name}")
        
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
        
        # Block Pulic Access
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        
        # Enable Server-Side Encryption
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

def create_ec2_instance():
    ec2 = boto3.client("ec2")
    my_ip = requests.get("https://checkip.amazonaws.com").text.strip()

    print(f"My IP detected: {my_ip}")

    # Create a security group with SSH only from current IP
    sg_name = "cloudsec-ssh-only"
    sg_desc = "Allow SSH only from my current public IP"

    try:
        # Create SG
        response = ec2.create_security_group(
            GroupName=sg_name,
            Description=sg_desc,
        )
        sg_id = response["GroupId"]
        
        # Add ingress rule
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

    # Launch EC2 instance
    print("Launching EC2 instance...")

    instance = ec2.run_instances(
        ImageId="ami-0c02fb55956c7d316", # Amazon Linux 2 AMI in us-east-1
        InstanceType="t2.micro",
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
    print("EC2 Instace ID:", instance_id)

