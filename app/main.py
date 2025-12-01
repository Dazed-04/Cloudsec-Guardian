import boto3
import time
from deploy import create_s3_bucket, create_ec2_instance
from monitor import run_monitor_loop

def ensure_cloudtrail():
    cloudtrail = boto3.client("cloudtrail")

    trails = cloudtrail.describe_trails().get("trailList", [])
    if trails:
        print("CloudTrail already enabled.")
        return True

    print("Error: CloudTrail is not enabled. Please enable before running automation.")
    return False


def deploy_resources():
    print("\n--- Deploying Secure Infrastructure ---")

    bucket = create_s3_bucket()
    if not bucket:
        print("Bucket creation failed. Exiting.")
        return False

    instance_id = create_ec2_instance()
    if not instance_id:
        print("EC2 creation failed. Exiting.")
        return False

    print("Deployment complete.")
    return True


def main():
    print("\n===== CloudSec Guardian =====")
    print("Automated Cloud Security + Monitoring\n")

    if not ensure_cloudtrail():
        return

    print("\nStarting secure deployment...")
    if not deploy_resources():
        return

    print("\nInfrastructure secure. Starting threat monitoring...\n")
    run_monitor_loop(interval=60)


if __name__ == "__main__":
    main()

