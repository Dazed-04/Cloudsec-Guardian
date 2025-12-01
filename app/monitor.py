import boto3
import time
import logging
from datetime import datetime, timedelta, UTC
import json
import os

# Log configuration
logging.basicConfig(
    filename="alerts.log",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Track last processed timestamp to avoid duplicate alerts
LAST_RUN_FILE = "last_run.txt"

# Threat rules with severity scoring
SUSPICIOUS_EVENTS = {
    "ConsoleLogin": ("Unauthorized login attempt", 3),
    "PutBucketAcl": ("Possible S3 public access risk", 2),
    "PutBucketPolicy": ("Possible S3 public access risk", 2),
    "TerminateInstances": ("EC2 instance termination attempt", 4),
    "RevokeSecurityGroupIngress": ("Security group modification", 3),
}


def load_last_run():
    """Get last processed timestamp to avoid duplicate alerts."""
    if os.path.exists(LAST_RUN_FILE):
        with open(LAST_RUN_FILE, "r") as f:
            ts = f.read().strip()
            try:
                return datetime.fromisoformat(ts)
            except ValueError:
                pass

    return datetime.now(UTC) - timedelta(hours=1)


def save_last_run(time_value):
    """Save timestamp of latest processed event."""
    with open(LAST_RUN_FILE, "w") as f:
        f.write(time_value.isoformat())


def get_cloudtrail_events():
    cloudtrail = boto3.client("cloudtrail")

    last_run = load_last_run()
    now = datetime.now(UTC)

    response = cloudtrail.lookup_events(
        StartTime=last_run,
        EndTime=now,
        MaxResults=50
    )

    events = response.get("Events", [])
    save_last_run(now)
    return events


def detect_threats(events):
    total_alerts = 0

    for event in events:
        name = event.get("EventName")
        event_time = event.get("EventTime")
        username = "Unknown"

        # Extract username from CloudTrail payload
        try:
            details = json.loads(event.get("CloudTrailEvent"))
            username = (
                details.get("userIdentity", {})
                .get("arn", "Unknown")
                .split("/")[-1]
            )
        except Exception:
            pass

        # Determine if suspicious
        if name in SUSPICIOUS_EVENTS:
            message, severity = SUSPICIOUS_EVENTS[name]
            total_alerts += 1

            alert_msg = (
                f"\nALERT [{severity}]: {message}\n"
                f" Event: {name}\n"
                f" User: {username}\n"
                f" Time: {event_time}\n"
            )

            print(alert_msg)
            logging.warning(alert_msg)

    print(f"Total alerts this scan: {total_alerts}")

def run_monitor_loop(interval=60):
    print(f"Monitoring started - checking every {interval}s.")

    try:
        while true:
            events = get_cloudtrail_events()
            detect_threats(events)
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nStopped monitoring.")
        logging.warning("Monitoring loop stopped by user.")


if __name__ == "__main__":
    run_monitor_loop(interval=60)
