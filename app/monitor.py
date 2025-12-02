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
    # Authentication security
    "ConsoleLogin": ("Unauthorized login attempt", 3),

    # S3 risks
    "PutBucketAcl": ("Possible S3 public access risk", 2),
    "PutBucketPolicy": ("Possible S3 public access risk", 2),

    # EC2 lifecycle
    "TerminateInstances": ("EC2 instance termination attempt", 4),
    "StopInstances": ("EC2 instance stopped", 2),
    "StartInstances": ("EC2 instance started", 1),

    # Security Group modifications
    "AuthorizeSecurityGroupIngress": ("Ingress rule added — potential exposure", 3),
    "RevokeSecurityGroupIngress": ("Ingress rule removed", 2),
}

def load_last_run():
    # 1️⃣ Check alert logs first
    if os.path.exists("alerts.log"):
        with open("alerts.log", "r") as f:
            lines = f.readlines()
            for line in reversed(lines):
                try:
                    ts = line.split(" - ")[0]  # timestamp prefix
                    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    continue

    # 2️⃣ Fallback to last_run file
    if os.path.exists(LAST_RUN_FILE):
        with open(LAST_RUN_FILE, "r") as f:
            try:
                return datetime.fromisoformat(f.read().strip())
            except Exception:
                pass

    # 3️⃣ First execution fallback
    return datetime.now(UTC) - timedelta(hours=3)

def save_last_run(events):
    if events:
        latest_ts = max(e["EventTime"] for e in events)
        with open(LAST_RUN_FILE, "w") as f:
            f.write(latest_ts.isoformat())

def get_cloudtrail_events():
    cloudtrail = boto3.client("cloudtrail")

    last_run = load_last_run()

    # Ensure timezone-aware UTC timestamp
    if last_run.tzinfo is None:
        last_run = last_run.replace(tzinfo=UTC)

    now = datetime.now(UTC)

    # Fix future timestamps caused by CloudTrail clock skew
    if last_run >= now:
        last_run = now - timedelta(minutes=5)

    response = cloudtrail.lookup_events(
        StartTime=last_run,
        EndTime=now,
        MaxResults=50
    )

    events = response.get("Events", [])
    save_last_run(events)  # Use latest event timestamps

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
        while True:
            events = get_cloudtrail_events()
            detect_threats(events)
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nStopped monitoring.")
        logging.warning("Monitoring loop stopped by user.")


if __name__ == "__main__":
    run_monitor_loop(interval=60)
