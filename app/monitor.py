from tracemalloc import start
import boto3
from datetime import datetime, timedelta, UTC

from urllib3 import response

def get_cloudtrail_events(hours=1):
    cloudtrail = boto3.client("cloudtrail")

    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(hours=hours)

    print(f"Checking CloudTrail events from last {hours} hour(s)...")

    response = cloudtrail.lookup_events(
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=50
    )

    events = response.get("Events", [])
    
    if not events:
        print("No events found.")
        return []

    for event in events:
        print("-------------------------")
        print(f"Event: {event['EventName']}")
        print(f"Source: {event['EventSource']}")
        print(f"Time: {event['EventTime']}")
        print(f"User: {event.get('Username', 'Unknown')}")

    print(f"Total events found: {len(events)}")
    return events

if __name__ == "__main__":
    get_cloudtrail_events(hours=3)
    
