import re
import json
import time
from pygtail import Pygtail
from queue import Queue
import os
from datetime import datetime
import pytz 
from redis_bus import DOWNLOADED_FILES_STREAM, find_download_request, get_redis_client, publish_event

LOG_FILE = os.path.join(os.getcwd(), "cowrie/log/cowrie.json")
log_queue = Queue()
redis_client = get_redis_client()

def parse_timestamp(timestamp):
    try:
        # Formát s "Z" na konci (napr. cowrie.json)
        if (timestamp.endswith("Z")):
            return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=pytz.UTC)
        # Formát s "+0000" na konci (napr. download_url.log)
        elif ("+" in timestamp):
            return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
        else:
            raise ValueError(f"Unknown timestamp format: {timestamp}")
    except Exception as e:
        print(f"Error parsing timestamp: {e}")
        return None

def get_flow_id_and_src_ip_from_log(url, current_timestamp):
    try:
        closest_entry = find_download_request(redis_client, url, current_timestamp)

        if closest_entry:
            return {
                "flow_id": closest_entry.get("flow_id"),
                "src_ip": closest_entry.get("src_ip"),
                "source_script": closest_entry.get("source_script")
            }
        else:
            print(f"No matching entry found for URL: {url}")
            return None
    except Exception as e:
        print(f"Error retrieving flow_id and src_ip: {e}")
        return None

def process_log_entry(log_entry):
    if "eventid" in log_entry and log_entry["eventid"] == "cowrie.session.file_download":
        url = log_entry["url"]
        current_timestamp = log_entry["timestamp"]
        flow_data = get_flow_id_and_src_ip_from_log(url, current_timestamp)

        flow_id = None
        src_ip = None
        source_script = None

        if flow_data:
            flow_id = flow_data.get("flow_id")
            src_ip = flow_data.get("src_ip")
            source_script = flow_data.get("source_script")

        log_write_entry = {
            "timestamp": log_entry["timestamp"],
            "url": url,
            "sha256": log_entry["shasum"],
            "flow_id": flow_id,
            "src_ip": src_ip,
        }
        if source_script:
            log_write_entry["source_script"] = source_script

        publish_event(redis_client, DOWNLOADED_FILES_STREAM, log_write_entry)

def follow_logs():
    if not os.path.exists(LOG_FILE):
        print(f"Log file '{LOG_FILE}' does not exist. Please check the file path.")
        return

    while True:
        try:
            for line in Pygtail(LOG_FILE):
                try:
                    log_entry = json.loads(line.strip())
                    log_queue.put(log_entry)
                    process_log_entry(log_entry)
                except json.JSONDecodeError:
                    print("Invalid JSON line:", line)
        except Exception as e:
            print(f"Error reading log file: {e}")
        time.sleep(1)

if __name__ == "__main__":
    follow_logs()

