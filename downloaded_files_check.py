import os
import subprocess
import json
import re
import time
from redis_bus import (
    DOWNLOADED_FILES_GROUP,
    DOWNLOADED_FILES_STREAM,
    EXTRACTOR_REQUESTS_STREAM,
    ack_event,
    get_redis_client,
    publish_download_request,
    publish_event,
    read_events,
)

DOWNLOADS_DIR = os.path.join(os.getcwd(), "cowrie/downloads")
redis_client = get_redis_client()
redis_consumer = "downloaded_files_check"

# regex pattern to identify download commands
DOWNLOAD_CMD_PATTERN = re.compile(r"(?:wget|curl)\s+(?:-q\s+)?(?:-O(?:\s+\S+|-)\s+)?(?:-s\s+)?((?:https?://|http?://)?[\w./-]+(?::\d+)?(?:/[\w./-]*)?)", re.IGNORECASE)

# regex pattern to identify download commands (-O without a filename)
DOWNLOAD_CMD_PATTERN_EMPTY_O = re.compile(r"(?:wget|curl)\s+(?:-q\s+)?(?:-O\s+)?(?:-s\s+)?((?:https?://|http?://)?[\w./-]+(?::\d+)?(?:/[\w./-]*)?)", re.IGNORECASE)

def is_binary(file_path):
    try:
        result = subprocess.run(
            ["file", "--mime", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        mime_output = result.stdout.lower()

        binary_mime_types = [
            "application/octet-stream",
            "application/x-executable",
            "application/x-sharedlib",
            "application/x-dosexec",  
            "application/x-object",  
            "application/x-archive", 
        ]

        return any(binary_type in mime_output for binary_type in binary_mime_types)

    except Exception as e:
        print(f"Error checking file type: {e}")
        return False

def parse_text_file(file_path):
    commands = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                matches = DOWNLOAD_CMD_PATTERN.findall(line)
                commands.extend(matches)
    except Exception as e:
        print(f"Error reading text file {file_path}: {e}")
    return commands

def log_output_file(log_entry):
    sha256 = log_entry["sha256"]
    flow_id = log_entry["flow_id"]
    url = log_entry["url"]
    timestamp = log_entry["timestamp"]
    src_ip = log_entry.get("src_ip")
    source_script = log_entry.get("source_script")
    log_entry = {
        "timestamp": timestamp,
        "flow_id": flow_id,
        "sha256": sha256,
        "url": url
    }
    if src_ip:
        log_entry["src_ip"] = src_ip
    if source_script:
        log_entry["source_script"] = source_script
    
    try:
        publish_event(redis_client, EXTRACTOR_REQUESTS_STREAM, log_entry)
    except Exception as e:
        print(f"Error publishing extractor request: {e}")

def process_downloaded_file(log_entry):
    file_sha256 = log_entry["sha256"]
    flow_id = log_entry["flow_id"]
    src_ip = log_entry.get("src_ip")
    timestamp = log_entry["timestamp"]
    file_path = os.path.join(DOWNLOADS_DIR, file_sha256)

    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist, skipping.")
        return

    if is_binary(file_path):
        print(f"Binary file detected: {file_path}")
        log_output_file(log_entry)
    else:
        print(f"Text file detected: {file_path}")
        commands = parse_text_file(file_path)
        
        if commands:
            commands = list(set(commands))
            print(f"Extracted commands: {commands}")
            try:
                for command in commands:
                    script_log_entry = {
                        "flow_id": flow_id,
                        "source_script": file_sha256,  # sha256 for the text file with this download command
                        "url": command,
                        "timestamp": timestamp,
                        "source": "script"
                    }
                    if src_ip:
                        script_log_entry["src_ip"] = src_ip
                    
                    publish_download_request(redis_client, script_log_entry)
                print("Commands published to Redis download_requests stream")
            except Exception as e:
                print(f"Error publishing commands to Redis: {e}")

def process_downloaded_files():
    for message_id, log_entry in read_events(redis_client, DOWNLOADED_FILES_STREAM, DOWNLOADED_FILES_GROUP, redis_consumer):
        try:
            process_downloaded_file(log_entry)
            ack_event(redis_client, DOWNLOADED_FILES_STREAM, DOWNLOADED_FILES_GROUP, message_id)

        except Exception as e:
            print(f"Error processing downloaded file: {e}")

if __name__ == "__main__":
    while True:
        process_downloaded_files()
        time.sleep(5)
