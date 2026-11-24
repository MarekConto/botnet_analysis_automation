import re
import base64
import hashlib
from pygtail import Pygtail
from queue import Queue
import json
import time
import urllib.parse
from redis_bus import get_redis_client, publish_download_request

LOG_FILE = "log.json"
log_queue = Queue()
redis_client = get_redis_client()

# regex pattern to identify download commands in HTTP requests
DOWNLOAD_CMD_PATTERN = re.compile(r'(?:wget|curl)\s+(?:-q\s+)?(?:-O(?:\s+\S+|-)\s+)?(?:-s\s+)?((?:https?:/{1,2}|http:/{1,2})?[\w./-]+(?::\d+)?(?:/[\w./-]*)?)', re.IGNORECASE)

# regex pattern to identify potential Base64 encoded strings
BASE64_PATTERN = re.compile(r'(?<=Base64/)([A-Za-z0-9+/]{4,}={0,2})')

# regex pattern to identify potential Base64 encoded strings without explicit "Base64/" prefix
GENERAL_BASE64_PATTERN = re.compile(r'\b[A-Za-z0-9+/]{4,}={0,2}\b')

# specific regex pattern before parse - identify Base64 encoded strings using `%` instead of `/`
BASE64_PERCENT_PATTERN = re.compile(r'\b[A-Za-z0-9+%]{4,}={0,2}\b')

def is_base64(s):
    try:
        decoded = base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def log_download_url(flow_id, url, src_ip, timestamp):
    log_entry = {
        "flow_id": flow_id,
        "url": url,
        "src_ip": src_ip,
        "timestamp": timestamp,
        "source": "suricata"
    }
    publish_download_request(redis_client, log_entry)

def extract_download_urls(log_entry):
    urls = set()
    if "http" in log_entry:
        # baseline combined value
        relevant_fields = ["http_method", "url", "protocol"]
        combined_value = " ".join(str(log_entry["http"].get(field, "")) for field in relevant_fields)
        combined_value += " ".join(str(value) for key, value in log_entry["http"].items() if key not in relevant_fields)
        
        print(f"combined_value is {combined_value}\n")
        
        # replace '+' with ' ' before decoding
        combined_value = combined_value.replace('+', ' ')
        
        # step 1: find Base64 encoded 'looking' strings using the new regex pattern with %
        base64_percent_matches = BASE64_PERCENT_PATTERN.findall(combined_value)
        for match in base64_percent_matches:
            corrected_match = urllib.parse.unquote(match)
            if is_base64(corrected_match):
                try:
                    decoded_word = base64.b64decode(corrected_match).decode('utf-8')
                    combined_value = combined_value.replace(match, decoded_word)
                except Exception as e:
                    continue
        
        decoded_value = urllib.parse.unquote(combined_value)
        
        # apply the regex pattern to find download URLs
        matches = DOWNLOAD_CMD_PATTERN.findall(decoded_value)
        urls.update(matches)
        
        # reset combined_value to baseline
        combined_value = " ".join(str(log_entry["http"].get(field, "")) for field in relevant_fields)
        combined_value += " ".join(str(value) for key, value in log_entry["http"].items() if key not in relevant_fields)
        combined_value = combined_value.replace('+', ' ')
        
        # step 2: decode the URL with urllib.parse.unquote
        decoded_value = urllib.parse.unquote(combined_value)
        print(f"decoded_value after URL decoding is {decoded_value}\n")
        
        # apply the regex pattern to find download URLs
        matches = DOWNLOAD_CMD_PATTERN.findall(decoded_value)
        urls.update(matches)
        
        # step 3: find Base64 encoded 'looking' strings using specific "Base64/" prefix regex pattern
        base64_matches = BASE64_PATTERN.findall(combined_value)
        for match in base64_matches:
            print(f"Base64/ match is {match}")
            if is_base64(match):
                try:
                    decoded_word = base64.b64decode(match).decode('utf-8')
                    print(f"decoded_word is {decoded_word}")
                    combined_value = combined_value.replace(match, decoded_word)
                except Exception as e:
                    continue
        
        # step 4: find Base64 encoded 'looking' strings using the general regex pattern
        general_base64_matches = GENERAL_BASE64_PATTERN.findall(combined_value)
        for match in general_base64_matches:
            if is_base64(match):
                try:
                    decoded_word = base64.b64decode(match).decode('utf-8')
                    print(f"decoded_word is {decoded_word}")
                    combined_value = combined_value.replace(match, decoded_word)
                except Exception as e:
                    continue
        
        decoded_value = urllib.parse.unquote(combined_value)
        # apply the download regex pattern again to the new combined value that may have revealed obfuscated data
        matches = DOWNLOAD_CMD_PATTERN.findall(decoded_value)
        urls.update(matches)
        
        # log the download URLs
        flow_id = log_entry.get("flow_id")
        src_ip = log_entry.get("src_ip")
        timestamp = log_entry.get("timestamp")
        for url in urls:
            log_download_url(flow_id, url, src_ip, timestamp)

    return urls

def follow_logs():
    while True:
        try:
            for line in Pygtail(LOG_FILE):
                try:
                    log_entry = json.loads(line.strip())
                    log_queue.put(log_entry)
                    print("\nNew log entry added to queue:", log_entry, "\n\n")

                    download_urls = extract_download_urls(log_entry)
                    if download_urls:
                        print("\nDetected download URLs:", download_urls, "in log flow id: ", log_entry.get("flow_id"))
                        print("----------------------------------------------------------------------------------") 
                except json.JSONDecodeError:
                    print("Invalid JSON line:", line)
        except Exception as e:
            print("Error reading log file:", e)
        time.sleep(1)

if __name__ == "__main__":
    follow_logs()
