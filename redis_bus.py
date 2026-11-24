import hashlib
import json
import os
import time
from datetime import datetime

import redis


DOWNLOAD_REQUESTS_STREAM = "download_requests"
DOWNLOADED_FILES_STREAM = "downloaded_files"
EXTRACTOR_REQUESTS_STREAM = "extractor_requests"

HONEYPOT_GROUP = "honeypot_automation"
DOWNLOADED_FILES_GROUP = "downloaded_files_check"
EXTRACTOR_GROUP = "extract_configuration"

INDEX_PREFIX = "download_request_index"
INDEX_TTL_SECONDS = int(os.getenv("REDIS_DOWNLOAD_INDEX_TTL", "86400"))
INDEX_LOOKUP_WINDOW_SECONDS = int(os.getenv("REDIS_DOWNLOAD_INDEX_WINDOW", "3600"))


def get_redis_client():
    return redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        db=int(os.getenv("REDIS_DB", "0")),
        decode_responses=True,
    )


def ensure_group(client, stream, group):
    try:
        client.xgroup_create(stream, group, id="0", mkstream=True)
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def publish_event(client, stream, event):
    return client.xadd(stream, {"data": json.dumps(event)}, maxlen=10000, approximate=True)


def read_events(client, stream, group, consumer, count=10, block_ms=5000):
    ensure_group(client, stream, group)
    response = client.xreadgroup(group, consumer, {stream: "0"}, count=count)
    if not response or not response[0][1]:
        response = client.xreadgroup(group, consumer, {stream: ">"}, count=count, block=block_ms)
    events = []
    for _, messages in response:
        for message_id, fields in messages:
            try:
                events.append((message_id, json.loads(fields["data"])))
            except (KeyError, json.JSONDecodeError) as e:
                print(f"Invalid Redis message {message_id} from {stream}: {e}")
                client.xack(stream, group, message_id)
    return events


def ack_event(client, stream, group, message_id):
    client.xack(stream, group, message_id)


def publish_download_request(client, event):
    message_id = publish_event(client, DOWNLOAD_REQUESTS_STREAM, event)
    index_download_request(client, event)
    return message_id


def index_download_request(client, event):
    url = event.get("url")
    if not url:
        return

    score = timestamp_to_epoch(event.get("timestamp")) or time.time()
    indexed_event = dict(event)
    indexed_event["_indexed_at"] = time.time()
    key = download_request_index_key(url)
    client.zadd(key, {json.dumps(indexed_event): score})
    client.expire(key, INDEX_TTL_SECONDS)


def find_download_request(client, url, timestamp):
    score = timestamp_to_epoch(timestamp)
    if score is None:
        return None

    key = download_request_index_key(url)
    candidates = client.zrangebyscore(
        key,
        score - INDEX_LOOKUP_WINDOW_SECONDS,
        score + INDEX_LOOKUP_WINDOW_SECONDS,
        withscores=True,
    )
    closest_event = None
    closest_diff = float("inf")

    for raw_event, candidate_score in candidates:
        try:
            event = json.loads(raw_event)
        except json.JSONDecodeError:
            continue

        diff = abs(score - candidate_score)
        if diff < closest_diff:
            closest_diff = diff
            closest_event = event

    return closest_event


def download_request_index_key(url):
    normalized_url = url.strip().lower()
    url_hash = hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()
    return f"{INDEX_PREFIX}:{url_hash}"


def timestamp_to_epoch(timestamp):
    if not timestamp:
        return None

    try:
        normalized = timestamp.replace("Z", "+00:00")
        if normalized.endswith("+0000"):
            normalized = normalized[:-5] + "+00:00"
        return datetime.fromisoformat(normalized).timestamp()
    except ValueError:
        return None
