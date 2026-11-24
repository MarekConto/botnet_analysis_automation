import subprocess
import time
import random
import os
from datetime import datetime, timedelta
from redis_bus import (
    DOWNLOAD_REQUESTS_STREAM,
    HONEYPOT_GROUP,
    ack_event,
    get_redis_client,
    read_events,
)

container_name = None # global var to store the name of the Cowrie container
source_download_limiter = {}  # global var for tracking download count from a flow id, used as a limiter
redis_client = get_redis_client()
redis_consumer = "honeypot_automation"

# generates a random available port number
def generate_random_port():
    while True:
        port = random.randint(20000, 65000)
        if is_port_available(port):
            return port


# checks if a port is available
def is_port_available(port):
    
    # run the ss command to list all listening ports and check if the port is not in the list
    result = subprocess.run(
        ["ss", "-tuln"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return f":{port} " not in result.stdout.decode()



# starts Cowrie on the specified port
def start_cowrie_container(port):
    global container_name
    current_dir = os.getcwd()

    container_name = f"cowrie_{port}"
    
    # runs cowrie in detached mode, bind mounts the cowrie configuration, log and download directories
    command = [
        "podman", "run","--rm", "-d", 
        "--cap-drop=all",                   # removes all capabilities because even if podman does not have full root privileges, it can still change NET_ADMIN, SYS_ADMIN ..
        "--security-opt=no-new-privileges", # prevents the container from gaining new privileges
        "--name", container_name,
        "-p", f"127.0.0.1:{port}:2222",
        "--mount", f"type=bind,source={current_dir}/cowrie/etc,target=/cowrie/cowrie-git/etc,Z",
        "--mount", f"type=bind,source={current_dir}/cowrie/log,target=/cowrie/cowrie-git/var/log/cowrie,Z",
        "--mount", f"type=bind,source={current_dir}/cowrie/downloads,target=/cowrie/cowrie-git/var/lib/cowrie/downloads,Z",
        "cowrie/cowrie"
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Container error: {result.stderr}")

    return container_name


# connects to the Cowrie honeypot and executes the specified commands
def connect_to_honeypot(port, password, commands):
    print(f"Connecting to honeypot on port {port}...")

    ssh_command = [
        "sshpass", "-p", password,
        "ssh","-tt", "-o", "StrictHostKeyChecking=accept-new",
        "-p", str(port), "root@localhost"
    ]
    
    try:
        process = subprocess.Popen(
            ssh_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        time.sleep(2)
         
        for command in commands:
            print(f"Executing command: {command}")
            process.stdin.write(command + "\n")
            process.stdin.flush() # flushes the input buffer, so that the command isn't buffered and sent all at once
            time.sleep(4)
            
        stdout, stderr = process.communicate()
        process.stdin.close()
        

        if process.returncode != 0:
            print(f"Error during SSH connection: {stderr}")
        else:
            print("Commands executed successfully.")
            print(stdout)

    except Exception as e:
        print(f"Error connecting to honeypot: {e}")


# stops the Cowrie container
def stop_cowrie_container(container_name):
    print(f"Stopping Cowrie container {container_name}...")

    result = subprocess.run(["podman", "stop", container_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if result.returncode == 0:
        print(f"Container {container_name} stopped.")
    else:
        print(f"Failed to stop container: {result.stderr.decode()}")

# increments the download count for a flow id and checks the limit
def update_source_download_limiter(flow_id):
    global source_download_limiter
    current_time = datetime.now()

    if flow_id not in source_download_limiter:
        source_download_limiter[flow_id] = {"count": 0, "ttl": current_time + timedelta(minutes=20)}

    source_download_limiter[flow_id]["count"] += 1
    source_download_limiter[flow_id]["ttl"] = current_time + timedelta(minutes=20)

    return source_download_limiter[flow_id]["count"] <= 16

# removes expired flow ids 
def clean_expired_sources():
    global source_download_limiter
    current_time = datetime.now()
    expired_flow_ids = [flow_id for flow_id, data in source_download_limiter.items() if data["ttl"] < current_time]

    for flow_id in expired_flow_ids:
        del source_download_limiter[flow_id]

# reads commands from Redis and returns a list of wget commands
def read_commands_from_redis():
    global source_download_limiter
    commands = []
    message_ids = []

    clean_expired_sources()

    for message_id, log_entry in read_events(redis_client, DOWNLOAD_REQUESTS_STREAM, HONEYPOT_GROUP, redis_consumer):
        flow_id = log_entry.get("flow_id")
        url = log_entry.get("url")

        if flow_id and not update_source_download_limiter(flow_id):
            print(f"Skipping command for flow_id {flow_id} (limit reached or expired).")
            ack_event(redis_client, DOWNLOAD_REQUESTS_STREAM, HONEYPOT_GROUP, message_id)
            continue

        if not url:
            ack_event(redis_client, DOWNLOAD_REQUESTS_STREAM, HONEYPOT_GROUP, message_id)
            continue

        commands.append(f"wget {url}")
        message_ids.append(message_id)

    return commands, message_ids


def main():
    global container_name
    
    while True:
        try:
            commands, message_ids = read_commands_from_redis()
            if commands:
                print(f"Commands to execute: {commands}")
                
                port = generate_random_port()
                container_name = start_cowrie_container(port)
                
                time.sleep(15)  
                password = "ngreasenbi"

                connect_to_honeypot(port, password, commands)
                for message_id in message_ids:
                    ack_event(redis_client, DOWNLOAD_REQUESTS_STREAM, HONEYPOT_GROUP, message_id)
                
                time.sleep(30)

        except Exception as e:
            print(f"Error: {e}")
        
        finally:
            if container_name:
                stop_cowrie_container(container_name)
                container_name = None


if __name__ == "__main__":
    main()
