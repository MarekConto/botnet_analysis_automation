import os
import json
import subprocess
import shutil
import time
import magic
from redis_bus import (
    EXTRACTOR_GROUP,
    EXTRACTOR_REQUESTS_STREAM,
    ack_event,
    get_redis_client,
    read_events,
)

DOWNLOADS_DIR = os.path.join(os.getcwd(), "cowrie/downloads")
TMP_SAMPLES_DIR = "/tmp/samples"
redis_client = get_redis_client()
redis_consumer = "extract_configuration"

EXTRACTORS = [
    {
        "image": "docker.io/marekconto/mozibgone",
        "commands": [
            "-e /app/samples/{sample_name}",
            "-a /app/samples/{sample_name}"
        ]
    },
    {
        "image": "docker.io/marekconto/mozitools",
        "commands": [
            "unp -i samples/{sample_name} -o /dev/stdout > /tmp/samples/unpacked_data.bin",
            "dec -i samples/unpacked_data.bin"
        ]
    },
    {
        "image": "docker.io/marekconto/miraicfg",
        "commands": [
            "/app/samples/{sample_name}"
]
    }
]


def prepare_sample(sha256):
    try:
        sample_path = os.path.join(DOWNLOADS_DIR, sha256)
        if not os.path.exists(sample_path):
            print(f"Sample with SHA256 {sha256} not found in {DOWNLOADS_DIR}")
            return None, None

        os.makedirs(TMP_SAMPLES_DIR, exist_ok=True)

        tmp_sample_path = os.path.join(TMP_SAMPLES_DIR, sha256)
        shutil.copy(sample_path, tmp_sample_path)

        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(tmp_sample_path)

        return tmp_sample_path, mime_type
    except Exception as e:
        print(f"Error preparing sample {sha256}: {e}")
        return None, None

def run_extractor(image, command):
    try:
        full_command = f"podman run --rm -v {TMP_SAMPLES_DIR}:/app/samples {image} {command}"
        print(f"Running command: {full_command}")
        
        result = subprocess.run(
            full_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        print(f"Error running extractor {image} with command '{command}': {e}")
        return {"returncode": -1, "stdout": "", "stderr": ""}

def parse_extractor_output(stdout, stderr):

    extracted_data = {}
    try:
        # parsing logic for mozibgone
        if "[*] Extracted config fields" in stdout:
            extracted_data["family"] = "Mozi"
            for line in stdout.splitlines():
                if " : " in line:
                    key, value = line.split(" : ", 1)
                    extracted_data[key.strip()] = value.strip()
        # parsing logic for mozitools
        elif "Parsed Mozi configuration:" in stderr:
            extracted_data["family"] = "Mozi"
            for line in stderr.splitlines():
                if "[" in line and "->" in line:
                    parts = line.split("[", 1)[1].split("->")
                    key = parts[0].split("]")[0].strip()
                    value = parts[1].strip()
                    extracted_data[key] = value
        # parsing logic for miraicfg
        elif "Success ratio: 100.00%" in stdout:
            extracted_data["family"] = "Mirai"
            try:
                json_start = stdout.find("{")
                json_end = stdout.rfind("}") + 1
                if json_start != -1 and json_end != -1:
                    json_data = json.loads(stdout[json_start:json_end])

                    for key, value in json_data.items():
                        if isinstance(value, dict):
                            extracted_data.update(value)
                else:
                    extracted_data[key] = value
            except json.JSONDecodeError:
                pass
    except Exception as e:
        print(f"Error parsing extractor output: {e}")
    return extracted_data

def process_extractor_request(log_entry):
    try:
        sha256 = log_entry.get("sha256")
        flow_id = log_entry.get("flow_id")
        source_url = log_entry.get("url")
        timestamp = log_entry.get("timestamp")
        source_script = log_entry.get("source_script")
        src_ip = log_entry.get("src_ip")
        if not sha256:
            print(f"Invalid log entry: {log_entry}")
            return

        extracted_results = {
            "flow_id": flow_id,
            "timestamp": timestamp,
            "sha256": sha256,
            "source_url": source_url,
            "src_ip": src_ip,
        }
        if source_script:
            extracted_results["source_script"] = source_script

        human_output = ""

        for extractor in EXTRACTORS:
            print(f"Processing extractor: {extractor['image']}")
            tmp_sample_path, mime_type = prepare_sample(sha256)
            extracted_results["mime_type"] = mime_type
            
            if not tmp_sample_path:
                print(f"Failed to prepare sample: {sha256}")
                return

            for command_template in extractor["commands"]:
                command = command_template.format(sample_name=sha256)
                print(f"Running command: {command} for extractor: {extractor['image']}")
                result = run_extractor(extractor["image"], command)
                stdout, stderr = result.get("stdout", ""), result.get("stderr", "")
                if result.get("returncode") == 0:
                    parsed_data = parse_extractor_output(stdout, stderr)
                    if parsed_data:
                        extracted_results.update(parsed_data)
                else:
                    print(f"Extractor {extractor['image']} failed with return code {result.get('returncode')}")

        # human-readable output for mozi 
        if "family" in extracted_results:
            human_output += f"The malware type is likely {extracted_results['family']}.\n"
        if "mime_type" in extracted_results:
            human_output += f"File type is: {extracted_results['mime_type']}.\n"
        if "dip" in extracted_results:
            human_output += f"Makes downloads from {extracted_results['dip']}.\n"
        if "idp" in extracted_results:
            report_status = "reports" if extracted_results["idp"].lower() == "true" else "does not report"
            human_output += f"The bot {report_status} to the CnC server.\n"
        if "ss" in extracted_results:
            human_output += f"The bot type is: {extracted_results['ss']}.\n"
        if "hp" in extracted_results:
            human_output += f"The bot uses a DHT (Distributed Hash Table) node ID prefix of {extracted_results['hp']}.\n"
        if "count" in extracted_results:
            human_output += f"The bot reports its presence or status to this URL: {extracted_results['count']}.\n"
        if "dr" in extracted_results:
            human_output += f"It downloads and executes an additional payload from: {extracted_results['dr']}.\n"
        if "atk" in extracted_results:
            human_output += f"The bot is configured to perform DDoS attacks using this method: {extracted_results['atk']}.\n"
        if "ver" in extracted_results:
            human_output += f"The bot sets its DHT protocol version identifier to: {extracted_results['ver']}.\n"
        if "sv" in extracted_results:
            human_output += f"It receives an updated configuration from: {extracted_results['sv']}.\n"
        if "ud" in extracted_results:
            human_output += f"A new version of the bot can be downloaded from: {extracted_results['ud']}.\n"
        if "rn" in extracted_results:
            human_output += f"It is instructed to execute the following shell command: \"{extracted_results['rn']}\".\n"

        # human-readable output for miraicfg-specific keys
        if "cnc" in extracted_results:
            human_output += f"The bot communicates with the CnC server at: {extracted_results['cnc']}.\n"
        if "key" in extracted_results:
            human_output += f"The encryption key used by the bot is: {extracted_results['key']}.\n"
        if "botnet" in extracted_results:
            human_output += f"Botnet name is: {extracted_results['botnet']}.\n"
        if "strings_table" in extracted_results:
            human_output += "The bot contains the following strings in its configuration:\n"
            for string in extracted_results["strings_table"]:
                if isinstance(string, str) and string.endswith("\u0000"):
                    human_output += f"  - {string}\n"

        if human_output.strip():
            human_output = f"Extracted information about file with sha256:{sha256} downloaded from {source_url} at {timestamp}\n" + human_output
        else:
            human_output = f"Extracted information about file with sha256:{sha256} downloaded from {source_url} at {timestamp}:\nNo meaningful information could be extracted from the binary."

        extracted_results["human_output"] = human_output.strip()

        if len(extracted_results) > 2:
            print(f"Extracted results for {sha256}: {extracted_results}")
        else:
            print(f"No relevant data extracted for {sha256}")

        with open("extracted_results.json", "a") as f:
            json.dump({sha256: extracted_results}, f)
            f.write("\n")

    except Exception as e:
        print(f"Error processing log entry: {e}")

def follow_extractor_requests():
    while True:
        try:
            for message_id, log_entry in read_events(redis_client, EXTRACTOR_REQUESTS_STREAM, EXTRACTOR_GROUP, redis_consumer):
                process_extractor_request(log_entry)
                ack_event(redis_client, EXTRACTOR_REQUESTS_STREAM, EXTRACTOR_GROUP, message_id)
        except Exception as e:
            print(f"Error reading extractor requests: {e}")
        time.sleep(1)

if __name__ == "__main__":
    follow_extractor_requests()
