#!/bin/bash

if command -v redis-server >/dev/null 2>&1 && command -v redis-cli >/dev/null 2>&1 && ! redis-cli ping >/dev/null 2>&1; then
    echo "Starting redis-server"
    redis-server --daemonize yes
fi

echo "Starting cowrie_log_parser.py"
nohup python3 -u cowrie_log_parser.py > script_logs/cowrie_log_parser.out 2>&1 &

echo "Starting downloaded_files_check.py"
nohup python3 -u downloaded_files_check.py > script_logs/downloaded_files_check.out 2>&1 &

echo "Starting extract_configuration.py"
nohup python3 -u extract_configuration.py > script_logs/extract_configuration.out 2>&1 &

echo "Starting honeypot_automation.py"
nohup python3 -u honeypot_automation.py > script_logs/honeypot_automation.out 2>&1 &

echo "Starting suricata_log_parser.py"
nohup python3 -u suricata_log_parser.py > script_logs/suricata_log_parser.out 2>&1 &
