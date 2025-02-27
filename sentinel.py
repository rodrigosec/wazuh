#!/var/ossec/framework/python/bin/python3
# Created by Rodrigo Pereira.

import os
import sys
import json
import logging
import requests
from pathlib import PureWindowsPath, PurePosixPath

# Wazuh Active Response log file path
LOG_FILE = "/var/ossec/logs/active-responses.log"

# SentinelOne API configurations
S1_CONSOLE_URL = "YOUR_S1_CONSOLE_URL"
S1_API_KEY = "YOUR_S1_API_KEY"
S1_ACCOUNT_ID = "YOUR_S1_ACCOUNT_ID"
S1_FIREWALL_RULE_NAMES = ["Blacklist", "Blacklist2", "Blacklist3", "Blacklist4"]

HEADERS = {
    "Authorization": f"ApiToken {S1_API_KEY}",
    "User-Agent": "Wazuh/SentinelOne-Integration",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# Expected commands from Wazuh
ADD_COMMAND = 0
DELETE_COMMAND = 1
OS_SUCCESS = 0
OS_INVALID = -1

def write_log(message):
    """Writes to the Wazuh Active Response log."""
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(f"{message}\n")

def get_ip_from_alert(alert):
    """Extracts the IP address from the received Wazuh alert."""
    try:
        ip = alert.get("parameters", {}).get("alert", {}).get("data", {}).get("srcip")
        if ip:
            write_log(f"Extracted IP: {ip}")
        else:
            write_log("No IP found in alert.")
        return ip
    except Exception as e:
        write_log(f"Error extracting IP: {str(e)}")
        return None

def block_ip(ip_to_block):
    """Blocks the IP in SentinelOne."""
    write_log(f"Attempting to block IP: {ip_to_block}")
    for rule_name in S1_FIREWALL_RULE_NAMES:
        url = f"{S1_CONSOLE_URL}/web/api/v2.1/firewall-control?siteIds={S1_ACCOUNT_ID}&name={rule_name}"
        response = requests.get(url, headers=HEADERS)

        if response.status_code == 200:
            firewall_rules = response.json()
            
            for item in firewall_rules.get("data", []):
                current_hosts = [host.get("values", []) for host in item.get("remoteHosts", [])]
                current_hosts = [ip for sublist in current_hosts for ip in sublist]

                if ip_to_block in current_hosts:
                    write_log(f"IP {ip_to_block} is already blocked in {rule_name}.")
                    return
                
                if len(current_hosts) >= 50:
                    continue

                item["remoteHosts"].append({"type": "addresses", "values": [ip_to_block]})
                put_response = requests.put(
                    f"{S1_CONSOLE_URL}/web/api/v2.1/firewall-control/{item['id']}", 
                    headers=HEADERS, 
                    json={"data": {"remoteHosts": item["remoteHosts"]}}
                )

                if put_response.status_code == 200:
                    write_log(f"IP {ip_to_block} blocked in {rule_name}.")
                    return
                else:
                    write_log(f"Error updating rule {rule_name}. Status: {put_response.status_code}")
                    return

    write_log("All firewall rules are full. Unable to add IP.")

def process_alert():
    """Processes the alert received by Active Response."""
    write_log("SentinelOne Active Response started.")

    # Read the alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_log(f"Received alert: {input_str}")

    try:
        data = json.loads(input_str)
    except ValueError:
        write_log("Error decoding alert JSON.")
        sys.exit(OS_INVALID)

    # Check the alert command (add/delete)
    command = data.get("command")
    if command == "add":
        cmd = ADD_COMMAND
    elif command == "delete":
        cmd = DELETE_COMMAND
    else:
        write_log(f"Invalid command: {command}")
        sys.exit(OS_INVALID)

    # Extract IP from the alert
    ip = get_ip_from_alert(data)
    if not ip:
        sys.exit(OS_INVALID)

    if cmd == ADD_COMMAND:
        block_ip(ip)
    elif cmd == DELETE_COMMAND:
        write_log(f"IP removal {ip} requested, but not yet implemented.")

    write_log("SentinelOne Active Response finished.")
    sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    process_alert()
