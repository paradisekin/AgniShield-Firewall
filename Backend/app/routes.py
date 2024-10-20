import csv
import os
from flask import Blueprint, jsonify, request
from flask_cors import CORS  # Import CORS
from urllib.parse import urlparse
from Aiwal import main as ai_main  # Import the main function from your AI model
import pandas
from datetime import datetime

main = Blueprint('main', __name__)
CORS(main)  # Enable CORS for the blueprint

# Path to store device data and blocked domains
DEVICES_FILE_PATH = 'devices.csv'
BLOCKED_DOMAINS_FILE_PATH = 'blocked_domains.csv'
BLOCKED_IPS_FILE_PATH = 'blocked_ips.csv'
DOMAINS_CSV_PATH = 'domains.csv'
IPS_CSV_PATH = 'ips.csv'
DOMAIN_LOGS_PATH = 'domain_logs.csv' 

devices = {
    1: {
        "id": 1,
        "name": "Device 1",
        "ip": "192.168.1.2",
        "status": "Active",
        "domains": ["example.com", "test.com"],
        "ips": ["192.168.1.10", "192.168.1.11"],
        "report": "No issues detected.",
        "healthStatus": "Good",
        "logs": ["User visited example.com", "User visited test.com"],
        "userActivity": ["User connected recently"]
    },
    2: {
        "id": 2,
        "name": "Device 2",
        "ip": "192.168.1.3",
        "status": "Inactive",
        "domains": ["malware.com"],
        "ips": ["192.168.1.12"],
        "report": "Malicious activity detected.",
        "healthStatus": "Critical",
        "logs": ["User visited malware.com"],
        "userActivity": ["User disconnected recently"]
    }
}

# Ensure CSV files exist
if not os.path.exists(DOMAINS_CSV_PATH):
    with open(DOMAINS_CSV_PATH, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['device_id', 'domain'])

if not os.path.exists(IPS_CSV_PATH):
    with open(IPS_CSV_PATH, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['device_id', 'ip'])

@main.route('/')
def index():
    return jsonify({"message": "Welcome to the Agni-Shield API!"})


@main.route('/api/devices', methods=['GET'])
def get_devices():
    devices = []

    if os.path.exists(DEVICES_FILE_PATH):
        with open(DEVICES_FILE_PATH, newline='') as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                devices.append({
                    "id": int(row['id']),
                    "name": row['name'],
                    "ip": row['ip'],
                    "status": row['status'],
                })
    else:
        # If the file does not exist, return the hardcoded data as fallback
        devices = [
            {"id": 1, "name": "Device 1", "ip": "192.168.1.2", "status": "Active"},
            {"id": 2, "name": "Device 2", "ip": "192.168.1.3", "status": "Inactive"},
        ]

    return jsonify(devices)


def extract_domain(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Adding scheme to parse domain properly
    parsed_url = urlparse(url)
    return parsed_url.netloc or parsed_url.path.split('/')[0]


@main.route('/api/firewall-rules', methods=['GET'])
def get_firewall_rules():
    blocked_domains = []
    blocked_ips = []

    try:
        if os.path.exists(BLOCKED_DOMAINS_FILE_PATH):
            with open(BLOCKED_DOMAINS_FILE_PATH, newline='') as csvfile:
                csvreader = csv.reader(csvfile)
                for row in csvreader:
                    if row:
                        domain = extract_domain(row[0])
                        blocked_domains.append(domain)

        if os.path.exists(BLOCKED_IPS_FILE_PATH):
            with open(BLOCKED_IPS_FILE_PATH, newline='') as csvfile:
                csvreader = csv.reader(csvfile)
                for row in csvreader:
                    if row:
                        blocked_ips.append(row[0])

        return jsonify({
            'blockedDomains': blocked_domains,
            'blockedIPs': blocked_ips
        })

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'error': str(e), 'blockedDomains': [], 'blockedIPs': []}), 500


@main.route('/api/block-domain', methods=['POST'])
def block_domain():
    data = request.json
    domain = data.get('domain')
    device_id = data.get('deviceId')

    if not domain or not device_id:
        return jsonify({"error": "Domain and Device ID are required"}), 400

    try:
        with open(BLOCKED_DOMAINS_FILE_PATH, 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([domain])

        return jsonify({"message": "Domain blocked successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main.route('/api/block-ip', methods=['POST'])
def block_ip():
    data = request.json
    ip = data.get('ip')
    device_id = data.get('deviceId')

    if not ip or not device_id:
        return jsonify({"error": "IP and Device ID are required"}), 400

    try:
        with open(BLOCKED_IPS_FILE_PATH, 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([ip])

        return jsonify({"message": "IP blocked successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main.route('/api/scan-url', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        # Analyze the URL using the AI model
        action = ai_main(url, threshold=0.3)

        if action == 'Block':
            return jsonify({"result": "Blocked by AI", "reason": "Spam detected"}), 403
        else:
            return jsonify({"result": "Allowed by AI", "reason": "No spam detected"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main.route('/api/device/<int:device_id>', methods=['GET'])
def get_device_details(device_id):
    device = devices.get(device_id)
    if not device:
        return jsonify({"error": "Device not found"}), 404
    return jsonify(device)


@main.route('/api/device/<int:device_id>/domains', methods=['POST'])
def add_domain(device_id):
    data = request.json
    domain = data.get('domain')

    if device_id in devices:
        devices[device_id]['domains'].append(domain)

        # Log the addition to CSV
        with open(DOMAINS_CSV_PATH, 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([device_id, domain])

        # Log the domain addition with timestamp
        with open(DOMAIN_LOGS_PATH, 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([datetime.now().isoformat(), device_id, domain])

        return jsonify({"status": "success", "message": f"Domain {domain} added."})

    return jsonify({"status": "error", "message": "Device not found."}), 404


@main.route('/api/device/<int:device_id>/logs', methods=['GET'])
def get_device_logs(device_id):
    logs = []
    try:
        if os.path.exists(DOMAIN_LOGS_PATH):
            with open(DOMAIN_LOGS_PATH, newline='') as csvfile:
                csvreader = csv.DictReader(csvfile)
                for row in csvreader:
                    if int(row['device_id']) == device_id:
                        logs.append({"timestamp": row['timestamp'], "domain": row['domain']})

        return jsonify(logs), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main.route('/api/device/<int:device_id>/ips', methods=['POST'])
def add_ip(device_id):
    data = request.json
    ip = data.get('ip')
    
    if device_id in devices:
        devices[device_id]['ips'].append(ip)

        # Save to CSV
        with open(IPS_CSV_PATH, 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([device_id, ip])

        return jsonify({"status": "success", "message": f"IP {ip} added."})

    return jsonify({"status": "error", "message": "Device not found."}), 404


@main.route('/api/device/<int:device_id>/domains/manage', methods=['POST'])
def manage_domain(device_id):
    data = request.json
    domain = data.get('domain')
    action = data.get('action')
    # Add logic to handle domain management here
    return jsonify({"status": "success", "message": f"Domain {domain} has been {action}ed."})


@main.route('/api/device/<int:device_id>/ips/manage', methods=['POST'])
def manage_ip(device_id):
    data = request.json
    ip = data.get('ip')
    action = data.get('action')
    # Add logic to handle IP management here
    return jsonify({"status": "success", "message": f"IP {ip} has been {action}ed."})

# Ensure CSV files exist
if not os.path.exists(DOMAINS_CSV_PATH):
    with open(DOMAINS_CSV_PATH, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['device_id', 'domain'])

if not os.path.exists(IPS_CSV_PATH):
    with open(IPS_CSV_PATH, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['device_id', 'ip'])

if not os.path.exists(DOMAIN_LOGS_PATH):
    with open(DOMAIN_LOGS_PATH, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['timestamp', 'device_id', 'domain'])  # Log file with timestamp
