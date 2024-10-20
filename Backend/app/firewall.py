import socket
import struct
import re
import os
import logging
import threading
import dns
import requests
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from OpenSSL import SSL

# Configure logging
logging.basicConfig(filename='advanced_firewall.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables
BLOCKED_IPS = set()
BLOCKED_DOMAINS = set()
BLOCKED_PORTS = {135, 137, 138, 139, 445}
ALLOWED_PROTOCOLS = {socket.IPPROTO_TCP, socket.IPPROTO_UDP, socket.IPPROTO_ICMP}
CONNECTION_TRACKER = defaultdict(int)
DNS_REQUESTS = defaultdict(set)
RATE_LIMIT_THRESHOLD = 100  # Max requests per IP per minute

# Threat intelligence sources
THREAT_FEEDS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",  # Example threat feed
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
]

# Regex patterns for DPI
MALICIOUS_PATTERNS = [
    re.compile(b'select.*from.*users', re.IGNORECASE),  # SQL injection example
    re.compile(b'<script>', re.IGNORECASE),  # XSS example
]

def load_threat_intelligence():
    for url in THREAT_FEEDS:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if re.match(r'^\d+\.\d+\.\d+\.\d+', line):  # Simple IP address detection
                        BLOCKED_IPS.add(line.strip())
                    elif re.match(r'^\S+\.\S+', line):  # Simple domain detection
                        BLOCKED_DOMAINS.add(line.strip())
        except Exception as e:
            logging.error(f"Failed to load threat feed {url}: {e}")

def packet_filter(packet):
    ip_layer = packet.getlayer(IP)
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = ip_layer.proto

    if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
        logging.warning(f"Packet blocked: {src_ip} -> {dst_ip} (Blocked IP)")
        return False

    if protocol not in ALLOWED_PROTOCOLS:
        logging.warning(f"Packet blocked: {src_ip} -> {dst_ip} (Blocked Protocol {protocol})")
        return False

    # Port filtering
    if protocol == socket.IPPROTO_TCP or protocol == socket.IPPROTO_UDP:
        transport_layer = packet.getlayer(TCP) if protocol == socket.IPPROTO_TCP else packet.getlayer(UDP)
        src_port = transport_layer.sport
        dst_port = transport_layer.dport
        if src_port in BLOCKED_PORTS or dst_port in BLOCKED_PORTS:
            logging.warning(f"Packet blocked: {src_ip}:{src_port} -> {dst_ip}:{dst_port} (Blocked Port)")
            return False

    return True

def dns_filter(packet):
    dns_request = packet[UDP].payload
    domain = str(dns_request.qd.qname, 'utf-8') if dns_request.qd.qname else ""
    if any(blocked_domain in domain for blocked_domain in BLOCKED_DOMAINS):
        logging.warning(f"Blocked DNS request to malicious domain: {domain}")
        return False
    return True

def deep_packet_inspection(packet):
    payload = bytes(packet)
    for pattern in MALICIOUS_PATTERNS:
        if pattern.search(payload):
            logging.warning(f"Malicious content detected from {packet[IP].src} to {packet[IP].dst}")
            return False
    return True

def ssl_decrypt(packet):
    # Placeholder for SSL/TLS decryption
    # Requires access to SSL keys and further setup (e.g., using mitmproxy or similar tool)
    return True

def rate_limiting(src_ip):
    CONNECTION_TRACKER[src_ip] += 1
    if CONNECTION_TRACKER[src_ip] > RATE_LIMIT_THRESHOLD:
        logging.critical(f"Rate limiting: Blocked {src_ip} after {CONNECTION_TRACKER[src_ip]} connections")
        return False
    return True

def log_packet(packet):
    ip_layer = packet.getlayer(IP)
    protocol = ip_layer.proto
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    if protocol == socket.IPPROTO_TCP:
        transport_layer = packet.getlayer(TCP)
        src_port = transport_layer.sport
        dst_port = transport_layer.dport
    elif protocol == socket.IPPROTO_UDP:
        transport_layer = packet.getlayer(UDP)
        src_port = transport_layer.sport
        dst_port = transport_layer.dport
    else:
        src_port = dst_port = None

    logging.info(f"Packet allowed: {src_ip}:{src_port} -> {dst_ip}:{dst_port} Protocol: {protocol}")

def firewall(packet):
    # Step 1: Packet filtering
    if not packet_filter(packet):
        return False

    # Step 2: DNS filtering
    if packet.haslayer(UDP) and packet.haslayer(dns) and not dns_filter(packet):
        return False

    # Step 3: SSL/TLS Decryption (placeholder, requires additional setup)
    if packet.haslayer(TCP) and packet[TCP].dport == 443 and not ssl_decrypt(packet):
        return False

    # Step 4: Deep packet inspection
    if not deep_packet_inspection(packet):
        return False

    # Step 5: Rate limiting
    if not rate_limiting(packet[IP].src):
        return False

    # Step 6: Log the allowed packet
    log_packet(packet)

    return True

def start_firewall():
    load_threat_intelligence()
    sniff(prn=firewall, store=0, filter="ip")

if __name__ == "__main__":
    # Run the firewall in a separate thread
    firewall_thread = threading.Thread(target=start_firewall)
    firewall_thread.start()
    firewall_thread.join()
