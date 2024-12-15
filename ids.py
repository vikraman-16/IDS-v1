import scapy.all as scapy
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, ARP
from scapy.layers import http
import pyfiglet
from collections import defaultdict
import time

# Data structure to track anomalies
domain_count = defaultdict(int)
bandwidth_usage = defaultdict(int)
anomaly_log = []
tracker_domains = [
    "google-analytics.com", "doubleclick.net", "facebook.com", "adroll.com", "trackers.example.com",
    "hotjar.com", "newrelic.com", "appsflyer.com", "mixpanel.com", "segment.io",
    "optimizely.com", "crazyegg.com", "clicktale.net", "quantserve.com", "scorecardresearch.com",
    "chartbeat.com", "pardot.com", "marketo.net", "taboola.com", "outbrain.com"
]
blacklisted_ips = ["192.168.1.100", "10.0.0.200"]  # Example blacklisted IPs

# Known legitimate IPs for DNS spoofing detection
known_dns_ips = {
    "example.com": "93.184.216.34",  # Replace with real known IPs
    "google.com": "142.250.190.78"
}

# Thresholds for detecting anomalies
DNS_QUERY_THRESHOLD = 10  # Maximum DNS queries per minute per domain
HTTP_PAYLOAD_THRESHOLD = 5000  # Maximum payload size in bytes
PORT_SCAN_THRESHOLD = 10  # Maximum unique ports accessed by a single IP

# Data structure to track port scanning
port_scan_tracker = defaultdict(set)

# Function to analyze and process packets
def process_sniffed_packet(packet):
    # Detect DNS anomalies
    if packet.haslayer(DNS) and packet[DNS].opcode == 0:  # Check if it's a query
        if packet.haslayer(DNSQR):  # Ensure DNSQR layer exists
            domain = packet[DNSQR].qname.decode()
            domain_count[domain] += 1

            if domain_count[domain] > DNS_QUERY_THRESHOLD:
                log_anomaly(f"High DNS query volume detected for domain: {domain}")

            # Detect trackers
            for tracker in tracker_domains:
                if tracker in domain:
                    log_anomaly(f"Tracker domain detected: {domain}")

            # Detect DNS spoofing
            if packet.haslayer(DNSRR):
                response_ip = packet[DNSRR].rdata
                if domain in known_dns_ips and known_dns_ips[domain] != response_ip:
                    log_anomaly(f"DNS spoofing detected for domain: {domain}. Legitimate IP: {known_dns_ips[domain]}, Spoofed IP: {response_ip}")

    # Detect HTTP anomalies
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            if len(load) > HTTP_PAYLOAD_THRESHOLD:
                src_ip = packet[IP].src
                log_anomaly(f"Large HTTP payload detected from IP: {src_ip}, Payload Size: {len(load)} bytes")

    # Detect IP blacklist violations
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if src_ip in blacklisted_ips:
            log_anomaly(f"Traffic detected from blacklisted IP: {src_ip}")

        # Track bandwidth usage
        bandwidth_usage[src_ip] += len(packet)

    # Detect port scanning
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
        port_scan_tracker[src_ip].add(dst_port)
        if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
            log_anomaly(f"Potential port scanning detected from IP: {src_ip}")

    # Detect ARP spoofing
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        mac = packet[ARP].hwsrc
        ip = packet[ARP].psrc
        for other_ip, other_mac in port_scan_tracker.items():
            if other_ip == ip and other_mac != mac:
                log_anomaly(f"ARP spoofing detected for IP: {ip} with MAC: {mac}")

# Function to log anomalies
last_anomaly_message = None  # Store the last printed anomaly message


def log_anomaly(message):
    global last_anomaly_message
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    formatted_message = f"[{timestamp}] {message}"

    # Only print if the message is different from the last one
    if formatted_message != last_anomaly_message:
        anomaly_log.append(formatted_message)
        print(f"\033[31m[ANOMALY DETECTED]\033[0m {formatted_message}")
        last_anomaly_message = formatted_message

# Function to display banner
def about_banner():
    banner = pyfiglet.figlet_format("Network Anomaly Analyzer")
    about = f"""
    {banner}
    [+] Author: Vikraman-P
    [+] Updated Version: 0.5
    [+] Monitoring network traffic for anomalies, trackers, and suspicious activities...
    """
    print(about)

# Function to sniff network traffic
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

# Function to summarize anomaly logs
def display_summary():
    print("\n\033[34m[SUMMARY]\033[0m Detected Anomalies:")
    for log in anomaly_log:
        print(log)
    print("\n\033[34m[SUMMARY]\033[0m Bandwidth Usage:")
    for ip, usage in bandwidth_usage.items():
        print(f"IP: {ip}, Bandwidth: {usage} bytes")

# Main function
def main():
    about_banner()
    interface = input("Enter the network interface to monitor (e.g., eth0, wlan0): ")
    try:
        print("\n\033[32m[INFO]\033[0m Starting network monitoring on interface:", interface)
        sniff(interface)
    except KeyboardInterrupt:
        print("\n\033[33m[INFO]\033[0m Stopping network monitoring...")
        display_summary()
    except Exception as e:
        print(f"\033[31m[ERROR]\033[0m {e}")

if __name__ == "__main__":
    main()
