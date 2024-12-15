# Network Anomaly Analyzer

## Overview
**Network Anomaly Analyzer** is a Python-based tool that monitors network traffic in real-time to detect anomalies, trackers, and suspicious activities. It uses Scapy for packet analysis and provides a comprehensive summary of detected issues, including bandwidth usage, DNS spoofing, HTTP anomalies, ARP spoofing, and port scanning.

![Network Anomaly Analyzer Banner](https://via.placeholder.com/800x200.png?text=Network+Anomaly+Analyzer)  
*Monitor, detect, and secure your network.*

---

## Features
- **Real-time DNS anomaly detection**: Identifies high query volumes and spoofed DNS responses.
- **Tracker detection**: Detects network requests to known tracker domains.
- **Blacklisted IP monitoring**: Alerts when traffic originates from blacklisted IPs.
- **HTTP payload analysis**: Detects large payloads that may indicate malicious behavior.
- **Port scanning detection**: Identifies potential port scanning activities.
- **ARP spoofing detection**: Tracks ARP anomalies to prevent man-in-the-middle attacks.
- **Bandwidth usage tracking**: Logs data usage per IP address.

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-anomaly-analyzer.git
   cd network-anomaly-analyzer

