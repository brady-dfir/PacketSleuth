# PCAP Analysis Tool

## Overview
A python script that parses PCAP files, summarizes traffic, and flags suspicious activity. This tool identifies and extracts per-packet metadata such as source/destination IPs, ports, and protocols. This tool also computes activity summaries and detects port scans, repeated failed attempts, and connection spikes. Results are exported as CSV reports.

## Key Features
Identify top talkers by packet and byte counts
Breakdown by protocol (TCP, UDP, HTTP, DNS)
Port scan detection
Detects repeated failed attempts using TCP and HTTP flags
Detects connection spikes by comparing per-minute rates
Exports summary and alerts to a CSV

## Requirements
Python 3.9
PyShark - Requires tshark installed on the host
Scapy
Pandas

## Install Python packages:
python -m pip install pyshark scapy pandas
Ensure tshark is installed and available on PATH for packet dissection.

## How To Run Script
python LogAnalysisTool.py example_capture.pcap

## Output Files
report_top_talkers.csv - columns: ip, packets, bytes
report_protocols.csv - columns: protocol, count
alerts.csv - Each row is one alert. Columns vary by alert type.

## alert.csv Definitions
type - port_scan, repeated_failed_attempts, connection_spike.
src and dst - Source and destination IPs.
port - Destination port.
distinct_ports - Number of distinct destination ports from port scans.
count_in_window and window_sec - Counts and window used for repeated failure alerts.
minute and median_rate - Minute timestamp and baseline used for connection spike detection.

## Detection Criteria
Port scan - A source that connects to destination ports on a target within a short time window is suspicious. Default threshold: >= 100 distinct ports in 60 seconds. Flags horizontal and vertical scans.
Repeated failed attempts - Failures include TCP SYNs without handshake completion, RSTs, or repeated HTTP (401/403) responses from the same source. Default threshold: >= 5 failures in 5 minutes.
Connection spikes - Computes per-minute connection counts per source, compare to the per-minute rate for that source, and flag minutes that exceed 5x the per-minute median.

## Detection Threshold Configuration
The detection thresholds are located at the top of the script. Lower thresholds will increase sensitivity, but increase false positives. Higher thresholds will reduce noise, but increases chance of missing stealthy activity. Thresholds should be configured based on capture size, traffic patterns, and the environment.

## Limitations and Known Issues
Encrypted application protocols such as SSH and HTTPS hide application layer failures. Detection relies on connection level signals only.
Visibility depends on capture point - Captures on a single host or network will show different views. NAT and load balancers can obscure endpoints.
False positives are possible for high volume services, port sweeps by scanners, or volatile application behavior. Alerts should be used as triage signals, not evidence.

## Troubleshooting
PyShark errors and tshark - Ensure that tshark is installed on PATH. Install via package manager.
Missing fields - Some packets lack IP or TCP layers. The tool will skip irregular or non-IP frames.
High memory usage - Process large captures in chunks or filter the capture before analysis.

## Future Improvements
GeoIP - Add country columns for IPs to prioritize threats.
SIEM Integration - Output JSON or push alerts to a SIEM for correlation.
Protocol Detectors - SSH brute-force, HTTP credential stuffing detection, or DNS tunneling detection.
Rate Limited Alerts - Group repeated alerts into aggregated incidents to reduce noise.

## Ownership and Contact Information
This tool was developed by Brady Peer as a personal project.
For questions please contact brdypr@gmail.com