import sys
import time
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
import pyshark
from scapy.all import rdpcap, TCP, IP
import pandas as pd

# Detection Thresholds
PORT_SCAN_PORT_THRESHOLD = 100
PORT_SCAN_WINDOW_SEC = 60
FAILED_ATTEMPT_THRESHOLD = 5
FAILED_ATTEMPT_WINDOW_SEC = 300
SPIKE_MULTIPLIER = 5

# Helper function
def ts_to_dt(ts):
    return datetime.fromtimestamp(float(ts))

# Main analysis using PyShark
def analyze_pcap(pcap_file):
    pkt_count_by_ip = Counter()
    bytes_by_ip = Counter()
    proto_counts = Counter()
    conn_events = []  # timestamp, src, dst, sport, dport, proto, flags, length, info
    syn_events = defaultdict(list)  # list of ts, dst, dport
    port_scan_candidates = defaultdict(lambda: defaultdict(set))
    failed_attempts = defaultdict(list)  # List of timestamps
    per_minute_conn = defaultdict(list)  # List of minute timestamps

    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    for pkt in cap:
        try:
            ts = float(pkt.sniff_timestamp)
            proto = pkt.highest_layer
            src = pkt.ip.src if hasattr(pkt, 'ip') else (pkt.eth.src if hasattr(pkt, 'eth') else 'unknown')
            dst = pkt.ip.dst if hasattr(pkt, 'ip') else (pkt.eth.dst if hasattr(pkt, 'eth') else 'unknown')
            length = int(pkt.length) if hasattr(pkt, 'length') else 0

            pkt_count_by_ip[src] += 1
            bytes_by_ip[src] += length
            proto_counts[proto] += 1

            sport = getattr(pkt, 'tcp', None) and getattr(pkt.tcp, 'srcport', None)
            dport = getattr(pkt, 'tcp', None) and getattr(pkt.tcp, 'dstport', None)
            # Records connection events for TCP
            flags = None
            if hasattr(pkt, 'tcp'):
                flags = pkt.tcp.flags
                conn_events.append((ts, src, dst, sport, dport, 'TCP', flags, length, proto))
                # SYN detection
                if '0x0002' in str(flags) or 'SYN' in str(flags):
                    syn_events[src].append((ts, dst, int(dport) if dport else None))
                    port_scan_candidates[src][dst].add(int(dport) if dport else None)
                # RST or SYN-ACK missing, treat RST as failure
                if 'RST' in str(flags) or '0x0004' in str(flags):
                    failed_attempts[(src, dst, dport)].append(ts)
            # HTTP auth failures
            if proto == 'HTTP' and hasattr(pkt.http, 'response_code'):
                code = int(pkt.http.response_code)
                if code in (401, 403):
                    failed_attempts[(src, dst, dport)].append(ts)
            # DNS queries count as UDP
            if proto == 'DNS':
                proto_counts['DNS'] += 1

            # Per-minute connection timestamps for spike detection
            minute_ts = datetime.fromtimestamp(ts).replace(second=0, microsecond=0)
            per_minute_conn[src].append(minute_ts)

        except Exception:
            continue
    cap.close()

    # Detects port scans
    now = datetime.utcnow().timestamp()
    port_scan_alerts = []
    for src, dst_map in port_scan_candidates.items():
        for dst, ports in dst_map.items():
            # Counts distinct ports
            if len(ports) >= PORT_SCAN_PORT_THRESHOLD:
                port_scan_alerts.append({
                    'type': 'port_scan',
                    'src': src,
                    'dst': dst,
                    'distinct_ports': len(ports),
                    'threshold': PORT_SCAN_PORT_THRESHOLD
                })

    # Detects repeated failed attempts
    failed_alerts = []
    for key, times in failed_attempts.items():
        times_sorted = sorted(times)
        dq = deque()
        for t in times_sorted:
            dq.append(t)
            while dq and (t - dq[0]) > FAILED_ATTEMPT_WINDOW_SEC:
                dq.popleft()
            if len(dq) >= FAILED_ATTEMPT_THRESHOLD:
                src, dst, dport = key
                failed_alerts.append({
                    'type': 'repeated_failed_attempts',
                    'src': src,
                    'dst': dst,
                    'port': dport,
                    'count_in_window': len(dq),
                    'window_sec': FAILED_ATTEMPT_WINDOW_SEC
                })
                break

    # Detects spikes in connection rate
    spike_alerts = []
    for src, minutes in per_minute_conn.items():
        if not minutes:
            continue
        counts = Counter(minutes)
        rates = list(counts.values())
        median_rate = pd.Series(rates).median()
        for minute, cnt in counts.items():
            if median_rate == 0:
                if cnt >= SPIKE_MULTIPLIER:
                    spike_alerts.append({
                        'type': 'connection_spike',
                        'src': src,
                        'minute': minute.isoformat(),
                        'count': cnt,
                        'median_rate': int(median_rate)
                    })
            else:
                if cnt > SPIKE_MULTIPLIER * median_rate:
                    spike_alerts.append({
                        'type': 'connection_spike',
                        'src': src,
                        'minute': minute.isoformat(),
                        'count': cnt,
                        'median_rate': int(median_rate)
                    })

    # Create summaries
    top_talkers = pd.DataFrame([
        {'ip': ip, 'packets': pkt_count_by_ip[ip], 'bytes': bytes_by_ip[ip]}
        for ip in pkt_count_by_ip
    ]).sort_values(by='packets', ascending=False).head(50)

    proto_df = pd.DataFrame([{'protocol': k, 'count': v} for k, v in proto_counts.items()]).sort_values('count', ascending=False)

    # Build alerts
    alerts = port_scan_alerts + failed_alerts + spike_alerts
    alerts_df = pd.DataFrame(alerts)

    # Export CSV
    top_talkers.to_csv('report_top_talkers.csv', index=False)
    proto_df.to_csv('report_protocols.csv', index=False)
    alerts_df.to_csv('alerts.csv', index=False)

    return {
        'top_talkers': top_talkers,
        'protocols': proto_df,
        'alerts': alerts_df
    }

# CLI
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python pcap_analyzer.py input.pcap")
        sys.exit(1)
    pcap_file = sys.argv[1]
    print(f"Analyzing {pcap_file} ...")
    results = analyze_pcap(pcap_file)
    print("Top talkers written to report_top_talkers.csv")
    print("Protocol counts written to report_protocols.csv")
    print("Alerts written to alerts.csv")