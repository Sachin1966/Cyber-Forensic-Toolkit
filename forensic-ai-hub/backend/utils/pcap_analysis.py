try:
    from scapy.all import rdpcap, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not installed. PCAP analysis will be disabled.")

import os
import sys
from datetime import datetime


from backend.database import log_scan, update_stats

def analyze_pcap_file(file_path):
    if not SCAPY_AVAILABLE:
        # Return explicit error key that app.py will check
        return {
            'error': 'Scapy library not installed or Npcap missing. Please install scapy and Npcap.',
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'PCAP',
            'filename': os.path.basename(file_path)
        }
        
    try:
        # Check if file is empty
        if os.path.getsize(file_path) == 0:
             return {
                'error': 'Uploaded file is empty.',
                'timestamp': datetime.now().isoformat(),
                'scan_type': 'PCAP',
                'filename': os.path.basename(file_path)
            }

        packets = rdpcap(file_path)
        
        if not packets:
             return {
                'error': 'No packets found in the file.',
                'timestamp': datetime.now().isoformat(),
                'scan_type': 'PCAP',
                'filename': os.path.basename(file_path)
            }

        packet_count = len(packets)
        protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        total_bytes = 0
        start_time = packets[0].time if packets else 0
        end_time = packets[-1].time if packets else 0
        
        for pkt in packets:
            total_bytes += len(pkt)
            if TCP in pkt:
                protocols['TCP'] += 1
            elif UDP in pkt:
                protocols['UDP'] += 1
            elif ICMP in pkt:
                protocols['ICMP'] += 1
            else:
                protocols['Other'] += 1
                
        duration = end_time - start_time
        
        # Simple anomaly detection (heuristic)
        anomalies = []
        if protocols['TCP'] > packet_count * 0.9:
            anomalies.append("High TCP Traffic (Potential Scan/Flood)")
        if packet_count > 1000 and duration < 10:
            anomalies.append("High Packet Rate (Potential DDoS)")
            
        # Threat score calculation (heuristic)
        threat_score = 0
        if anomalies:
            threat_score = 70
        
        is_threat = threat_score > 50
        
        # Log to database
        result = {
            'scan_type': 'PCAP',
            'input_summary': os.path.basename(file_path),
            'filename': os.path.basename(file_path),
            'packetCount': packet_count,
            'protocols': protocols,
            'anomalies': anomalies,
            'threatScore': threat_score,
            'networkStats': {
                'totalBytes': total_bytes,
                'avgPacketSize': total_bytes / packet_count if packet_count else 0,
                'duration': float(duration)
            },
            'timestamp': datetime.now().isoformat()
        }

        # Log to database
        log_scan('pcap', os.path.basename(file_path), 'Suspicious' if is_threat else 'Normal', threat_score, is_threat, details=result)
        update_stats('pcap', is_threat)
        
        return result
    except Exception as e:
        return {
            'error': f"Error analyzing PCAP: {str(e)}",
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'PCAP',
            'filename': os.path.basename(file_path)
        }
