import sys
import os

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    print("Error: Scapy is not installed. Install it using: pip install scapy")
    sys.exit(1)

class NetworkIntrusionDetection:
    def __init__(self):
        self.packet_count = 0
        self.suspicious_ips = set()
        self.port_scan_threshold = 10
        self.syn_count = {}

    def packet_callback(self, packet):
        self.packet_count += 1
        
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Detect SYN flood attacks
            if TCP in packet:
                if packet[TCP].flags == 2:  # SYN flag
                    self.syn_count[ip_src] = self.syn_count.get(ip_src, 0) + 1
                    
                    if self.syn_count[ip_src] > self.port_scan_threshold:
                        self.suspicious_ips.add(ip_src)
                        print(f"⚠️  ALERT: Possible SYN flood from {ip_src}")
            
            # Detect ICMP floods (ping sweeps)
            if ICMP in packet:
                self.suspicious_ips.add(ip_src)
                print(f"⚠️  ALERT: ICMP packet detected from {ip_src}")
            
            print(f"[{self.packet_count}] {packet.summary()}")

    def start_sniffing(self, packet_count=0):
        try:
            print("="*60)
            print("Network Intrusion Detection System")
            print("="*60)
            print("Starting packet sniffing...")
            print("(Press Ctrl+C to stop)")
            print("="*60)
            
            if packet_count == 0:
                sniff(prn=self.packet_callback, store=False)
            else:
                sniff(prn=self.packet_callback, store=False, count=packet_count)
                
        except PermissionError:
            print("ERROR: This script requires administrator/root privileges!")
            print("On Windows: Run as Administrator")
            print("On Linux/Mac: Use 'sudo python network_intrusion_detection.py'")
        except KeyboardInterrupt:
            print("\n" + "="*60)
            print(f"Sniffing stopped. Total packets captured: {self.packet_count}")
            print(f"Suspicious IPs detected: {len(self.suspicious_ips)}")
            if self.suspicious_ips:
                print(f"IPs: {', '.join(self.suspicious_ips)}")
            print("="*60)
        except Exception as e:
            print(f"ERROR: {str(e)}")

if __name__ == '__main__':
    nid = NetworkIntrusionDetection()
    nid.start_sniffing()