#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import argparse
import sys
import os
import signal
from datetime import datetime

class PacketSniffer:
    def __init__(self):
        self.captured_packets = []
        self.filters = {}
        self.continue_analyzing = True
        self.interface = None
        self.stop_sniffing = False
        self.packet_timestamps = []
       

        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        if not self.stop_sniffing:
            self.stop_sniffing = True
            print("\n\nCaught Ctrl+C! Stopping capture...")

    def start(self):
        print("Packet Sniffer...")
        self.setup_interface()
        self.capture_traffic()

    def setup_interface(self):
        print("\nAvailable network interfaces:")
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces):
            print(f"{i+1}. {iface}")
        
        try:
            choice = input("\nSelect interface (number or name): ").strip()
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    self.interface = interfaces[idx]
                else:
                    raise ValueError("Invalid number")
            else:
                self.interface = choice
            print(f"Selected interface: {self.interface}")
        except:
            print("Invalid selection, using default interface")
            self.interface = conf.iface
            print(f"Using: {self.interface}")

    def capture_traffic(self):
        print(f"\nCapturing traffic on {self.interface}...")
        print("Press Ctrl+C to stop capturing\n")
        
        self.stop_sniffing = False
        
        # Use stop_filter to check our flag
        sniff(iface=self.interface, 
              prn=self.process_packet, 
              store=False,
              stop_filter=lambda x: self.stop_sniffing)
        
        # After sniffing stops
        print(f"\nTotal packets captured: {len(self.captured_packets)}\n")
        if len(self.captured_packets) > 0:
            self.analyze_captured_data()
        else:
            print("No packets captured.")

    def process_packet(self, packet):
        self.captured_packets.append(packet)
        timestamp = datetime.now().strftime("%H:%M:%S")
        src = "Unknown"
        dst = "Unknown"
        protocol = "Unknown"
        
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            
            if TCP in packet:
                protocol = f"TCP:{packet[TCP].dport}"
            elif UDP in packet:
                protocol = f"UDP:{packet[UDP].dport}"
            elif ICMP in packet:
                protocol = "ICMP"
        
        print(f"[{timestamp}] {src:15} -> {dst:15} | {protocol}")

    def detect_anomalies(self):
        anomalies = []
        if len(self.captured_packets) < 10:
            return anomalies

        syn_packets = {}
        ack_packets = {}

        for pkt in self.captured_packets:
            if TCP in pkt and IP in pkt:
                src = pkt[IP] in pkt
                flags = pkt[TCP].flags

                if flags & 0x02:
                    syn_packets[src] = syn_packets.get(src, 0) + 1

                if flags & 0x10:
                    ack_packets[src] = ack_packets.get(src, 0) + 1

        for src_ip, syn_count in syn_packets.items():
            ack_count = ack_packets.get(src_ip, 0)
            if syn_count > 10 and (ack_count < syn_count * 0.3):
                anomalies.append({
                    'type' : 'SYN Flood',
                    'severity' : 'HIGH',
                    'description' : f'Possible SYN flood from {src_ip}',
                    'details' : f'{syn_count} SYN packets, only {ack_count} ACKs'
                })

        port_scan = {}
        for pkt in self.captured_packets:
            if TCP in pkt and IP in pkt:
                src = pkt[IP].src
                dst_port = pkt[TCP].dport
                if src not in port_scan:
                    port_scan[src] = set()
                port_scan[src].add(dst_port)
        
        for src_ip, ports in port_scan.items():
            if len(ports) > 20:
                anomalies.append({
                    'type': 'Port Scan',
                    'severity': 'HIGH',
                    'description': f'Possible port scan from {src_ip}',
                    'details': f'Attempted connection to {len(ports)} different ports'
                })

        if len(self.packet_timestamps) > 20:
            time_windows = []
            window_size = 5
            
            start_time = self.packet_timestamps[0]
            end_time = self.packet_timestamps[-1]
            total_duration = (end_time - start_time).total_seconds()
            
            if total_duration > 10:
                for i in range(0, len(self.packet_timestamps) - 1):
                    current_time = self.packet_timestamps[i]
                    packets_in_window = sum(1 for t in self.packet_timestamps 
                                          if current_time <= t < current_time + timedelta(seconds=window_size))
                    if packets_in_window > 0:
                        time_windows.append(packets_in_window)
                
                if time_windows:
                    avg_rate = sum(time_windows) / len(time_windows)
                    max_rate = max(time_windows)
                    
                    if max_rate > avg_rate * 3 and max_rate > 50:
                        anomalies.append({
                            'type': 'Traffic Spike',
                            'severity': 'MEDIUM',
                            'description': 'Unusual traffic spike detected',
                            'details': f'Peak: {max_rate} packets/5s, Average: {avg_rate:.1f} packets/5s'
                        })
        protocol_count = {}
        for pkt in self.captured_packets:
            if IP in pkt:
                proto = pkt[IP].proto
                protocol_count[proto] = protocol_count.get(proto, 0) + 1
        
        total = len(self.captured_packets)
        for proto, count in protocol_count.items():
            percentage = (count / total) * 100
            if proto not in [6, 17, 1] and percentage > 10:
                anomalies.append({
                    'type': 'Unusual Protocol',
                    'severity': 'LOW',
                    'description': f'High volume of unusual protocol (ID: {proto})',
                    'details': f'{count} packets ({percentage:.1f}%)'
                })
        dst_sources = {}
        for pkt in self.captured_packets:
            if IP in pkt:
                dst = pkt[IP].dst
                src = pkt[IP].src
                if dst not in dst_sources:
                    dst_sources[dst] = set()
                dst_sources[dst].add(src)
        
        for dst_ip, sources in dst_sources.items():
            if len(sources) > 15:
                anomalies.append({
                    'type': 'Potential DDoS',
                    'severity': 'HIGH',
                    'description': f'Many sources targeting {dst_ip}',
                    'details': f'{len(sources)} different source IPs'
                })
        
        return anomalies


    def analyze_captured_data(self):
        while self.continue_analyzing:
            print("\n" + "="*60)
            print("Packet Analysis Menu")
            print("="*60)
            print("1. Download pcap file")
            print("2. Filter packets")
            print("3. View Network Traffic Summary")
            print("4. Display detailed output")
            print("5. Continue analyzing")
            print("6. Exit")
            
            choice = input("\nSelect option (1-6): ").strip()
            
            if choice == "1":
                self.save_pcap_file()
            elif choice == "2":
                self.apply_filters()
            elif choice == "3":
                self.view_traffic_summary()
            elif choice == "4":
                self.display_detailed_output()
            elif choice == "5":
                self.continue_analysis()
            elif choice == "6":
                self.end_analysis()
                break
            else:
                print("Invalid option, please try again")

    def save_pcap_file(self):
        filename = input("Enter filename for pcap (default: capture.pcap): ").strip()
        if not filename:
            filename = "capture.pcap"
        if not filename.endswith('.pcap'):
            filename += '.pcap'
        
        try:
            wrpcap(filename, self.captured_packets)
            print(f"Packets saved to {filename}")
            print(f"Total packets saved: {len(self.captured_packets)}")
        except Exception as e:
            print(f"Error saving file: {e}")

    def apply_filters(self):
        print("\nPACKET FILTERS")
        print("1. Filter by IP address")
        print("2. Filter by protocol")
        print("3. Filter by port")
        print("4. Clear filters")
        
        filter_choice = input("Select filter option (1-4): ").strip()
        
        if filter_choice == "1":
            ip = input("Enter IP address to filter: ").strip()
            filtered = [pkt for pkt in self.captured_packets 
                       if IP in pkt and (pkt[IP].src == ip or pkt[IP].dst == ip)]
            self.display_filtered_results(filtered, f"IP: {ip}")
            
        elif filter_choice == "2":
            protocol = input("Enter protocol (TCP/UDP/ICMP): ").strip().upper()
            if protocol == "TCP":
                filtered = [pkt for pkt in self.captured_packets if TCP in pkt]
            elif protocol == "UDP":
                filtered = [pkt for pkt in self.captured_packets if UDP in pkt]
            elif protocol == "ICMP":
                filtered = [pkt for pkt in self.captured_packets if ICMP in pkt]
            else:
                print("Invalid protocol")
                return
            self.display_filtered_results(filtered, f"Protocol: {protocol}")
            
        elif filter_choice == "3":
            port = input("Enter port number: ").strip()
            try:
                port = int(port)
                filtered = [pkt for pkt in self.captured_packets if
                           (TCP in pkt and (pkt[TCP].sport == port or pkt[TCP].dport == port)) or
                           (UDP in pkt and (pkt[UDP].sport == port or pkt[UDP].dport == port))]
                self.display_filtered_results(filtered, f"Port: {port}")
            except ValueError:
                print("Invalid port number")
                
        elif filter_choice == "4":
            self.filters = {}
            print("All filters cleared")

    def display_filtered_results(self, filtered_packets, filter_desc):
        print(f"\nFILTERED RESULTS ({filter_desc})")
        print("="*60)
        print(f"Total packets matching filter: {len(filtered_packets)}")
        
        if filtered_packets:
            print("\nFirst 10 matching packets:")
            for i, pkt in enumerate(filtered_packets[:10]):
                print(f"\n--- Packet {i+1} ---")
                if IP in pkt:
                    print(f"Source: {pkt[IP].src}")
                    print(f"Destination: {pkt[IP].dst}")
                    print(f"Protocol: {pkt[IP].proto}")
                    print(f"Length: {len(pkt)} bytes")
        else:
            print("No packets match the filter criteria")

    def view_traffic_summary(self):
        print("\nNETWORK TRAFFIC SUMMARY")
        print("="*60)
        
        total_packets = len(self.captured_packets)
        tcp_count = sum(1 for pkt in self.captured_packets if TCP in pkt)
        udp_count = sum(1 for pkt in self.captured_packets if UDP in pkt)
        icmp_count = sum(1 for pkt in self.captured_packets if ICMP in pkt)
        
        print(f"Total Packets Captured: {total_packets}")
        if total_packets > 0:
            print(f"TCP Packets: {tcp_count} ({tcp_count/total_packets*100:.1f}%)")
            print(f"UDP Packets: {udp_count} ({udp_count/total_packets*100:.1f}%)")
            print(f"ICMP Packets: {icmp_count} ({icmp_count/total_packets*100:.1f}%)")
        
        ip_stats = {}
        for pkt in self.captured_packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                ip_stats[src_ip] = ip_stats.get(src_ip, 0) + 1
                ip_stats[dst_ip] = ip_stats.get(dst_ip, 0) + 1
        
        if ip_stats:
            print("\nTop 5 Most Active IPs:")
            sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)
            for i, (ip, count) in enumerate(sorted_ips[:5]):
                print(f"{i+1}. {ip}: {count} packets")

            print("\n" + "="*60)
        anomalies = self.detect_anomalies()
        
        if anomalies:
            print(f"\n  Found {len(anomalies)} potential security issues:\n")
            
            for i, anomaly in enumerate(anomalies, 1):
                print(f"{i}. [{anomaly['severity']}] {anomaly['type']}")
                print(f"   Description: {anomaly['description']}")
                print(f"   Details: {anomaly['details']}")
                print()
        else:
            print("\nNo anomalies detected - traffic appears normal\n")

    def display_detailed_output(self):
        print("\nDETAILED PACKET ANALYSIS")
        print("="*60)
        
        if not self.captured_packets:
            print("No packets captured yet")
            return
        
        num_packets = min(5, len(self.captured_packets))
        print(f"Showing detailed view of last {num_packets} packets:\n")
        
        for i, pkt in enumerate(self.captured_packets[-num_packets:]):
            print(f"PACKET {len(self.captured_packets)-num_packets+i+1}")
            print("-" * 40)
            
            if Ether in pkt:
                print(f"Ethernet: {pkt[Ether].src} → {pkt[Ether].dst}")
            
            if IP in pkt:
                sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                print(f"IP: {pkt[IP].src}:{sport} → {pkt[IP].dst}:{dport}")
                print(f"Protocol: {pkt[IP].proto}")
                print(f"TTL: {pkt[IP].ttl}")
                print(f"Length: {pkt[IP].len}")
            
            if TCP in pkt:
                print(f"TCP Flags: {pkt[TCP].flags}")
                print(f"Seq: {pkt[TCP].seq}, Ack: {pkt[TCP].ack}")
            elif UDP in pkt:
                print(f"UDP Length: {pkt[UDP].len}")
            
            print(f"Total Size: {len(pkt)} bytes")
            print()

    def continue_analysis(self):
        print("\nContinue analyzing selected")
        choice = input("Do you want to capture more packets? (y/n): ").strip().lower()
        if choice == 'y':
            print("Starting new capture session...")
            self.capture_traffic()
        else:
            print("Continuing with current packet analysis...")

    def end_analysis(self):
        print("\nThank you for using the Packet Sniffer!")
        print("Session Summary:")
        print(f"  • Total packets captured: {len(self.captured_packets)}")
        print(f"  • Interface used: {self.interface}")
        print(f"  • Session duration: Complete")
        self.continue_analyzing = False

def main():
    parser = argparse.ArgumentParser(description='Network Packet Sniffer using Scapy')
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-f', '--filter', help='BPF filter expression')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    args = parser.parse_args()
    
    print("Network Packet Sniffer Tool")
    print("=" * 40)
    
    if os.geteuid() != 0:
        print("Warning: This tool requires root privileges for packet capture")
        print("Please run with: sudo python3 tool.py")
        sys.exit(1)
    
    sniffer = PacketSniffer()
    if args.interface:
        sniffer.interface = args.interface
    
    sniffer.start()

if __name__ == "__main__":
    main()
