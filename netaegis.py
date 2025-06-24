import os
import json
import ipaddress
from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
from collections import defaultdict
import pyfiglet

RULES_FILE = "rules.json"
LOG_FILE = "firewall_log.txt"

def print_banner():
    ascii_banner = pyfiglet.figlet_format("NetAegis")
    print(ascii_banner)

def load_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    else:
        return {"block_ips": [], "block_ports": [], "block_protocols": []}

def save_rules():
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=4)

def log_event(event):
    with open(LOG_FILE, "a") as f:
        f.write(event + "\n")
    print(event)

def apply_iptables_rule(ip=None, port=None, protocol=None):
    if ip:
        os.system(f"sudo iptables -A OUTPUT -p tcp -d {ip} -j REJECT")
        os.system(f"sudo iptables -A INPUT -p tcp -s {ip} -j REJECT")
        os.system(f"sudo iptables -A OUTPUT -p udp -d {ip} -j DROP")
        os.system(f"sudo iptables -A INPUT -p udp -s {ip} -j DROP")
        os.system(f"sudo iptables -A OUTPUT -p icmp -d {ip} -j DROP")
        os.system(f"sudo iptables -A INPUT -p icmp -s {ip} -j DROP")
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        os.system(f"sudo iptables -A OUTPUT -d {ip} -j DROP")
        log_event(f"[✓] Fully blocked IP {ip} (TCP/UDP/ICMP and general)")

    if port:
        os.system(f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP")
        os.system(f"sudo iptables -A OUTPUT -p tcp --dport {port} -j DROP")
        log_event(f"[✓] Applied system block for Port {port}")

    if protocol:
        proto = protocol.upper()
        if proto == "ICMP":
            os.system("sudo iptables -A INPUT -p icmp -j DROP")
            os.system("sudo iptables -A OUTPUT -p icmp -j DROP")
            log_event("[✓] Applied system block for ICMP protocol")
        elif proto == "TCP":
            os.system("sudo iptables -A INPUT -p tcp -j DROP")
            os.system("sudo iptables -A OUTPUT -p tcp -j DROP")
            log_event("[✓] Applied system block for TCP protocol")
        elif proto == "UDP":
            os.system("sudo iptables -A INPUT -p udp -j DROP")
            os.system("sudo iptables -A OUTPUT -p udp -j DROP")
            log_event("[✓] Applied system block for UDP protocol")
        elif proto == "DNS":
            os.system("sudo iptables -A INPUT -p udp --dport 53 -j DROP")
            os.system("sudo iptables -A OUTPUT -p udp --sport 53 -j DROP")
            os.system("sudo iptables -A INPUT -p tcp --dport 53 -j DROP")
            os.system("sudo iptables -A OUTPUT -p tcp --sport 53 -j DROP")
            log_event("[✓] Applied system block for DNS protocol (port 53)")
        elif proto == "ARP":
            os.system("sudo arptables -A INPUT -j DROP")
            os.system("sudo arptables -A OUTPUT -j DROP")
            log_event("[✓] Applied system block for ARP protocol (via arptables)")

def flush_iptables():
    os.system("sudo iptables -F")
    os.system("sudo iptables -X")
    os.system("sudo arptables -F")
    log_event("[✓] Flushed all iptables and arptables rules")

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if src_ip in rules["block_ips"] or dst_ip in rules["block_ips"]:
            log_event(f"[BLOCKED IP] {packet.summary()}")
            return

    if packet.haslayer(TCP) or packet.haslayer(UDP):
        transport = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        if transport.sport in rules["block_ports"] or transport.dport in rules["block_ports"]:
            log_event(f"[BLOCKED PORT] {packet.summary()}")
            return

    if "ICMP" in rules["block_protocols"] and packet.haslayer(ICMP):
        log_event(f"[BLOCKED ICMP] {packet.summary()}")
        return
    if "TCP" in rules["block_protocols"] and packet.haslayer(TCP):
        log_event(f"[BLOCKED TCP] {packet.summary()}")
        return
    if "UDP" in rules["block_protocols"] and packet.haslayer(UDP):
        log_event(f"[BLOCKED UDP] {packet.summary()}")
        return
    if "DNS" in rules["block_protocols"] and packet.haslayer(DNS):
        log_event(f"[BLOCKED DNS] {packet.summary()}")
        return
    if "ARP" in rules["block_protocols"] and packet.haslayer(ARP):
        log_event(f"[BLOCKED ARP] {packet.summary()}")
        return

def generate_capture_report(packets, filename="capture_summary.txt"):
    summary = defaultdict(int)
    ip_traffic = defaultdict(int)
    for pkt in packets:
        if pkt.haslayer(IP):
            ip_traffic[pkt[IP].src] += 1
            ip_traffic[pkt[IP].dst] += 1
        if pkt.haslayer(TCP):
            summary["TCP"] += 1
        elif pkt.haslayer(UDP):
            summary["UDP"] += 1
        elif pkt.haslayer(ICMP):
            summary["ICMP"] += 1
        elif pkt.haslayer(DNS):
            summary["DNS"] += 1
        elif pkt.haslayer(ARP):
            summary["ARP"] += 1
        else:
            summary["OTHER"] += 1
    with open(filename, "w") as f:
        f.write("==== Packet Capture Summary ====\n\n")
        f.write("Protocol Counts:\n")
        for proto, count in summary.items():
            f.write(f"  {proto}: {count}\n")
        f.write("\nTop IPs Involved:\n")
        for ip, count in sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:10]:
            f.write(f"  {ip}: {count} packets\n")
    log_event(f"[✓] Packet capture summary saved to {filename}")

def start_firewall():
    iface = input("Enter network interface to sniff (e.g. eth0, wlan0): ").strip()
    print(f"[✓] Sniffing on interface '{iface}'... Press Ctrl+C to stop.")
    packets = []
    try:
        packets = sniff(iface=iface, prn=packet_callback, store=True)
    except KeyboardInterrupt:
        print("[✓] Sniffing stopped by user.")
    finally:
        if packets:
            wrpcap("capture.pcap", packets)
            generate_capture_report(packets)
            print(f"[✓] Saved {len(packets)} packets to capture.pcap")
        else:
            print("[i] No packets captured.")

def view_iptables():
    print("\n========== IPTABLES RULES ==========\n")
    os.system("sudo iptables -L -n -v")
    print("\n========== ARPTABLES RULES ==========\n")
    os.system("sudo arptables -L -v")

# === Validation Functions ===

def get_valid_ip(prompt="Enter a valid IP address: "):
    while True:
        ip = input(prompt).strip()
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            print("[!] Invalid IP format. Try again.")

def get_valid_port(prompt="Enter a port (1-65535): "):
    while True:
        try:
            port = int(input(prompt))
            if 1 <= port <= 65535:
                return port
            else:
                print("[!] Port must be between 1 and 65535.")
        except ValueError:
            print("[!] Invalid input. Enter a number.")

def get_valid_protocol(prompt="Enter protocol to block (ICMP/TCP/UDP/DNS/ARP): "):
    valid_protocols = {"ICMP", "TCP", "UDP", "DNS", "ARP"}
    while True:
        proto = input(prompt).strip().upper()
        if proto in valid_protocols:
            return proto
        else:
            print(f"[!] Invalid protocol. Choose from: {', '.join(valid_protocols)}")

def get_menu_choice(prompt, choices):
    while True:
        choice = input(prompt).strip()
        if choice in choices:
            return choice
        print("[!] Invalid choice. Try again.")

# === Main Menu ===

def show_menu():
    print("""
========== Personal Firewall ==========
1. View Rules
2. Add IP to Block
3. Add Port to Block
4. Add Protocol to Block (ICMP, TCP, UDP, DNS, ARP)
5. View iptables & arptables Rules
6. Clear All Rules and Flush iptables
7. Apply System Rule (IP/Port)
8. Start Firewall Sniffer
0. Exit
""")

def main():
    global rules
    print_banner()
    rules = load_rules()
    while True:
        show_menu()
        choice = get_menu_choice("Choice: ", [str(i) for i in range(9)])
        if choice == "1":
            print(json.dumps(rules, indent=4))
        elif choice == "2":
            ip = get_valid_ip()
            if ip not in rules["block_ips"]:
                rules["block_ips"].append(ip)
                apply_iptables_rule(ip=ip)
                save_rules()
                log_event(f"[✓] Manually added IP {ip} to block list")
            else:
                print("[i] IP already in list.")
        elif choice == "3":
            port = get_valid_port()
            if port not in rules["block_ports"]:
                rules["block_ports"].append(port)
                apply_iptables_rule(port=port)
                save_rules()
                log_event(f"[✓] Manually added Port {port} to block list")
            else:
                print("[i] Port already in list.")
        elif choice == "4":
            proto = get_valid_protocol()
            if proto not in rules["block_protocols"]:
                rules["block_protocols"].append(proto)
                save_rules()
                apply_iptables_rule(protocol=proto)
                log_event(f"[✓] Protocol {proto} added to block list and system rules applied")
            else:
                print("[i] Protocol already in list.")
        elif choice == "5":
            view_iptables()
        elif choice == "6":
            flush_iptables()
            rules = {"block_ips": [], "block_ports": [], "block_protocols": []}
            save_rules()
            log_event("[✓] All rules cleared")
        elif choice == "7":
            mode = get_menu_choice("Block by:\n1. IP\n2. Port\nChoice: ", ["1", "2"])
            if mode == "1":
                ip = get_valid_ip()
                if ip not in rules["block_ips"]:
                    rules["block_ips"].append(ip)
                    save_rules()
                apply_iptables_rule(ip=ip)
            elif mode == "2":
                port = get_valid_port()
                if port not in rules["block_ports"]:
                    rules["block_ports"].append(port)
                    save_rules()
                apply_iptables_rule(port=port)
        elif choice == "8":
            start_firewall()
        elif choice == "0":
            print("Exiting...")
            break

if __name__ == "__main__":
    main()


