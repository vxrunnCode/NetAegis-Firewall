
# 🔥 NetAegis – Python-based Personal Firewall for Kali Linux

NetAegis is a powerful and interactive personal firewall tool developed in Python. It allows users to monitor, filter, block, and log suspicious or unwanted network traffic. Built specifically for **Kali Linux environments**, it leverages `iptables`, `arptables`, and `Scapy` to provide in-depth packet control and auditing functionality — all from a terminal interface.

---

## 📌 Project Highlights

- 🔐 **Real-time firewall control** (block by IP, port, or protocol)
- 📦 **Generates `.pcap` files** compatible with Wireshark for traffic auditing
- 🧠 **Smart input validation** (IP, port, protocol) to prevent errors
- 🛠️ All essential **firewall actions in one interface**
- 📊 **Automatic traffic summaries** with protocol/IP stats
- 💾 **Persistent rule management** via `rules.json`
- 🧾 **Event logging** with time-stamped actions

---

## ⚙️ Technologies Used

- **Python 3**
- **Scapy** (for packet sniffing and inspection)
- **iptables & arptables** (Linux-level traffic control)
- **Kali Linux OS** (recommended platform)

---

## ⚠️ Root Access Required

To work with packet capturing and modify system firewall settings, **NetAegis requires root privileges**.

Use the following command to run:

```bash
sudo python3 netaegis.py
```

> Without `sudo`, the firewall will not be able to generate `.pcap` capture files or apply firewall rules correctly.

---

## 📁 Auto-Generated Files

The following files will be **automatically created when you initialize and run the project**:

| File Name             | Description                                        |
|-----------------------|----------------------------------------------------|
| `rules.json`          | Stores all block rules (IPs, ports, protocols)     |
| `firewall_log.txt`    | Log of all events, blocks, actions                 |
| `capture.pcap`        | Saved packet capture (open in Wireshark)          |
| `capture_summary.txt` | Text summary of the captured packets              |

---

## 📦 Required Python Libraries

```
scapy
pyfiglet
```

---

## 🧰 Required Kali Linux Packages

Ensure these tools are pre-installed (default in Kali Linux):

- `iptables`
- `arptables`

Install them if missing:

```bash
sudo apt install iptables arptables
```

---

## ▶️ How to Use

### 1. Clone the Project
```bash
git clone https://github.com/vxrunnCode/NetAegis-Firewall.git
cd NetAegis-Firewall
```

### 2. Install Python Requirements
```bash
pip install -r requirements.txt
```

### 3. Run the Firewall Tool
```bash
sudo python3 netaegis.py
```

### 4. Use the Interactive Menu

```
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
```

---

## 👨‍💻 Author

**Varun Darji**  
Elevate Labs Internship Project – Python Network Security Tool

---

## ⚠️ Disclaimer

This tool is for **educational and ethical use only**. Do not run it on networks you do not own or have permission to inspect.

---

