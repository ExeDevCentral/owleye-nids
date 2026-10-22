<div align="center">

# OwlEye NIDS • Low-Level Network Observability
### *Kernel-Level Raw Socket Sniffing, Scapy Packet Parsing & Real-Time Security Telemetry*

[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scapy Telemetry](https://img.shields.io/badge/Sniffing-Scapy_Low--Level-red?style=for-the-badge)](https://scapy.net/)
[![Threat Detection](https://img.shields.io/badge/Security-SYN_Flood_%7C_PortScan-orange?style=for-the-badge)](https://github.com/ExeDevCentral)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

<p align="center">
  A lightweight, real-time network security monitoring utility that converts raw Ethernet/IP/TCP/UDP/ICMP frames into structured telemetry, flagging anomalous connection bursts and scanning behaviors in real time.
</p>

</div>

---

## 🔍 Key Capabilities

- **Low-Level Socket Sniffing:** Uses Scapy's high-efficiency packet filter to capture real-time raw network streams.
- **Real-Time Anomaly Detection:** Built-in threshold trackers for SYN burst floods, port discovery scans, and unexpected ICMP ping storms.
- **Terminal Observability Dashboard:** Colorized, live-updating CLI dashboard (`net_lowlevel_dashboard.py`) for instantaneous threat visibility.
- **JSON Telemetry Streaming:** Formats captured security metadata into JSON Lines for external SIEM integration.

---

## 🚀 Execution & Usage

```bash
# Clone the repository
git clone https://github.com/ExeDevCentral/owleye-nids.git
cd owleye-nids

# Install dependencies
pip install scapy

# Run monitor (requires root privileges for raw socket access)
sudo python3 net_lowlevel_monitor.py

# Run dashboard
python3 net_lowlevel_dashboard.py
```

---

## 👨‍💻 Author

**Exequiel Echevarria**
- GitHub: [@ExeDevCentral](https://github.com/ExeDevCentral)
