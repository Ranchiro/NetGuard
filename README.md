# 🛡️ NetGuard

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![ML](https://img.shields.io/badge/ML-Powered-orange.svg)

**Advanced Network Intrusion Detection System (NIDS)** with ML-powered threat detection, real-time packet analysis, and interactive dashboard.

## ✨ Features

- 🔍 **Deep Packet Inspection** - Protocol analysis for TCP, UDP, ICMP, HTTP, DNS, TLS
- 🤖 **ML-Based Detection** - Anomaly detection using statistical analysis and z-scores
- 🚨 **Signature Matching** - Pre-built rules for SQL injection, XSS, shell commands
- 📊 **Real-time Monitoring** - Live traffic statistics and flow analysis
- 🛑 **Auto-Blocking** - Automatic IP blocking based on reputation scores
- 📝 **Comprehensive Logging** - Detailed alert history and threat reports

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Ranchiro/NetGuard.git
cd NetGuard

# Install dependencies
pip install -r requirements.txt
```

## 📖 Usage

### Basic Packet Analysis
```python
from netguard.packet_analyzer import PacketAnalyzer, DeepPacketInspector

# Initialize analyzer
analyzer = PacketAnalyzer()
dpi = DeepPacketInspector()

# Analyze traffic
packet = analyzer.analyze_packet(raw_data)
app_info = dpi.inspect(packet)

# Get statistics
stats = analyzer.get_statistics()
print(f"Packets: {stats['total_packets']}, Flows: {stats['active_flows']}")
```

### Threat Detection
```python
from netguard.threat_detector import ThreatDetector, ThreatLevel

# Initialize detector
detector = ThreatDetector(enable_anomaly=True)

# Add custom signature
from netguard.threat_detector import ThreatSignature
custom_sig = ThreatSignature(
    id='CUSTOM001',
    name='Custom Attack',
    description='Custom pattern detection',
    level=ThreatLevel.HIGH,
    pattern=r'malicious_pattern'
)
detector.add_signature(custom_sig)

# Analyze for threats
alerts = detector.analyze(packet)
for alert in alerts:
    print(f"[{alert.level.name}] {alert.description}")
```

## 📁 Project Structure

```
NetGuard/
├── netguard/
│   ├── packet_analyzer.py    # Deep packet inspection
│   └── threat_detector.py    # ML threat detection
├── requirements.txt          # Dependencies
├── LICENSE                   # MIT License
└── README.md                 # Documentation
```

## 🔒 Security Features

| Feature | Description |
|---------|-------------|
| Signature Detection | Pre-built rules for common attacks |
| Anomaly Detection | Statistical z-score based detection |
| IP Reputation | Automatic threat scoring per IP |
| Auto-Blocking | Block high-risk IPs automatically |
| Flow Analysis | Track network conversations |

## 🤝 Contributing

Contributions welcome! Feel free to:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## 👨‍💻 Author

**Ruchir Ganatra** - [@Ranchiro](https://github.com/Ranchiro)

---
⭐ Star this repo if you find it useful!
