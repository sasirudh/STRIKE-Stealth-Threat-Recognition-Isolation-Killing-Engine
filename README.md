# 🛡️ AEGIS - Advanced Threat Detection System

**AEGIS** is a professional-grade, multi-layer malware detection system designed to identify threats through **Static Analysis**, **Dynamic Behavioral Monitoring**, and **Network Traffic Forensics**.

Built with a specialized **Cybersecurity Theme** GUI, it combines real-time hardware monitoring with advanced Machine Learning models to provide a comprehensive security posture.

---

## 🚀 Features

### 1. ◈ Static Analysis Layer
* **Signature & ML Scanning**: Detects known threats using signatures (e.g., EICAR) and zero-day threats using an **EMBER-based LightGBM model**.
* **File Forensics**: Extracts and displays PE file headers and feature vectors.
* **Quarantine Management**: Securely isolates detected malicious files to a quarantine vault.

### 2. ◆ Dynamic Analysis Layer
* **Real-Time Process Monitor**: Tracks active processes with live metrics (CPU%, Memory%, PID, Status).
* **Behavioral Detection**: Uses a **GRU/LSTM Deep Learning model** to analyze process behavior sequences for anomalies.
* **Hybrid Simulation**: Capable of injecting simulated malware behaviors from CSV data to test detection logic.

### 3. ◇ Network Analysis Layer
* **Live Traffic Inspection**: Monitors bandwidth usage, active connections, and remote IP addresses in real-time.
* **Intrusion Detection System (IDS)**: Analyzes flow features using an **ONNX model** to identify malicious traffic patterns.
* **C2 Communication Detection**: Flags suspicious connections to known Command & Control servers.

### 4. ⬡ Threat Intelligence & Visualization
* **Attack Graph**: Interactive **Matplotlib** visualization mapping infected processes to their destination IPs (C2 Servers).
* **Unified Dashboard**: Calculates an **Ensemble Risk Score** by weighing inputs from all three layers.
* **Alert Logs**: Detailed, timestamped logs of all detected threats with export capabilities.

---

## 🛠️ Installation

### Prerequisites
* Python 3.8+
* Admin/Root privileges (required for deep process and network monitoring)

### 1. Clone the Repository
```bash
git clone [https://github.com/yourusername/aegis-detector.git](https://github.com/yourusername/aegis-detector.git)
cd aegis-detector
