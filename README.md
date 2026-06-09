# 🛡️ NetSniper

![NetSniper](https://img.shields.io/badge/NetSniper-Network%20Intelligence-red?style=for-the-badge)
![Bash](https://img.shields.io/badge/Bash-CLI%20Tool-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-blue?style=for-the-badge)

## Network Reconnaissance & Exposure Intelligence Engine

---

# 📌 DESCRIPTION

NetSniper is a Bash-based network reconnaissance and exposure intelligence engine designed to transform raw scan data into structured, actionable security insights. Instead of simply presenting nmap output, NetSniper performs device fingerprinting, risk scoring, and vulnerability-oriented analysis to prioritize real-world exposure across a network.

The tool processes scan data through a modular pipeline to convert raw network information into structured intelligence that can be used for security analysis, reporting, or automation.

NetSniper also supports optional integration with Greenbone Vulnerability Management (GVM). High-risk targets identified during local scanning can be automatically imported into Greenbone as scan tasks for deeper vulnerability assessment.

---

# ⚙️ INSTALLATION

```bash
git clone https://github.com/parkerlee07/NetSniper.git
cd NetSniper
chmod +x netsniper.sh
```
#Install dependencies
```
sudo apt install nmap jq
```
#Optional (for Greenbone integration)
```
sudo apt install gvm
sudo gvm-setup
sudo gvm-check-setup
sudo gvm-start
```
# Quick Start

```
./netsniper.sh
```
<p align="center">
  <img src="Images/Startup.gif" alt="NetSniper Demo">
</p>

## 📁 OUTPUT STRUCTURE

All scans generate timestamped outputs:

```text
~/NetSniper/
├── discovery/
├── scans/
├── targets/
├── reports/
├── analysis/
├── config/
└── netsniper.conf
```

## 🧾 TEXT FILE ANALYSIS OUTPUT

Each host is analyzed and scored based on exposed services.

```text
HOST: 192.168.1.15
DEVICE TYPE: Windows Host
SEVERITY: CRITICAL
SCORE: 10

Risk Findings:
SMB exposed
RDP exposed
```
## 📦 JSON FILE ANALYSIS OUTPUT

Machine-readable output for automation and pipelines.

```json
{
    "host": "192.168.1.10",
    "device_type": "Windows Server",
    "severity": "High",
    "score": 87,
    "scanner_version": "v1.2",
    "timestamp": "2026-05-29T18:00:00Z",
    "findings": [
        {
            "id": "SMB-001",
            "name": "SMB Signing Disabled",
            "service": "SMB",
            "port": 445,
            "score": 9,
            "evidence": "Message signing not required"
        }
    ]
}
```


## ⚠️ DISCLAIMER

NetSniper is provided for educational and authorized security testing purposes only.

This tool must only be used on systems for which you have explicit authorization.

The author assumes no responsibility for misuse, damage, or illegal activity resulting from the use of this software.

## ☕ Support Development

If NetSniper is useful in your security workflow, you can support continued development here:

- Buy Me a Coffee: https://buymeacoffee.com/

