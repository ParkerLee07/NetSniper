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
git clone https://github.com/parkerlee07/netsniper.git
cd netsniper
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
<h2>Example Outputs</h2>

#Text File Analysis output

HOST: 192.168.1.15

DEVICE TYPE: Windows Host

SEVERITY: CRITICAL

SCORE: 10

Risk Findings

SMB exposed

RDP exposed

#JSON File Analysis output

{

  "host": "192.168.1.15",
  
  "device_type": "Windows Host",
  
  "severity": "CRITICAL",
  
  "score": 10,
  
  "findings": "SMB exposed\nRDP exposed"
  
}

<h2>Output Structure</h2>

All scans generate timestamped outputs:

~/netsniper/

├── scans/

├── targets/

├── reports/

└── analysis_YYYYMMDD-HHMMSS.json


<h2>⚠️ Disclaimer</h2>

NetSniper is intended for:

+ Authorized security testing
+ Lab environments
+ Defensive security research

Do not use against systems without explicit permission.

