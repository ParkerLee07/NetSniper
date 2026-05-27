<h1>NetSniper</h1>
NetSniper is a Bash-based network reconnaissance and exposure intelligence engine designed to transform raw scan data into structured, actionable security insights. Instead of simply presenting nmap output, NetSniper performs device fingerprinting, risk scoring, and vulnerability-oriented analysis to prioritize real-world exposure across a network.

The tool follows a modular pipeline approach—discovery, scanning, analysis, and reporting—producing both human-readable reports and machine-readable JSON outputs for further automation or integration.

NetSniper also supports optional integration with Greenbone Vulnerability Management (GVM). High-risk targets identified during local scanning can be automatically imported into Greenbone as scan tasks, enabling deeper vulnerability assessment workflows while keeping NetSniper focused on fast reconnaissance and exposure intelligence.

<h2>INSTALLATION</h2>

git clone https://github.com/YOUR_USERNAME/netsniper.git
cd netsniper
chmod +x netsniper.sh

#Install dependencies

sudo apt install nmap jq

#Optional (for Greenbone integration)

gvm-cli

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

