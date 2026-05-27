# 🛡️ NetSniper Usage Guide

## 🚀 EXECUTION

Run NetSniper using:

```
./netsniper.sh
```

After execution, NetSniper launches an interactive CLI menu:

```
1) Discover Hosts
2) Fast Scan
3) Extract High Risk
4) Import to Greenbone
5) Run FULL Pipeline
6) Show High Risk Targets
7) Generate Report
8) Analyze Hosts
0) Exit
```

<details> <summary><b>1) Discover Hosts</b></summary>

Performs network discovery and identifies live hosts on the target subnet.

</details> <details> <summary><b>2) Fast Scan</b></summary>

Runs a fast Nmap scan against discovered hosts to enumerate open ports and services.

</details> <details> <summary><b>3) Extract High Risk</b></summary>

Filters scan results for hosts exposing high-risk or commonly exploited services.

</details> <details> <summary><b>4) Import to Greenbone</b></summary>

Imports high-risk hosts into Greenbone Vulnerability Management (GVM) as scan targets for deeper analysis.

</details> <details> <summary><b>5) Run FULL Pipeline</b></summary>

Executes the full automated workflow:

Discovery → Scanning → Analysis → Reporting
</details> <details> <summary><b>6) Show High Risk Targets</b></summary>

Displays previously identified high-risk hosts from scan results.

</details> <details> <summary><b>7) Generate Report</b></summary>

Generates a structured Markdown report including:

- Host summary
- Port statistics
- High-risk breakdown
- Full scan overview
</details> <details> <summary><b>8) Analyze Hosts</b></summary>

Runs exposure analysis and produces:

- Device classification
- Risk scoring system
- Structured JSON output
- Human-readable findings
</details>
