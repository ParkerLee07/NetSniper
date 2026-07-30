# 🧠 NetSniper Architecture

---

## 🏗️ SYSTEM OVERVIEW

NetSniper follows a modular pipeline architecture designed to separate raw network data collection from intelligence generation.

This design allows NetSniper to operate in two roles:
- A standalone reconnaissance tool
- A preprocessing and triage layer for vulnerability management systems

---

## 🔄 ARCHITECTURE FLOW

Discovery → Service Scanning → Analysis Engine → Reporting → (Optional) Greenbone Integration

---

## ⚙️ PIPELINE STAGES

### 🔎 1) Discovery Layer

The Discovery stage identifies active hosts on the target network.

It is responsible for:
- Detecting live hosts
- Performing network enumeration
- Building an initial target list

---

### ⚡ 2) Service Scan Layer

The Service Scan stage performs fast enumeration of services and ports using Nmap.

It is responsible for:
- Detecting open ports
- Identifying running services
- Collecting service exposure data

---

### 🧠 3) Analysis Engine

The Analysis Engine converts raw scan output into structured intelligence.

It is responsible for:
- Device classification (e.g., Windows Host, Web Server, Printer)
- Risk scoring based on exposed services
- Severity assignment (LOW, MEDIUM, HIGH, CRITICAL)
- Exposure analysis of vulnerable services

---

### 📊 4) Reporting Layer

The Reporting layer generates structured outputs for both humans and machines.

It produces:
- Human-readable Markdown reports
- Machine-readable JSON analysis files
- Timestamped outputs for tracking and forensics

---

### 🔗 5) Greenbone Integration (Optional)

NetSniper can integrate with Greenbone Vulnerability Management (GVM) to extend analysis.

It enables:
- Importing high-risk hosts into GVM
- Creating automated scan tasks
- Enabling deeper vulnerability assessment workflows

---

## 🧩 DESIGN PRINCIPLES

NetSniper is built on the principle of separating **data collection** from **intelligence processing**.

This architecture provides:

- Faster and more efficient scanning workflows
- Modular expansion of analysis logic
- Easy integration with external security platforms
- Clear separation between reconnaissance and reporting layers

---

## 🧠 FINAL PIPELINE MODEL

```
[ Discovery ]
      ↓
[ Service Scanning ]
      ↓
[ Analysis Engine ]
      ↓
[ Reporting Layer ]
      ↓
[ Optional Greenbone Integration ]
```
