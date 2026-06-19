# NetSniper Device Taxonomy

NetSniper v1.7 introduces a formal device taxonomy for explainable classification.

The goal is not to classify every host aggressively. The goal is to classify hosts only when evidence is strong enough, keep weak results in review, and avoid false confidence.

## Top-Level Categories

### Network Infrastructure

- Router / Gateway
- Switch
- Wireless Access Point
- DNS / DHCP Infrastructure

### Server Infrastructure

- Linux Server
- Windows Server
- Active Directory / Domain Controller
- Database Server
- Web Server / Web Application Host
- Container Infrastructure
- Virtualization Host

### End-User Devices

- Workstation
- Laptop
- Mobile Device
- Unknown Client Device

### IoT / Embedded

- IP Camera / NVR
- Network Printer / MFP
- Smart TV / Media Device
- NAS / Storage Appliance
- VoIP Phone
- UPS / Power Device
- Building Automation / ICS-like Device

### Security / Monitoring

- Firewall / UTM
- IDS / Sensor
- VPN Appliance

### Unknown / Ambiguous

- Unknown
- Ambiguous Device

## Classification Principles

1. Prefer "Unknown" over a confident wrong answer.
2. Port-only evidence is weak.
3. Multiple independent evidence sources are stronger than one source.
4. Contradictions should downgrade confidence or trigger review.
5. Every classification must be explainable.
6. Every classification should include evidence, confidence, confidence band, decision, and SIEM action.

## Confidence Bands

| Band | Score Range | Meaning |
|---|---:|---|
| weak | 1-39 | Insufficient confidence; analyst review recommended |
| possible | 40-69 | Plausible classification but not final |
| strong | 70-89 | Strong classification |
| high | 90-100 | Very strong classification |

## Classification Decisions

| Decision | Meaning |
|---|---|
| unknown | No useful classification |
| possible | Some evidence exists but not enough for strong classification |
| classified | Strong enough to use as the primary type |
| contradiction_review | Conflicting evidence requires review |

## SIEM Actions

| SIEM Action | Meaning |
|---|---|
| display_only | Show the classification but do not alert |
| review_queue | Put the asset into analyst review |
| contradiction_review | Put the asset into contradiction review |
| alert_candidate | Classification may influence alert/risk logic |
