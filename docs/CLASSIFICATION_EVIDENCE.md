# NetSniper Classification Evidence Model

NetSniper v1.7 uses weighted evidence to classify devices.

Each device type should define:

- positive evidence
- negative evidence
- contradiction rules
- evidence reliability
- confidence thresholds
- SIEM action mapping

## Evidence Reliability

### High Reliability

High-reliability evidence should have the most weight.

Examples:

- Protocol-specific validation
- Product-specific service banner
- TLS certificate subject or issuer matching the device role
- Multiple matching services supporting the same role
- Strong SMB, SNMP, IPP, RTSP, or HTTP fingerprint

### Medium Reliability

Medium-reliability evidence is useful but should not stand alone unless combined with other evidence.

Examples:

- Vendor OUI
- HTTP title
- Nmap product guess
- Service name
- Hostname pattern

### Low Reliability

Low-reliability evidence should usually create weak or possible classifications only.

Examples:

- Port-only match
- Generic HTTP service
- Generic SSH service
- Generic unknown TCP service

## Contradiction Handling

Contradictions should reduce confidence or force contradiction review.

Example:

Candidate: Network Printer / MFP

Positive evidence:

- tcp/9100 JetDirect
- tcp/631 IPP

Contradicting evidence:

- tcp/88 Kerberos
- tcp/389 LDAP
- tcp/445 SMB with domain hints

Expected result:

- Do not confidently classify as a printer.
- Move to contradiction_review or ambiguous infrastructure.

## Minimum Expected Output Fields

Each classified host should eventually expose:

- primary_type
- category
- confidence
- confidence_band
- decision
- siem_action
- evidence[]
- contradictions[]
- secondary_candidates[]
- explanation
