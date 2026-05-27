# NetSniper
NetSniper is a Bash-based network reconnaissance and exposure intelligence engine designed to transform raw scan data into structured, actionable security insights. Instead of simply presenting nmap output, NetSniper performs device fingerprinting, risk scoring, and vulnerability-oriented analysis to prioritize real-world exposure across a network.

The tool follows a modular pipeline approach—discovery, scanning, analysis, and reporting—producing both human-readable reports and machine-readable JSON outputs for further automation or integration.

NetSniper also supports optional integration with Greenbone Vulnerability Management (GVM). High-risk targets identified during local scanning can be automatically imported into Greenbone as scan tasks, enabling deeper vulnerability assessment workflows while keeping NetSniper focused on fast reconnaissance and exposure intelligence.
