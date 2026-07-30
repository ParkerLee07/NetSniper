# NetSniper v1.5 Classification Taxonomy

NetSniper v1.5 expands the evidence-based device classification engine introduced in v1.4.0.

The purpose of this taxonomy is to define stable operator-facing device categories before changing the scoring engine. Categories should only be added when NetSniper can collect useful evidence for them from ports, service names, banners, hostnames, MAC/OUI hints, protocol hints, or downstream scan artifacts.

## Classification Principle

NetSniper should classify the strongest supported device role, not simply the presence of a management interface.

Core rule:

- Web Interface = evidence.
- Web Server / Web Application Host = device role.

For example:

- Port 80 or 443 alone should not automatically classify a host as a Web Server.
- Printers, routers, cameras, NAS devices, access points, hypervisors, and security appliances often expose web interfaces.
- HTTP/HTTPS should be treated as evidence for a Web Interface unless additional evidence supports Web Server / Web Application Host.

## Confidence Model

NetSniper v1.5 keeps the v1.4 classification model:

- `primary_type`
- `confidence`
- `confidence_label`
- `decision`
- `method`
- `evidence`
- `contradictions`
- `secondary_candidates`

The classifier should prefer conservative output over overconfident guesses.

Suggested interpretation:

- `0`: Unknown
- `1-39`: weak evidence
- `40-69`: possible classification
- `70+`: classified

## v1.5 Device Categories

### Router / Gateway

A network edge or routing device.

Strong evidence examples:

- Default gateway IP.
- DNS, DHCP, NAT, or UPnP gateway behavior.
- Router/gateway vendor hints.
- HTTP title or banner referencing router, gateway, firewall, modem, or broadband device.

Weak evidence examples:

- Web interface only.
- Common management ports without routing hints.

### Wireless Access Point

A wireless infrastructure device.

Strong evidence examples:

- Vendor hints from known wireless/AP manufacturers.
- HTTP title or banner referencing AP, wireless controller, SSID, WLAN, or access point.
- Management services associated with wireless infrastructure.

Weak evidence examples:

- Web interface only.
- Generic network device banner.

### Managed Switch / Network Infrastructure

A switch, controller, or network management device.

Strong evidence examples:

- SNMP, LLDP/CDP hints if available.
- HTTP title or banner referencing switch, switching, controller, or network management.
- Known switch or network infrastructure vendor hints.

Weak evidence examples:

- SSH/HTTP management ports alone.

### Network Printer / Multifunction Printer

A printer or multifunction device.

Strong evidence examples:

- TCP/9100 raw printing.
- IPP on TCP/631.
- LPD on TCP/515.
- Printer vendor hints.
- HTTP title or banner referencing printer, print server, JetDirect, LaserJet, OfficeJet, Brother, Canon, Epson, Xerox, Ricoh, Kyocera, or similar.

Contradiction examples:

- RTSP/camera evidence.
- Database-only evidence.
- Windows domain service evidence without print evidence.

### IP Camera / NVR

A camera, DVR, or network video recorder.

Strong evidence examples:

- RTSP on TCP/554.
- ONVIF-related service hints.
- HTTP title or banner referencing camera, NVR, DVR, surveillance, video, Hikvision, Dahua, Reolink, Axis, Amcrest, or similar.
- Camera vendor hints.

Contradiction examples:

- Printer-specific ports.
- Database-only evidence.
- Windows workstation/server evidence.

### NAS / File Server

A storage appliance or file-serving host.

Strong evidence examples:

- SMB/NFS/AFP service combination.
- HTTP title or banner referencing NAS, storage, Synology, QNAP, TrueNAS, FreeNAS, Asustor, or file station.
- Multiple file-sharing services with storage vendor hints.

Weak evidence examples:

- SMB alone.
- HTTP management interface alone.

### VoIP Phone / PBX

A voice endpoint, SIP device, or PBX.

Strong evidence examples:

- SIP on TCP/UDP 5060 or 5061.
- RTP-related service hints.
- HTTP title or banner referencing phone, VoIP, PBX, Asterisk, FreePBX, Yealink, Polycom, Grandstream, Cisco phone, or similar.

Weak evidence examples:

- Web interface only.

### UPS / Power Device

A UPS, PDU, or power management appliance.

Strong evidence examples:

- HTTP title or banner referencing UPS, PDU, APC, Eaton, CyberPower, Tripp Lite, power management, or network management card.
- SNMP and power-device vendor hints.

Weak evidence examples:

- Web interface only.

### Security Appliance

A firewall, IDS/IPS, VPN appliance, or security gateway.

Strong evidence examples:

- HTTP title or banner referencing firewall, VPN, security gateway, Fortinet, SonicWall, Palo Alto, pfSense, OPNsense, Sophos, WatchGuard, or similar.
- VPN-related services paired with security appliance vendor/title hints.

Weak evidence examples:

- HTTPS management alone.

### Hypervisor / Virtualization Host

A virtualization platform or host.

Strong evidence examples:

- VMware, ESXi, vCenter, Proxmox, Hyper-V, Xen, oVirt, or virtualization-specific banners.
- Management ports associated with hypervisor platforms plus matching service/product evidence.

Weak evidence examples:

- SSH/HTTPS only.

### Container Infrastructure

A Docker, Kubernetes, Portainer, or container management endpoint.

Strong evidence examples:

- Docker API.
- Kubernetes API.
- Portainer service.
- Container runtime or orchestration banner/title.
- Known container management ports plus matching service evidence.

Weak evidence examples:

- Port 9443/9000 without service/title evidence.

### Database Server

A host exposing database services.

Strong evidence examples:

- MySQL/MariaDB, PostgreSQL, MongoDB, Redis, MSSQL, Oracle, Elasticsearch, Cassandra, or similar database service detection.
- Multiple database services.

Weak evidence examples:

- Unknown high port alone.

### Windows Workstation

A likely Windows client endpoint.

Strong evidence examples:

- Windows SMB/NetBIOS/RPC evidence.
- Workstation-like hostname.
- RDP with workstation-style SMB evidence.
- Windows product hints without server-specific role evidence.

Weak evidence examples:

- SMB alone.

### Windows Server

A likely Windows server endpoint.

Strong evidence examples:

- Windows SMB/RPC plus server role hints.
- Domain controller indicators.
- IIS plus Windows service evidence.
- RDP plus server hostname/service hints.

Weak evidence examples:

- RDP alone.
- SMB alone.

### Linux Server

A likely Linux server endpoint.

Strong evidence examples:

- SSH plus Linux/OpenSSH product evidence.
- Linux-specific banners.
- Server services such as web, database, NFS, Docker, or admin interfaces with Linux evidence.

Weak evidence examples:

- SSH alone.

### Web Server / Web Application Host

A host whose primary role appears to be serving web content or applications.

Strong evidence examples:

- HTTP/HTTPS plus web server product evidence such as Apache, nginx, Caddy, lighttpd, IIS, Tomcat, Jetty, Gunicorn, Node, Express, Django, Flask, Rails, or similar.
- Web application title/banner without stronger device-role evidence.
- Multiple web services where no appliance/device role is suggested.

Weak evidence examples:

- Port 80/443 alone.
- Login page alone.
- Generic web UI on a device that has stronger printer/camera/router/NAS evidence.

### Development / Admin Interface

A host exposing development, debug, CI/CD, or administrative tooling.

Strong evidence examples:

- Jenkins, GitLab, Gitea, Grafana, Prometheus, Kibana, phpMyAdmin, Adminer, Jupyter, Cockpit, Webmin, Portainer, or similar.
- Development/admin tool titles or service names.

Weak evidence examples:

- High-numbered HTTP service alone.

### IoT / Embedded Device

A low-confidence embedded or appliance-like device that does not fit a stronger category.

Strong evidence examples:

- Embedded web server banners.
- IoT vendor hints.
- Minimal service set with embedded vendor/title hints.
- Device-style hostname and web UI evidence.

Weak evidence examples:

- MAC vendor only.
- Web interface only.

### Client Device

A likely user endpoint such as laptop, desktop, phone, or tablet.

Strong evidence examples:

- Client-style hostname.
- Vendor hints and lack of server/service role.
- mDNS/NetBIOS hints if available.

Weak evidence examples:

- MAC vendor only.
- Host responds to ping but has no open ports.

### Unknown / Ambiguous

Used when evidence is absent, weak, contradictory, or insufficient for a stable primary classification.

Unknown / Ambiguous is preferable to a confident but unsupported label.
