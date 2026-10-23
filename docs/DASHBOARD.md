# Network Anomaly Detection (NAD) — Dashboard & UI User Guide

A comprehensive, screen-by-screen guide to the Network Anomaly Detection Web User Interface, covering the **Network Anomaly Detection (NAD) SOC Console** and the **WebSec Security & Vulnerability Platform**.

---

## 🧭 Dashboard Architecture Overview

The frontend is a high-performance, dark-mode-first React 18 single-page application (SPA) styled with custom Tailwind CSS and CSS design tokens. It synchronizes state with the backend via a low-latency WebSocket connection (`ws://<HOST>:8000/ws`), receiving live sub-second packet stats, active flow counts, alert feeds, and agent heartbeats.

The interface is structured into two interconnected platforms:
1. **Network Anomaly Detection (NAD) SOC Console**: Real-time network anomaly detection, live packet capture, distributed telemetry agents, asset inventories, and threat intelligence.
2. **WebSec Platform**: Website security auditing, synthetic uptime probes, SSL/TLS certificate tracking, and HTTP vulnerability assessments.

Analysts can switch between both platforms instantly using the **Switch Platform** button in the sidebar or top navigation bar.

---

## 🛡️ Platform 1: Network Anomaly Detection SOC Console

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                               TOP NAVIGATION BAR                                │
│ [Logo] Mode: [Simulator / Host NIC / SPAN / Agents] [LEARNING MODE] [● LIVE]    │
├──────────────┬──────────────────────────────────────────────────────────────────┤
│   SIDEBAR    │                         KPI SUMMARY ROW                          │
│              │ [ Throughput ]  [ Active Flows ]  [ High/Critical ]  [ Conn PCs ]│
│ • Overview   ├──────────────────────────────────────────────────────────────────┤
│ • Alerts     │                                                                  │
│ • Connect    │                                                                  │
│ • Agents     │                       ACTIVE TAB VIEWPORT                        │
│ • Assets     │                                                                  │
│ • Network    │                                                                  │
│ • Threat     │                                                                  │
│              │                                                                  │
│ [Themes]     │                                                                  │
└──────────────┴──────────────────────────────────────────────────────────────────┘
```

---

### 1. Global Header & KPI Summary Bar

The top section of the dashboard is persistent across all tabs and provides immediate visibility into network health and system state:

#### Top Bar Indicators:
- **Active Ingestion Source**: Shows the current packet source (e.g. `● Simulator (High)`, `● Host NIC (eth0)`, `● Switch SPAN (eth1)`, or `● PCAP Replay`). Clicking the **Change** button opens the Connect & Ingest view.
- **Learning Baseline Mode**: Displays an orange `LEARNING BASELINE` badge when the system is in calibration mode, automatically discovering and whitelisting normal network behavior.
- **Platform Switcher**: Quick button (`Website Security Platform ➔`) to transition into the WebSec module.
- **Connection Heartbeat**: Displays green `● LIVE` when the WebSocket is streaming, or `CONNECTING…` if the server is offline or reconnecting.

#### KPI Metric Cards:
| KPI Card | Display Value | Subtitle | Meaning |
|---|---|---|---|
| **Throughput** | `PPS` (e.g. `1,250`) | Total Packets (e.g. `1.8M pkts`) | Current aggregate packet ingestion rate per second and total count. |
| **Active Flows** | Integer (e.g. `142`) | `5-tuple tracked` | Active conversations tracked by `(src_ip, dst_ip, src_port, dst_port, proto)`. |
| **High / Critical** | Integer (e.g. `3`) | Total Alerts (e.g. `48 total alerts`) | Unmitigated high and critical severity threats requiring immediate SOC attention. |
| **Connected PCs** | Count (e.g. `2 online`) | Registered nodes (e.g. `5 nodes`) | Live distributed remote computers actively streaming telemetry. Clicking opens the Agents page. |

---

### 2. Tab: Overview

The **Overview** tab serves as the primary command center for security analysts during active monitoring:

```
┌───────────────────────────────────────────────┬─────────────────────────┐
│           TRAFFIC THROUGHPUT (PPS)            │   PROTOCOL BREAKDOWN    │
│               [Time-Series Line Chart]        │      [Donut Chart]      │
├───────────────────────┬───────────────────────┼─────────────────────────┤
│      ATTACK MIX       │      TOP TALKERS      │      TOP OFFENDERS      │
│     [Bar Chart]       │  [Bandwidth by IP]    │  [Malicious Sources]    │
├───────────────────────┴───────────────────────┴─────────────────────────┤
│                          RECENT SECURITY ALERTS                         │
│                 [Interactive Live Threat Table & Filters]               │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Key Widgets:
1. **Traffic Throughput Chart (`TrafficChart.tsx`)**:
   - Real-time animated canvas graph plotting packet velocity over a sliding 60-second window.
   - Visual spikes highlight volumetric attacks (SYN floods, UDP floods, DDoS).
2. **Protocol Breakdown (`ProtocolBreakdown.tsx`)**:
   - Interactive donut chart showing Layer 4 distribution: TCP, UDP, ICMP, and Other protocols.
3. **Attack Mix Distribution (`AttackMix.tsx`)**:
   - Color-coded bar chart displaying the breakdown of detected threats (e.g., Port Scan, Brute Force, Log4Shell, SQLi, ML Anomaly).
4. **Top Talkers (`TopTalkers.tsx`)**:
   - Ranks the highest-bandwidth IP addresses by total bytes and packets transferred.
5. **Top Offenders (`TopOffenders.tsx`)**:
   - Highlights source IP addresses generating the largest volume of high-confidence security alerts.
6. **Live Alert Feed (`AlertPanel.tsx`)**:
   - Sub-second threat stream showing: **Timestamp**, **Threat Name**, **Severity Badge** (CRITICAL, HIGH, MEDIUM, LOW), **0–100 Threat Score**, **Source IP & Port**, **Destination IP & Port**, **MITRE ATT&CK Code**, and **Remediation Plan**.

---

### 3. Tab: Alerts

The **Alerts** tab provides an expanded, full-screen forensic view for incident response:

#### Features:
- **Instant Search Bar**: Filter alerts in real time by IP address, port, attack name, or MITRE code (e.g. `10.0.0.99`, `T1110`, `Log4Shell`).
- **Severity Filters**: Toggle between `ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` alerts.
- **One-Click Firewall Rule Generator**:
  - Clicking any alert's **Block IP** button opens a modal that generates copy-paste ready blocking commands tailored to your firewall:
    - **Linux `iptables`**: `sudo iptables -I INPUT -s <IP> -j DROP`
    - **Linux `nftables`**: `sudo nft add rule inet filter input ip saddr <IP> drop`
    - **Windows `netsh`**: `netsh advfirewall firewall add rule name="Block_<IP>" dir=in action=block remoteip=<IP>`
    - **Cisco IOS ACL**: `access-list 100 deny ip host <IP> any`
- **Audit Export**: Export all filtered alerts as structured JSON or CSV for compliance auditing or SIEM ingestion.

---

### 4. Tab: Connect & Ingest (`ConnectPage.tsx`)

The **Connect & Ingest** view is the control center for selecting how the system receives network traffic. It offers **5 selectable ingestion modes**:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SELECT INGESTION SOURCE                         │
│  [1. Simulator]  [2. This Computer]  [3. PCAP Replay]  [4. SPAN] [5. Agent]│
└─────────────────────────────────────────────────────────────────────────┘
```

#### Mode 1: Built-in Simulator
- **Purpose**: Demonstrations, offline training, and unit testing without physical network cables.
- **Controls**:
  - **Intensity Selector**: `Low` (~50 pps), `Medium` (~200 pps), `High` (~500 pps), `Stress` (~1,500+ pps).
  - **Attack Toggles**: Selectively enable or disable specific attack categories (*Scans, Floods, Brute Force, Web Payloads, Exfiltration*).

#### Mode 2: This Computer (Local Host Capture)
- **Purpose**: Sniff physical network adapters on the local machine.
- **Controls**:
  - **Interface Browser**: Lists all discovered host interfaces with status, IPv4 address, MAC address, and packets seen.
  - **10-Second Traffic Probe**: Click **Test Traffic** to sample any interface for 10 seconds and verify packet flow before activating.
  - **BPF Filter Expression**: Enter Berkeley Packet Filter rules (e.g., `not port 22 and not port 8000`).
  - **Learning Mode Toggle**: Check to run in baseline calibration mode.

#### Mode 3: Replay PCAP File
- **Purpose**: Forensics, incident replay, and compliance benchmark verification.
- **Controls**:
  - **File Uploader**: Drag and drop `.pcap` or `.pcapng` files up to 100MB.
  - **Speed Multiplier**: Choose playback rate: `Instant`, `1x (Real-time)`, `5x Speed`, or `10x Speed`.
  - **Playback Status**: Live progress bar showing packets injected and elapsed replay time.

#### Mode 4: Switch SPAN / Mirror Port
- **Purpose**: Enterprise monitoring of entire office buildings, server racks, or campus labs.
- **Controls**:
  - **Listening Interface**: Select the dedicated NIC connected to the switch mirror port.
  - **Configuration Guides**: Built-in tabs with copy-paste setup commands for **Cisco Catalyst**, **HP / Aruba**, **MikroTik RouterOS**, and **Linux Bridge**.

#### Mode 5: Remote Multi-Computer Agents
- **Purpose**: Ingest telemetry from distributed Windows and Linux computers across different subnets.
- **Controls**:
  - Summary of active agents and a direct button linking to the **Connected Computers** fleet manager.

---

### 5. Tab: Connected Computers (`AgentsPage.tsx`)

The **Connected Computers** tab provides centralized fleet management for all remote laboratory workstations and servers:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ FLEET OVERVIEW: [ 2 Online ]  [ 0 Offline ]  [ + Add New Computer ]     │
├─────────────────────────────────────────────────────────────────────────┤
│ NODE NAME       SITE          IP ADDRESS    OS          STATUS  ACTION  │
│ University-01   Lab 101       10.175.10.220 Windows 10  ● ONLINE [Revoke]│
│ University-02   CS Faculty    10.175.10.221 Ubuntu 24   ● ONLINE [Revoke]│
└─────────────────────────────────────────────────────────────────────────┘
```

#### Features:
- **Fleet Metrics**: Total registered agents, online nodes, aggregate telemetry rate.
- **"Add Computer" Onboarding Modal**:
  - Generates a cryptographically secure token (`agt_...`).
  - **Linux One-Liner**: Ready-to-copy `curl -sSL http://<SERVER>:8000/api/agents/install.sh | bash -s -- <TOKEN>`
  - **Windows PowerShell One-Liner**: Direct PowerShell execution command downloading the agent and starting telemetry streaming.
- **Live Node Grid**: Displays computer name, assigned site/department, host IP, detected operating system, packets streamed, and last heartbeat ping.
- **Token Revocation**: Click the trash icon to revoke a computer's token and immediately terminate its ingestion session.

---

### 6. Tab: Assets & Allowlist (`AssetsAllowlistPage.tsx`)

This view manages enterprise asset inventory and threat suppression rules:

#### Sub-Tab 1: Network Assets Inventory
- Automatically discovers and logs every IP and MAC address communicating on the network.
- Displays: **IP Address**, **MAC Address**, **Hostname**, **Operating System**, **Department**, **Owner**, **First Seen**, and **Last Active**.
- **Metadata Editing**: Click **Edit** to assign asset owners and departments (e.g. `Engineering Lab / Dr. Aris`).

#### Sub-Tab 2: Threat Allowlist (Suppression)
- Define trusted IP addresses or CIDR blocks (e.g. `192.168.1.50`, `10.10.0.0/16`) for vulnerability scanners, administrative jump-boxes, and monitoring probes.
- When an IP is on the allowlist, the correlation engine automatically bypasses alert generation, eliminating false positives while keeping flow logs intact.

---

### 7. Tab: Network

A focused network performance and traffic engineering view:
- **Full-Width Traffic Chart**: Detailed packet rate timeline.
- **Top Talkers Table**: Comprehensive ranking of the heaviest talkers on the network with protocol and port details.
- **Layer 4 Protocol Distribution**: TCP vs UDP vs ICMP volume breakdown.

---

### 8. Tab: Threat Intel (`ThreatMatrix.tsx`)

The **Threat Intel** tab maps all system detections directly to the international **MITRE ATT&CK Framework**:
- **Tactics Heatmap**: Highlights active detections across MITRE stages: *Reconnaissance, Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact*.
- **Detector Catalog**: Interactive table of all 30 detectors showing their heuristic trigger condition, sliding window, and remediation instructions.

---

## 🌐 Platform 2: WebSec Security & Vulnerability Platform

The **WebSec Platform** (`WebSecPlatform.tsx`) is a dedicated application within the suite focused on external web application posture, SSL/TLS certificates, and synthetic health monitoring.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                             WEBSEC COMMAND CONSOLE                              │
│ [WebSec]        [Target: https://university.edu]  [Security Grade: A] [Scan Now]│
├──────────────┬──────────────────────────────────────────────────────────────────┤
│   SIDEBAR    │                      POSTURE & AUDIT METRICS                     │
│ • Overview   │  [ Grade: A ]   [ TLS: 82 Days ]   [ Headers: 5/6 ]  [ Vulns: 1 ]│
│ • Targets    ├──────────────────────────────────────────────────────────────────┤
│ • Scanner    │                                                                  │
│ • Vulns      │                     WEBSEC ACTIVE VIEWPORT                       │
│ • TLS Audit  │                                                                  │
│ • Attack Srf │                                                                  │
│ • Reports    │                                                                  │
└──────────────┴──────────────────────────────────────────────────────────────────┘
```

---

### 1. WebSec Overview Page (`WebSecOverviewPage.tsx`)
- **Executive Security Score Ring (`ScoreRing.tsx`)**: Circular rating gauge displaying the target's overall security grade from **A+ (95-100)** down to **F (<60)**.
- **Key Risk Indicators**:
  - **SSL/TLS Certificate Validity**: Days remaining before expiration.
  - **Security Headers Rating**: Ratio of active protective HTTP headers (HSTS, CSP, etc.).
  - **Uptime & Latency**: Synthetic ping response time in milliseconds.
- **Recent Vulnerabilities**: Immediate list of high-priority findings discovered during the last audit.

---

### 2. Targets Management (`WebSecTargetsPage.tsx`)
- Register and maintain a portfolio of websites, APIs, and web portals.
- Controls to trigger instant on-demand audits (`Scan Now`) or adjust audit frequencies (e.g. every 60s, 5m, 1h).

---

### 3. Interactive Web Scanner (`WebSecScannerPage.tsx`)
- Enter any URL to perform an instant live security audit.
- Evaluates:
  - Synthetic HTTP connection latency and status codes.
  - SSL/TLS handshake protocols and certificate validation.
  - Server banner exposure and information leakage.

---

### 4. Vulnerabilities Inspector (`WebSecVulnerabilitiesPage.tsx`)
Exhaustive catalog of discovered security deficiencies categorized by severity:
- **Missing HSTS (`Strict-Transport-Security`)**: Risk of SSL-stripping man-in-the-middle attacks.
- **Missing Content Security Policy (CSP)**: Exposure to Cross-Site Scripting (XSS) and code injection.
- **Missing `X-Frame-Options`**: Vulnerability to Clickjacking attacks.
- **Insecure Cookie Flags**: Missing `Secure` or `HttpOnly` attributes on session cookies.
- **Information Disclosure**: Exposed `Server` or `X-Powered-By` headers revealing exact software versions.

---

### 5. SSL/TLS Certificate Audit (`WebSecTlsAuditPage.tsx`)
Detailed cryptographic assessment of the target's TLS configuration:
- Certificate Subject, Issuer Authority (e.g. Let's Encrypt, DigiCert), and Serial Number.
- Expiration countdown with automated warnings when renewal is due within 14 days.
- Cipher suite strength, supported TLS protocol versions (TLS 1.2, TLS 1.3), and deprecated protocol warnings (SSLv3, TLS 1.0, TLS 1.1).

---

### 6. Attack Surface Mapping (`WebSecAttackSurfacePage.tsx`)
Maps external-facing digital assets:
- Discovered subdomains and linked endpoints.
- External third-party scripts and CDN dependencies.
- Open HTTP methods and exposed administrative interfaces.

---

### 7. Executive Audit Reports (`WebSecReportsPage.tsx` & `AuditReportModal.tsx`)
- Generates publication-ready security audit reports.
- Includes:
  - Executive summary and letter grade.
  - Full breakdown of tested controls.
  - Concrete developer remediation code snippets (e.g. exact Nginx / Apache configuration directives to fix missing headers).
  - Print and PDF export support.

---

## 🎨 Themes & Customization (`ThemePicker.tsx`)

An instant theme switcher accessible at the bottom of the sidebar adapts all charts, widgets, and background contrast:

| Theme | Visual Aesthetic | Intended Environment |
|---|---|---|
| **Dark (Default)** | GitHub dark slate & deep navy | Standard SOC operations and low-light environments. |
| **Cyberpunk** | High-contrast neon cyan, magenta & purple | Demonstrations, live exhibitions, and presentation displays. |
| **Terminal Green** | Classic monochromatic phosphor green | Retro matrix style for terminal enthusiasts. |
| **Light** | Clean white slate with dark slate typography | Bright conference rooms, reports, and daytime viewing. |

---

## ⚡ Keyboard Shortcuts & Quick Navigation

| Key Combination | Action |
|---|---|
| `Tab 1` through `Tab 7` | Switch between primary SOC console tabs. |
| `Esc` | Close any open modal (Add Computer, Firewall Generator, Audit Report). |
| `Ctrl + F` / `/` | Focus the Alert Search input box immediately. |
| Platform Switch Button | Jump seamlessly between Network Anomaly Detection and WebSec. |
