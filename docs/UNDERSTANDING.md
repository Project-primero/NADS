# Understanding Network Anomaly Detection (NAD) — Concepts, Architecture & Purpose

A plain-language guide to how Network Anomaly Detection (NAD) works, why it is designed this way, and what problems it solves in modern cybersecurity.

---

## 1. The Core Mental Model

Think of Network Anomaly Detection as an **automated, intelligent security camera system for computer networks**:

```
 ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
 │     EYES     │ ──► │    BRAIN     │ ──► │   ARBITER    │ ──► │ CONTROL ROOM │
 │  Ingestion   │     │  Detection   │     │ Correlation  │     │  Dashboard   │
 └──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

1. **The Eyes (Universal Ingestion):** Watches traffic passing through network cables, Wi-Fi adapters, switch mirror ports, replay files, or remote laboratory computers.
2. **The Brain (Two-Engine Detection):**
   - **The Guard with a "Wanted Poster" (Signatures):** Instantly recognizes 30 specific known attack signatures (e.g. port scans, password cracking, SQL injection, Log4Shell).
   - **The AI Observer (Machine Learning):** Learns what normal campus or office traffic looks like and flags abnormal, suspicious patterns it has never seen before (zero-days).
3. **The Arbiter (Correlation & Threat Fusion):** Checks whether the source is on a pre-approved allowlist, combines the signature and AI verdicts into a single **0 to 100 Threat Score**, labels it with an official **MITRE ATT&CK** technique code, and writes a step-by-step remediation plan.
4. **The Control Room (SOC Dashboard):** Streams live traffic charts and critical security alerts via WebSockets to security analysts in sub-second time.

---

## 2. Navigating the Codebase by Function

If you are exploring the system, here is where each conceptual layer lives in code:

| Layer | Responsibility | Key File | Key Class / Function |
|---|---|---|---|
| **Ingestion** | Physical capture, synthetic traffic, PCAP replay | [`backend/capture/packet_capture.py`](file:///home/dereje/project/NAD/backend/capture/packet_capture.py) | [`PacketCapture`](file:///home/dereje/project/NAD/backend/capture/packet_capture.py#L38-L150) |
| **Normalization** | Groups packets into 5-tuple conversations | [`backend/flow/flow_manager.py`](file:///home/dereje/project/NAD/backend/flow/flow_manager.py) | [`FlowManager`](file:///home/dereje/project/NAD/backend/flow/flow_manager.py#L11-L68) |
| **Telemetry** | Endpoint client on remote Windows & Linux PCs | [`scripts/aegis-agent.py`](file:///home/dereje/project/NAD/scripts/aegis-agent.py) | `AegisAgent` |
| **Signatures** | 30 sliding-window heuristic detectors | [`backend/detection/signature_engine.py`](file:///home/dereje/project/NAD/backend/detection/signature_engine.py) | [`SignatureEngine`](file:///home/dereje/project/NAD/backend/detection/signature_engine.py#L48-L230) |
| **Machine Learning** | 41-feature extraction and anomaly scoring | [`backend/detection/inference.py`](file:///home/dereje/project/NAD/backend/detection/inference.py) | [`DetectionEngine`](file:///home/dereje/project/NAD/backend/detection/inference.py#L11-L47) |
| **Fusion & Policy** | Combines engines, checks allowlists, calculates threat score | [`backend/detection/correlation.py`](file:///home/dereje/project/NAD/backend/detection/correlation.py) | [`correlate()`](file:///home/dereje/project/NAD/backend/detection/correlation.py#L29-L97) |
| **Asset Discovery** | Auto-indexes active IP/MAC addresses into inventory | [`backend/database/db.py`](file:///home/dereje/project/NAD/backend/database/db.py) | [`Database.touch_asset`](file:///home/dereje/project/NAD/backend/database/db.py#L120-L150) |
| **WebSec Monitor** | Synthetic HTTP audits, TLS checks, security headers | [`backend/api/routes.py`](file:///home/dereje/project/NAD/backend/api/routes.py) | `check_site()` |
| **SOC Dashboard** | Real-time React frontend with dark security UI | [`frontend/src/components/Dashboard.tsx`](file:///home/dereje/project/NAD/frontend/src/components/Dashboard.tsx) | `Dashboard` |

---

## 3. Why Each Architectural Layer Is Necessary

### Why Signatures Alone Are Not Enough
Signature rules can only catch attacks security researchers already know and have written rules for. When a cybercriminal devises a novel evasion technique or proprietary malware, signatures see nothing. Machine learning anomaly detection provides the safety net by identifying behavioral deviations (such as unusual data volumes or strange connection intervals).

### Why Machine Learning Alone Is Not Enough
Pure machine learning models are notorious for false positives and lack explainability. When an ML model says a connection has a "0.89 anomaly score", an analyst does not know *why* or what to do about it. The NAD platform solves this by prioritizing deterministic signatures and using ML as a confirmation amplifier.

### Why Multi-Source Telemetry Matters
Modern attacks rarely happen on the internet gateway alone. Advanced persistent threats (APTs) compromise an internal computer through phishing or infected USB drives, and then traverse horizontally across the network. By pairing central switch mirroring with distributed endpoint agents, the system monitors both north-south perimeter traffic and east-west lateral movement.

### Why Alert Correlation & Allowlists Matter
Security Operation Centers (SOCs) fail most often from **alert fatigue**—analysts become overwhelmed by thousands of minor, un-prioritized notifications. The NAD engine addresses this by:
- Throttling duplicate alerts over a 60-second sliding window.
- Providing an instant CIDR/IP allowlist for legitimate vulnerability scanners and internal tools.
- Calculating an actionable 0–100 Threat Score so analysts immediately tackle the highest-risk threats first.

---

## 4. Real-World Attack Scenarios Protected Against

1. **Ransomware Early Reconnaissance:**
   Ransomware operators begin by scanning the local subnet for vulnerable servers. The engine detects **Port Scans**, **Horizontal Scans**, and **Ping Sweeps** in under one second—stopping attackers during reconnaissance before encryption begins.
2. **Credential Attacks & Account Takeovers:**
   Brute-force scripts and botnets attacking SSH, RDP, or web logins trigger the port-aware failed login detector, alerting administrators before a password is compromised.
3. **Exploitation of Web Vulnerabilities:**
   Attacks injecting malicious database queries (**SQL Injection**), server-side commands (**Command Injection**), or remote code execution tokens (**Log4Shell `${jndi:`) are detected directly in HTTP request payloads.
4. **Data Exfiltration & DNS Covert Channels:**
   Malware attempting to bypass outbound firewalls by encoding sensitive data into high-volume DNS requests is caught by the **DNS Tunneling** and **DNS Exfiltration** rules.

---

## 5. The 30-Second Elevator Pitch

> *"Network Anomaly Detection (NAD) is an intelligent Cyber Attack Monitoring and Security Operations platform. It unifies traffic from physical network switches, host adapters, and remote laboratory computers into a single real-time dashboard. By fusing 30 instant signature detectors with machine learning anomaly detection, NAD pinpoints both known exploits and zero-day threats in under a second—scoring each threat from 0 to 100 with clear MITRE ATT&CK classifications and actionable remediation commands."*
