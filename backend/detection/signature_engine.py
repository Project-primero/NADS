"""Signature engine v3 — real-world coverage of 30 attack classes.

Each detector emits: attack_type, severity, confidence, mitre, description,
remediation, plus packet 5-tuple. Tunables come from backend.config.Settings.
"""
from __future__ import annotations
import time
from collections import defaultdict, deque


# attack catalog shared with API + frontend
CATALOG = {
    # scans & recon
    "Port Scan":        {"severity": "HIGH",     "mitre": "T1046", "remediation": "Block src IP at firewall, review exposed services."},
    "Null/Xmas Scan":   {"severity": "MEDIUM",   "mitre": "T1046", "remediation": "Block scanner IP, verify IDS coverage."},
    "Ping Sweep":       {"severity": "MEDIUM",   "mitre": "T1595", "remediation": "Block sweeping host, review ICMP policy."},
    "Horizontal Scan":  {"severity": "HIGH",     "mitre": "T1046", "remediation": "Block src IP — one port probed across many hosts (worm-like)."},
    # floods / DoS
    "SYN Flood":        {"severity": "HIGH",     "mitre": "T1498", "remediation": "Enable SYN cookies, rate-limit SYNs, upstream blackhole."},
    "UDP Flood":        {"severity": "HIGH",     "mitre": "T1498", "remediation": "Rate-limit UDP, filter unused UDP ports."},
    "ICMP Flood":       {"severity": "MEDIUM",   "mitre": "T1498", "remediation": "Rate-limit ICMP, block smurf amplifiers."},
    "UDP Amplification":{"severity": "HIGH",     "mitre": "T1498", "remediation": "Block NTP/SSDP/monlist abusers, disable open amplifiers."},
    "Slowloris":        {"severity": "MEDIUM",   "mitre": "T1498", "remediation": "Shorten header timeouts, cap connections per IP, use reverse proxy."},
    "DDoS":             {"severity": "CRITICAL", "mitre": "T1498", "remediation": "Engage DDoS mitigation / scrubbing, block top sources."},
    # brute force & spraying
    "SSH Brute Force":  {"severity": "HIGH",     "mitre": "T1110", "remediation": "Block src IP, enforce key-auth + fail2ban."},
    "FTP Brute Force":  {"severity": "HIGH",     "mitre": "T1110", "remediation": "Block src IP, disable anonymous FTP."},
    "RDP Brute Force":  {"severity": "HIGH",     "mitre": "T1110", "remediation": "Block src IP, require NLA + MFA on RDP."},
    "Telnet Brute Force": {"severity": "HIGH",   "mitre": "T1110", "remediation": "Block src IP — likely Mirai-style IoT botnet; disable Telnet."},
    "HTTP Brute Force": {"severity": "HIGH",     "mitre": "T1110", "remediation": "Block src IP, enable CAPTCHA / account lockout."},
    "Password Spraying":{"severity": "HIGH",     "mitre": "T1110", "remediation": "Force password reset on targeted accounts, block src IP."},
    # DNS & exfiltration
    "DNS Tunneling":    {"severity": "HIGH",     "mitre": "T1071", "remediation": "Block tunneled domain, inspect endpoint for malware."},
    "DNS Exfiltration": {"severity": "CRITICAL", "mitre": "T1048", "remediation": "Isolate host, block domain, forensic triage."},
    "Data Exfiltration":{"severity": "CRITICAL", "mitre": "T1041", "remediation": "Isolate host, inspect large egress flows."},
    # spoofing, C2, lateral movement
    "ARP Spoofing":     {"severity": "HIGH",     "mitre": "T1557", "remediation": "Enable Dynamic ARP Inspection, locate rogue host."},
    "Malware C2":       {"severity": "CRITICAL", "mitre": "T1071", "remediation": "Isolate host, block C2 domain/IP, reimage."},
    "C2 Beaconing":     {"severity": "CRITICAL", "mitre": "T1071", "remediation": "Isolate host, hunt periodic egress pattern."},
    "SMB Lateral Movement": {"severity": "HIGH", "mitre": "T1021", "remediation": "Isolate host, audit SMB logins, block 445 egress."},
    "Cryptominer":      {"severity": "HIGH",     "mitre": "T1496", "remediation": "Isolate host, kill miner process, block pool domains."},
    # web exploitation
    "SQL Injection":    {"severity": "HIGH",     "mitre": "T1190", "remediation": "Block src IP at WAF, patch input handling."},
    "XSS Attempt":      {"severity": "MEDIUM",   "mitre": "T1189", "remediation": "Block at WAF, review app output encoding."},
    "Path Traversal":   {"severity": "HIGH",     "mitre": "T1083", "remediation": "Block at WAF, audit file-access controls."},
    "Command Injection":{"severity": "CRITICAL", "mitre": "T1190", "remediation": "Block src IP at WAF, audit shell-exec code paths."},
    "Log4Shell":        {"severity": "CRITICAL", "mitre": "T1190", "remediation": "Isolate + patch Log4j NOW, block LDAP callbacks outbound."},
    "SSRF Attempt":     {"severity": "HIGH",     "mitre": "T1190", "remediation": "Block at WAF, deny cloud-metadata IP (169.254.169.254)."},
}

AMP_PORTS = {123, 1900, 11211, 5353}          # NTP / SSDP / memcached / mDNS
CMDI_TOKENS = [";cat ", "|cat ", ";ls", "|whoami", "$(", "`", "&& ", "|| ",
               "wget http", "curl http", ";id", "/bin/sh", "/bin/bash", "nc -e "]
MINER_TOKENS = ["stratum", "mining.subscribe", "mining.authorize", "xmrig",
                "cryptonight", "monero", "nicehash", "ethermine"]
SSRF_TOKENS = ["169.254.169.254", "metadata.google", "instance-data", "instance-data/"]


class SignatureEngine:
    def __init__(self, port_scan_ports=15, port_scan_window=60,
                 syn_flood_count=50, syn_flood_window=10,
                 ddos_pps=1000, brute_force_fails=10,
                 brute_force_window=300, dns_tunnel_len=53,
                 udp_flood_count=200, udp_flood_window=10,
                 icmp_flood_count=100, icmp_flood_window=10,
                 exfil_bytes=10_000_000,
                 sweep_dsts=10, sweep_window=60,
                 horiz_dsts=10, horiz_window=60,
                 spray_dsts=5,
                 smb_count=20, smb_window=60,
                 slowloris_count=50, slowloris_window=60,
                 amp_count=50, amp_window=10):
        self.port_scan_ports = port_scan_ports
        self.port_scan_window = port_scan_window
        self.syn_flood_count = syn_flood_count
        self.syn_flood_window = syn_flood_window
        self.ddos_pps = ddos_pps
        self.brute_force_fails = brute_force_fails
        self.brute_force_window = brute_force_window
        self.dns_tunnel_len = dns_tunnel_len
        self.udp_flood_count = udp_flood_count
        self.udp_flood_window = udp_flood_window
        self.icmp_flood_count = icmp_flood_count
        self.icmp_flood_window = icmp_flood_window
        self.exfil_bytes = exfil_bytes
        self.sweep_dsts = sweep_dsts
        self.sweep_window = sweep_window
        self.horiz_dsts = horiz_dsts
        self.horiz_window = horiz_window
        self.spray_dsts = spray_dsts
        self.smb_count = smb_count
        self.smb_window = smb_window
        self.slowloris_count = slowloris_count
        self.slowloris_window = slowloris_window
        self.amp_count = amp_count
        self.amp_window = amp_window

        self._ports: defaultdict[str, deque] = defaultdict(deque)
        self._syns: defaultdict[str, deque] = defaultdict(deque)
        self._udps: defaultdict[str, deque] = defaultdict(deque)
        self._icmps: defaultdict[str, deque] = defaultdict(deque)
        self._amps: defaultdict[str, deque] = defaultdict(deque)
        self._fails: defaultdict[str, deque] = defaultdict(deque)
        self._beacon: defaultdict[str, deque] = defaultdict(deque)
        self._arp: deque = deque(maxlen=500)
        self._pps: deque = deque(maxlen=ddos_pps + 500)
        # v3 trackers
        self._ping: defaultdict[str, deque] = defaultdict(deque)    # src -> (ts,dst)
        self._horiz: defaultdict[str, deque] = defaultdict(deque)   # src:dport -> (ts,dst)
        self._spray: defaultdict[str, deque] = defaultdict(deque)   # src -> (ts,dst of fail)
        self._smb: defaultdict[str, deque] = defaultdict(deque)     # src -> ts
        self._slow: defaultdict[str, deque] = defaultdict(deque)    # src -> ts
        self._c2 = {"malicious.example.com", "evil-c2.example.net",
                    "beacon.evil.example.com", "data.exfil.example.org"}

    # ---------- helpers ----------
    @staticmethod
    def _prune_ts(dq: deque, window: int, now: float) -> None:
        while dq and now - dq[0] > window:
            dq.popleft()

    @staticmethod
    def _prune_tuples(dq: deque, window: int, now: float) -> None:
        while dq and now - dq[0][0] > window:
            dq.popleft()

    def _alert(self, attack: str, desc: str, pkt: dict, confidence: float = 0.9) -> dict:
        meta = CATALOG.get(attack, {"severity": "MEDIUM", "mitre": "-", "remediation": ""})
        return {"attack_type": attack, "severity": meta["severity"],
                "confidence": confidence, "mitre": meta["mitre"],
                "remediation": meta["remediation"], "description": desc,
                "src_ip": pkt.get("src_ip", ""), "dst_ip": pkt.get("dst_ip", ""),
                "src_port": pkt.get("src_port", 0), "dst_port": pkt.get("dst_port", 0),
                "protocol": pkt.get("protocol", ""), "engine": "signature"}

    # ---------- packet-level ----------
    def check_packet(self, pkt: dict) -> list[dict]:
        now = time.time()
        out: list[dict] = []
        src, dst = pkt.get("src_ip", ""), pkt.get("dst_ip", "")
        proto = pkt.get("protocol", "")
        flags = str(pkt.get("flags", ""))
        dport = pkt.get("dst_port", 0)
        text = (str(pkt.get("http_payload", "")) + " " + str(pkt.get("payload_text", ""))).lower()
        dns = str(pkt.get("dns_query", ""))

        # 1. Port scan (vertical: many ports, one host)
        q = self._ports[src]
        q.append((now, dport))
        self._prune_tuples(q, self.port_scan_window, now)
        uniq = {p for _, p in q}
        if len(uniq) >= self.port_scan_ports:
            out.append(self._alert("Port Scan",
                                   f"{src} probed {len(uniq)} ports in {self.port_scan_window}s", pkt, 0.92))
            q.clear()

        # 2. Horizontal scan (one port, many hosts — worm-like)
        if proto == "TCP" and "S" in flags:
            h = self._horiz[f"{src}:{dport}"]
            h.append((now, dst))
            self._prune_tuples(h, self.horiz_window, now)
            if len({d for _, d in h}) >= self.horiz_dsts:
                out.append(self._alert("Horizontal Scan",
                                       f"{src} probed port {dport} on {self.horiz_dsts}+ hosts", pkt, 0.88))
                h.clear()

        # 3. Ping sweep (ICMP across many hosts)
        if proto == "ICMP":
            p = self._ping[src]
            p.append((now, dst))
            self._prune_tuples(p, self.sweep_window, now)
            if len({d for _, d in p}) >= self.sweep_dsts:
                out.append(self._alert("Ping Sweep",
                                       f"{src} pinged {self.sweep_dsts}+ hosts in {self.sweep_window}s", pkt, 0.85))
                p.clear()

        # 4. Null / Xmas scan
        if proto == "TCP" and (flags in ("", "0") or set(flags) >= {"F", "P", "U"}):
            out.append(self._alert("Null/Xmas Scan", f"Stealth scan flags='{flags}' from {src}", pkt, 0.8))

        # 5. SYN flood (per target)
        if proto == "TCP" and "S" in flags and "A" not in flags:
            s = self._syns[dst]
            s.append(now)
            self._prune_ts(s, self.syn_flood_window, now)
            if len(s) >= self.syn_flood_count:
                out.append(self._alert("SYN Flood",
                                       f"{len(s)} SYNs → {dst} in {self.syn_flood_window}s", pkt, 0.9))
                s.clear()

        # 6. UDP flood / amplification (per target)
        if proto == "UDP" and dport != 53:
            u = self._udps[dst]
            u.append(now)
            self._prune_ts(u, self.udp_flood_window, now)
            if len(u) >= self.udp_flood_count:
                out.append(self._alert("UDP Flood",
                                       f"{len(u)} UDP pkts → {dst} in {self.udp_flood_window}s", pkt, 0.88))
                u.clear()
            if dport in AMP_PORTS:
                a = self._amps[dst]
                a.append(now)
                self._prune_ts(a, self.amp_window, now)
                if len(a) >= self.amp_count:
                    out.append(self._alert("UDP Amplification",
                                           f"{len(a)} pkts → amplifier port {dport} on {dst}", pkt, 0.85))
                    a.clear()

        # 7. ICMP flood (volume per target)
        if proto == "ICMP":
            c = self._icmps[dst]
            c.append(now)
            self._prune_ts(c, self.icmp_flood_window, now)
            if len(c) >= self.icmp_flood_count:
                out.append(self._alert("ICMP Flood",
                                       f"{len(c)} ICMP pkts → {dst} in {self.icmp_flood_window}s", pkt, 0.85))
                c.clear()

        # 8. Slowloris (many small HTTP requests, one src)
        if proto == "TCP" and dport in (80, 443, 8080) and int(pkt.get("payload_len", 0)) < 200 \
                and ("post" in text or "get" in text):
            sl = self._slow[src]
            sl.append(now)
            self._prune_ts(sl, self.slowloris_window, now)
            if len(sl) >= self.slowloris_count:
                out.append(self._alert("Slowloris",
                                       f"{len(sl)} slow HTTP requests from {src} (partial-connection DoS)", pkt, 0.8))
                sl.clear()

        # 9. DDoS (global pps)
        self._pps.append(now)
        while self._pps and now - self._pps[0] > 1.0:
            self._pps.popleft()
        if len(self._pps) >= self.ddos_pps:
            out.append(self._alert("DDoS",
                                   f"Global {len(self._pps)} pps ≥ threshold {self.ddos_pps}", pkt, 0.95))

        # 10-14. Brute force per service + password spraying
        fail_sig = ("failed password" in text or "login failed" in text
                    or " 401" in text or "authentication failure" in text)
        if fail_sig:
            label = ("SSH Brute Force" if dport == 22 else
                     "FTP Brute Force" if dport == 21 else
                     "RDP Brute Force" if dport == 3389 else
                     "Telnet Brute Force" if dport in (23, 2323) else "HTTP Brute Force")
            f = self._fails[(src, label)]
            f.append(now)
            self._prune_ts(f, self.brute_force_window, now)
            if len(f) >= self.brute_force_fails:
                extra = " — possible Mirai-style IoT botnet" if "Telnet" in label else ""
                out.append(self._alert(label, f"{len(f)} failed logins from {src} ({label.split()[0]}){extra}", pkt, 0.9))
                f.clear()
            # spraying: same src failing across MANY distinct targets
            sp = self._spray[src]
            sp.append((now, dst))
            self._prune_tuples(sp, self.brute_force_window, now)
            if len({d for _, d in sp}) >= self.spray_dsts:
                out.append(self._alert("Password Spraying",
                                       f"{src} failing logins on {self.spray_dsts}+ hosts (spraying, not brute force)", pkt, 0.87))
                sp.clear()

        # 15. SMB lateral movement (burst of 445 connections)
        if proto == "TCP" and dport == 445:
            sm = self._smb[src]
            sm.append(now)
            self._prune_ts(sm, self.smb_window, now)
            if len(sm) >= self.smb_count:
                out.append(self._alert("SMB Lateral Movement",
                                       f"{len(sm)} SMB connections from {src} — possible lateral movement", pkt, 0.85))
                sm.clear()

        # 16-17. DNS tunneling / exfiltration + C2 domains
        if dns:
            if len(dns) > self.dns_tunnel_len * 2:
                out.append(self._alert("DNS Exfiltration",
                                       f"Very long DNS query ({len(dns)}B): {dns[:60]}…", pkt, 0.9))
            elif len(dns) > self.dns_tunnel_len:
                out.append(self._alert("DNS Tunneling",
                                       f"Oversized DNS query ({len(dns)}B): {dns[:60]}…", pkt, 0.85))
            if any(c in dns for c in self._c2):
                out.append(self._alert("Malware C2", f"Known C2 domain: {dns[:80]}", pkt, 0.97))

        # 18. C2 beaconing (periodic small egress)
        if int(pkt.get("length", 0)) < 300 and dst:
            b = self._beacon[(src, dst)]
            b.append(now)
            while b and now - b[0] > 300:
                b.popleft()
            if len(b) >= 20:
                gaps = [t2 - t1 for t1, t2 in zip(list(b)[-20:-1], list(b)[-19:])]
                if gaps and max(gaps) - min(gaps) < 5:
                    out.append(self._alert("C2 Beaconing",
                                           f"{src} → {dst}: {len(b)} periodic beacons (~{sum(gaps)/len(gaps):.0f}s)", pkt, 0.88))
                    b.clear()

        # 19. ARP spoofing (reply storm)
        if proto == "ARP":
            self._arp.append(now)
            self._prune_ts(self._arp, 5, now)
            if len(self._arp) >= 30:
                out.append(self._alert("ARP Spoofing",
                                       f"ARP storm: {len(self._arp)} replies in 5s (possible MITM)", pkt, 0.85))
                self._arp.clear()

        # 20-25. Payload signatures (any-port text + HTTP)
        if any(t in text for t in ["' or '1'='1", "union select", "; drop", "sleep(", "'--", "information_schema"]):
            out.append(self._alert("SQL Injection", "SQLi pattern in payload", pkt, 0.9))
        if any(t in text for t in ["<script", "javascript:", "onerror=", "onload=", "<img", "document.cookie"]):
            out.append(self._alert("XSS Attempt", "XSS pattern in payload", pkt, 0.85))
        if any(t in text for t in ["../", "..\\", "/etc/passwd", "....//"]):
            out.append(self._alert("Path Traversal", "Directory-traversal pattern", pkt, 0.88))
        if any(t in text for t in CMDI_TOKENS):
            out.append(self._alert("Command Injection", "OS command-injection pattern in payload", pkt, 0.92))
        if "${jndi:" in text:
            out.append(self._alert("Log4Shell", "Log4Shell JNDI payload — patch immediately", pkt, 0.97))
        if any(t in text for t in SSRF_TOKENS):
            out.append(self._alert("SSRF Attempt", "Cloud-metadata / internal URL in request", pkt, 0.9))
        if any(t in text for t in MINER_TOKENS):
            out.append(self._alert("Cryptominer", "Stratum/miner protocol strings in traffic", pkt, 0.9))

        return out

    # ---------- flow-level ----------
    def check_flow(self, feats: dict, flow) -> list[dict]:
        base = {"src_ip": getattr(flow, "src_ip", ""), "dst_ip": getattr(flow, "dst_ip", ""),
                "src_port": getattr(flow, "src_port", 0), "dst_port": getattr(flow, "dst_port", 0),
                "protocol": getattr(flow, "protocol", "")}
        out = []
        if feats.get("unique_dst_ports", 0) >= self.port_scan_ports:
            out.append(self._alert("Port Scan", "Flow touched many ports", base, 0.8))
        if feats.get("syn_ack_ratio", 0) > 5 and feats.get("total_packets", 0) > 20:
            out.append(self._alert("SYN Flood", "High SYN/ACK ratio in flow", base, 0.8))
        if feats.get("packets_per_sec", 0) > self.ddos_pps:
            out.append(self._alert("DDoS", "Flow PPS exceeds DDoS threshold", base, 0.9))
        if feats.get("total_bytes", 0) > self.exfil_bytes and feats.get("src_to_dst_bytes", 0) > 0.8 * feats.get("total_bytes", 1):
            out.append(self._alert("Data Exfiltration", f"Large one-sided transfer ({feats['total_bytes']/1e6:.1f} MB)", base, 0.82))
        if feats.get("dns_query_len", 0) > self.dns_tunnel_len * 2:
            out.append(self._alert("DNS Exfiltration", "Long DNS query in flow", base, 0.85))
        elif feats.get("dns_query_len", 0) > self.dns_tunnel_len:
            out.append(self._alert("DNS Tunneling", "Long DNS query in flow", base, 0.8))
        if feats.get("failed_login", 0) >= self.brute_force_fails:
            out.append(self._alert("SSH Brute Force", "Failed logins concentrated in flow", base, 0.85))
        if feats.get("sqli_score", 0) > 0:
            out.append(self._alert("SQL Injection", "SQLi tokens in flow payload", base, 0.9))
        if feats.get("xss_score", 0) > 0:
            out.append(self._alert("XSS Attempt", "XSS tokens in flow payload", base, 0.85))
        return out
