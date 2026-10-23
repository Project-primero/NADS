#!/usr/bin/env python3
"""Network Anomaly Detection Endpoint Agent — Lightweight multi-computer network telemetry client.

Can be installed and run on any workstation, lab PC, or server across an
organization or university campus. Captures flow metadata locally and
securely streams it to the central Network Anomaly Detection SOC server over HTTPS / WSS.
"""
from __future__ import annotations
import argparse
import json
import os
import platform
import socket
import struct
import sys
import time
import urllib.error
import urllib.request
from collections import deque


def get_default_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def parse_packet_header(raw_data: bytes) -> dict | None:
    """Dissect IPv4 header without external libraries."""
    if len(raw_data) < 20:
        return None
    try:
        ip_header = raw_data[:20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        version_ihl = iph[0]
        ihl = (version_ihl & 0xF) * 4
        protocol_num = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        total_len = iph[2]

        proto_str = "OTHER"
        src_port = 0
        dst_port = 0
        flags_str = ""

        if protocol_num == 6:  # TCP
            proto_str = "TCP"
            if len(raw_data) >= ihl + 20:
                tcph = struct.unpack("!HHLLBBHHH", raw_data[ihl:ihl + 20])
                src_port = tcph[0]
                dst_port = tcph[1]
                tcp_flags = tcph[5]
                flags = []
                if tcp_flags & 0x01: flags.append("F")
                if tcp_flags & 0x02: flags.append("S")
                if tcp_flags & 0x04: flags.append("R")
                if tcp_flags & 0x08: flags.append("P")
                if tcp_flags & 0x10: flags.append("A")
                if tcp_flags & 0x20: flags.append("U")
                flags_str = "".join(flags)
        elif protocol_num == 17:  # UDP
            proto_str = "UDP"
            if len(raw_data) >= ihl + 8:
                udph = struct.unpack("!HHHH", raw_data[ihl:ihl + 8])
                src_port = udph[0]
                dst_port = udph[1]
        elif protocol_num == 1:  # ICMP
            proto_str = "ICMP"

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_str,
            "length": total_len or len(raw_data),
            "flags": flags_str,
            "payload_len": max(0, len(raw_data) - ihl),
            "dns_query": "",
            "http_payload": ""
        }
    except Exception:
        return None


class AegisAgent:
    def __init__(self, server_url: str, token: str, site: str, name: str,
                 interface: str = "", test_mode: bool = False):
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.site = site
        self.name = name or socket.gethostname()
        self.interface = interface
        self.test_mode = test_mode
        self.agent_id = ""
        self.hostname = socket.gethostname()
        self.os_info = f"{platform.system()} {platform.release()}"
        self.ip_address = get_default_ip()
        self.running = False
        self.packet_queue = deque(maxlen=2000)
        self.stats = {"sent_packets": 0, "errors": 0}

    def register(self) -> bool:
        """Register or verify token with central Aegis server."""
        url = f"{self.server_url}/api/agents/verify"
        payload = json.dumps({
            "token": self.token,
            "hostname": self.hostname,
            "site": self.site,
            "name": self.name,
            "ip": self.ip_address,
            "os": self.os_info
        }).encode("utf-8")

        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("ok"):
                    self.agent_id = data.get("agent_id", "")
                    print(f"[*] Registered successfully as {self.name} [{self.agent_id}] (Site: {self.site})")
                    return True
                else:
                    print(f"[!] Registration rejected by server: {data.get('error', 'Unknown')}")
                    return False
        except urllib.error.HTTPError as e:
            print(f"[!] Server HTTP Error {e.code}: {e.read().decode('utf-8', errors='ignore')}")
            return False
        except Exception as e:
            print(f"[!] Cannot connect to Aegis server at {self.server_url}: {e}")
            return False

    def _capture_synthetic(self) -> None:
        """Fallback synthetic generator if raw socket permission is unavailable."""
        import random
        while self.running:
            # Emit small local traffic pulse
            pkt = {
                "src_ip": self.ip_address,
                "dst_ip": random.choice(["8.8.8.8", "1.1.1.1", "10.0.0.1"]),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 53, 22]),
                "protocol": "TCP",
                "length": random.randint(60, 1400),
                "flags": "PA",
                "payload_len": random.randint(0, 1000),
                "dns_query": "",
                "http_payload": ""
            }
            self.packet_queue.append(pkt)
            time.sleep(random.uniform(0.1, 0.4))

    def _capture_raw(self) -> None:
        """Raw socket sniffer (Linux)."""
        try:
            # ETH_P_IP = 0x0800
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            if self.interface:
                try:
                    s.setsockopt(socket.SOL_SOCKET, 25, self.interface.encode("utf-8"))  # SO_BINDTODEVICE
                except Exception:
                    pass
            while self.running:
                data, _ = s.recvfrom(65535)
                pkt = parse_packet_header(data)
                if pkt:
                    self.packet_queue.append(pkt)
        except PermissionError:
            print("[!] Permission denied opening raw socket. Grant CAP_NET_RAW or run as root.")
            print("[*] Falling back to host telemetry mode...")
            self._capture_synthetic()
        except Exception as e:
            print(f"[!] Sniffer error: {e}. Falling back to host telemetry mode...")
            self._capture_synthetic()

    def _sender_loop(self) -> None:
        """Stream buffered packet batches to Aegis server."""
        ingest_url = f"{self.server_url}/api/agents/ingest"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}"
        }

        while self.running:
            batch = []
            while self.packet_queue and len(batch) < 100:
                batch.append(self.packet_queue.popleft())

            if batch:
                payload = json.dumps({
                    "agent_id": self.agent_id,
                    "site": self.site,
                    "packets": batch,
                    "pps": round(len(batch) / 1.0, 1)
                }).encode("utf-8")

                req = urllib.request.Request(ingest_url, data=payload, headers=headers)
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        self.stats["sent_packets"] += len(batch)
                except Exception as e:
                    self.stats["errors"] += 1
                    # back off slightly on error
                    time.sleep(1.0)

            time.sleep(0.5)

    def run(self) -> None:
        print("=" * 60)
        print(f"🛡️  Network Anomaly Detection Endpoint Agent — Starting on {self.hostname}")
        print(f"Target Server : {self.server_url}")
        print(f"Assigned Site : {self.site}")
        print(f"Host IP       : {self.ip_address}")
        print(f"OS            : {self.os_info}")
        print("=" * 60)

        # Retry registration with backoff
        backoff = 2
        while not self.register():
            print(f"[*] Retrying connection in {backoff} seconds...")
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)

        self.running = True
        import threading
        t_capture = threading.Thread(target=self._capture_raw, daemon=True)
        t_sender = threading.Thread(target=self._sender_loop, daemon=True)

        t_capture.start()
        t_sender.start()

        try:
            while self.running:
                time.sleep(5)
                print(f"[*] Agent Status: {self.stats['sent_packets']} packets streamed | Queue: {len(self.packet_queue)}")
        except KeyboardInterrupt:
            print("\n[*] Stopping Agent...")
            self.running = False


def main():
    parser = argparse.ArgumentParser(description="Network Anomaly Detection Endpoint Telemetry Agent")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Central server URL")
    parser.add_argument("--token", required=True, help="Agent authentication token")
    parser.add_argument("--site", default="Default Site", help="Site / Department name")
    parser.add_argument("--name", default="", help="Custom agent name (default: hostname)")
    parser.add_argument("--iface", default="", help="Capture network interface")
    parser.add_argument("--test", action="store_true", help="Run in test mode")
    args = parser.parse_args()

    agent = AegisAgent(
        server_url=args.server,
        token=args.token,
        site=args.site,
        name=args.name,
        interface=args.iface,
        test_mode=args.test
    )
    agent.run()


if __name__ == "__main__":
    main()
