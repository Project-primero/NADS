"""Protocol dissection: L2-L7 parsing into a normalized packet dict."""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class ParsedPacket:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, ICMP, ARP, OTHER
    length: int
    flags: str = ""
    payload_len: int = 0
    payload_text: str = ""
    dns_query: str = ""
    http_payload: str = ""


def parse_raw(pkt) -> ParsedPacket | None:
    """Parse a scapy packet into ParsedPacket. Returns None if unparsable."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import ARP
        from scapy.layers.dns import DNS, DNSQR
        from scapy.packet import Raw
    except ImportError:
        return None
    try:
        if pkt.haslayer(ARP):
            a = pkt[ARP]
            return ParsedPacket(src_ip=a.psrc, dst_ip=a.pdst, src_port=0,
                                dst_port=0, protocol="ARP", length=len(pkt))
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        proto, sport, dport, flags = "OTHER", 0, 0, ""
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            proto, sport, dport, flags = "TCP", int(t.sport), int(t.dport), str(t.flags)
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            proto, sport, dport = "UDP", int(u.sport), int(u.dport)
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        dns_q = ""
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                dns_q = pkt[DNSQR].qname.decode(errors="ignore")
            except Exception:
                dns_q = ""
        raw = b""
        if pkt.haslayer(Raw):
            try:
                raw = bytes(pkt[Raw].load)
            except Exception:
                raw = b""
        http = ""
        if sport == 80 or dport == 80:
            http = raw[:1024].decode(errors="ignore")
        # generic payload snippet so non-HTTP detectors (miner, Log4Shell,
        # command injection, SSRF) work on any port
        payload_text = raw[:512].decode(errors="ignore")
        return ParsedPacket(src_ip=ip.src, dst_ip=ip.dst, src_port=sport,
                            dst_port=dport, protocol=proto, length=len(pkt),
                            flags=flags, payload_len=len(raw),
                            payload_text=payload_text,
                            dns_query=dns_q, http_payload=http)
    except Exception:
        return None


def dict_from_parsed(p: ParsedPacket) -> dict:
    return {"src_ip": p.src_ip, "dst_ip": p.dst_ip, "src_port": p.src_port,
            "dst_port": p.dst_port, "protocol": p.protocol, "length": p.length,
            "flags": p.flags, "payload_len": p.payload_len,
            "payload_text": p.payload_text,
            "dns_query": p.dns_query, "http_payload": p.http_payload}
