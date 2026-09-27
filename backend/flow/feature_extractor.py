"""CIC-IDS style 40+ flow feature extraction."""
from __future__ import annotations
import math
from collections import Counter

FEATURE_NAMES = [
    "duration", "total_packets", "total_bytes", "packets_per_sec",
    "bytes_per_sec", "bytes_per_packet", "src_to_dst_packets",
    "dst_to_src_packets", "src_to_dst_bytes", "dst_to_src_bytes",
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count",
    "syn_ack_ratio", "avg_packet_size", "packet_size_std",
    "iat_mean", "iat_std", "iat_min", "iat_max",
    "unique_dst_ports", "port_entropy", "tcp_ratio", "udp_ratio",
    "icmp_ratio", "arp_count", "dns_query_len", "payload_mean",
    "payload_std", "payload_max", "http_len", "sqli_score",
    "xss_score", "failed_login", "dst_port", "protocol_TCP",
    "protocol_UDP", "protocol_ICMP", "is_well_known_port",
]

SQLI_TOKENS = ["' or '1'='1", "union select", "--", "; drop", "'--", "sleep("]
XSS_TOKENS = ["<script", "javascript:", "onerror=", "onload=", "<img"]


def _entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total <= 1:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counter.values())


def extract_features(flow) -> dict:
    pkts = flow.packets if hasattr(flow, "packets") else flow
    n = len(pkts)
    if n == 0:
        return {k: 0.0 for k in FEATURE_NAMES}
    get = lambda p, k, d=0: p.get(k, d)
    first = pkts[0]
    duration = max(get(pkts[-1], "_ts", n) - get(pkts[0], "_ts", 0), 1e-6) \
        if "_ts" in first else getattr(flow, "duration", 1.0)
    lengths = [get(p, "length", 0) for p in pkts]
    total_bytes = sum(lengths)
    mean_len = total_bytes / n
    var = sum((x - mean_len) ** 2 for x in lengths) / n
    initiator = (first.get("src_ip"), first.get("src_port"))
    s2d = [p for p in pkts if (p.get("src_ip"), p.get("src_port")) == initiator]
    d2s = [p for p in pkts if (p.get("src_ip"), p.get("src_port")) != initiator]
    flags = " ".join(str(get(p, "flags", "")) for p in pkts)
    syn, ack = flags.count("S"), flags.count("A")
    fin, rst, psh = flags.count("F"), flags.count("R"), flags.count("P")
    iats: list[float] = []
    if "_ts" in first and n > 1:
        ts = [get(p, "_ts", 0) for p in pkts]
        iats = [b - a for a, b in zip(ts, ts[1:])]
    ports = Counter(get(p, "dst_port", 0) for p in pkts)
    protos = Counter(get(p, "protocol", "") for p in pkts)
    payloads = [get(p, "payload_len", 0) for p in pkts]
    pm = sum(payloads) / n
    pv = sum((x - pm) ** 2 for x in payloads) / n
    http = " ".join(str(get(p, "http_payload", "")) for p in pkts).lower()
    dns = max([len(str(get(p, "dns_query", ""))) for p in pkts] + [0])
    fails = http.count("failed password") + http.count("login failed") + http.count("401")
    sqli = sum(t in http for t in SQLI_TOKENS)
    xss = sum(t in http for t in XSS_TOKENS)
    proto = get(first, "protocol", "")
    dport = get(first, "dst_port", 0)
    return {
        "duration": duration, "total_packets": n, "total_bytes": total_bytes,
        "packets_per_sec": n / duration, "bytes_per_sec": total_bytes / duration,
        "bytes_per_packet": mean_len, "src_to_dst_packets": len(s2d),
        "dst_to_src_packets": len(d2s),
        "src_to_dst_bytes": sum(get(p, "length", 0) for p in s2d),
        "dst_to_src_bytes": sum(get(p, "length", 0) for p in d2s),
        "syn_count": syn, "ack_count": ack, "fin_count": fin,
        "rst_count": rst, "psh_count": psh,
        "syn_ack_ratio": syn / max(ack, 1),
        "avg_packet_size": mean_len, "packet_size_std": math.sqrt(var),
        "iat_mean": sum(iats) / len(iats) if iats else 0.0,
        "iat_std": (sum((x - sum(iats) / len(iats)) ** 2 for x in iats) / len(iats)) ** 0.5 if iats else 0.0,
        "iat_min": min(iats) if iats else 0.0, "iat_max": max(iats) if iats else 0.0,
        "unique_dst_ports": len(ports), "port_entropy": _entropy(ports),
        "tcp_ratio": protos.get("TCP", 0) / n, "udp_ratio": protos.get("UDP", 0) / n,
        "icmp_ratio": protos.get("ICMP", 0) / n, "arp_count": protos.get("ARP", 0),
        "dns_query_len": dns, "payload_mean": pm, "payload_std": math.sqrt(pv),
        "payload_max": max(payloads) if payloads else 0,
        "http_len": len(http), "sqli_score": sqli, "xss_score": xss,
        "failed_login": fails, "dst_port": dport,
        "protocol_TCP": 1.0 if proto == "TCP" else 0.0,
        "protocol_UDP": 1.0 if proto == "UDP" else 0.0,
        "protocol_ICMP": 1.0 if proto == "ICMP" else 0.0,
        "is_well_known_port": 1.0 if dport < 1024 else 0.0,
    }


def features_to_vector(feats: dict) -> list[float]:
    return [float(feats.get(k, 0.0)) for k in FEATURE_NAMES]
