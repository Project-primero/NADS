"""Generate a labeled flow dataset: data/nad_dataset.csv

Usage:
    /tmp/nadvenv/bin/python scripts/generate_dataset.py [--flows 6000] [--out data/nad_dataset.csv] [--seed 42]

Each row = 41 CIC-IDS style features + label (Normal|<Attack>) + attack_type.
Compatible with: train_model.py --dataset data/nad_dataset.csv
"""
from __future__ import annotations
import argparse
import csv
import random
from types import SimpleNamespace

from backend.flow.feature_extractor import FEATURE_NAMES, extract_features


def _pkt(src="192.168.1.10", dst="192.168.1.20", sport=1234, dport=80,
         proto="TCP", length=500, flags="PA", payload=400, ts=0.0,
         dns="", http=""):
    return {"src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "protocol": proto, "length": length, "flags": flags,
            "payload_len": payload, "_ts": ts, "dns_query": dns,
            "http_payload": http, "payload_text": http}


def _flow(packets, src, dst, sport, dport, proto):
    return SimpleNamespace(packets=packets, src_ip=src, dst_ip=dst,
                           src_port=sport, dst_port=dport, protocol=proto,
                           duration=max(packets[-1]["_ts"] - packets[0]["_ts"], 1e-3))


def benign(rng: random.Random):
    n = rng.randint(5, 40)
    dur = rng.uniform(1, 60)
    dport = rng.choice([80, 443, 22, 53, 3306])
    pkts = [_pkt(sport=rng.randint(1024, 65535), dport=dport,
                 proto=rng.choice(["TCP", "TCP", "TCP", "UDP"]),
                 length=rng.randint(60, 1500), payload=rng.randint(0, 1400),
                 ts=i * dur / n) for i in range(n)]
    return _flow(pkts, pkts[0]["src_ip"], pkts[0]["dst_ip"],
                 pkts[0]["src_port"], dport, pkts[0]["protocol"]), "Normal"


def syn_flood(rng: random.Random):
    n = rng.randint(60, 200)
    dur = rng.uniform(2, 5)
    pkts = [_pkt(src=f"172.16.0.{rng.randint(2, 60)}", dport=80, length=60,
                 flags="S", payload=0, ts=i * dur / n) for i in range(n)]
    return _flow(pkts, pkts[0]["src_ip"], pkts[0]["dst_ip"],
                 pkts[0]["src_port"], 80, "TCP"), "SYN Flood"


def udp_flood(rng: random.Random):
    n = rng.randint(80, 250)
    dur = rng.uniform(2, 6)
    pkts = [_pkt(src=f"172.16.1.{rng.randint(2, 60)}",
                 dport=rng.randint(1000, 6000), proto="UDP",
                 length=rng.randint(64, 512), flags="", payload=100,
                 ts=i * dur / n) for i in range(n)]
    return _flow(pkts, pkts[0]["src_ip"], pkts[0]["dst_ip"],
                 pkts[0]["src_port"], pkts[0]["dst_port"], "UDP"), "UDP Flood"


def brute_force(rng: random.Random):
    n = rng.randint(12, 30)
    dur = rng.uniform(30, 200)
    pkts = [_pkt(src="10.0.0.77", dport=22, length=90, payload=40,
                 ts=i * dur / n, http="SSH Failed password for root")
            for i in range(n)]
    return _flow(pkts, "10.0.0.77", pkts[0]["dst_ip"],
                 pkts[0]["src_port"], 22, "TCP"), "SSH Brute Force"


def dns_tunnel(rng: random.Random):
    n = rng.randint(5, 15)
    q = "x" * rng.randint(55, 90) + ".evil.example.com"
    pkts = [_pkt(dport=53, proto="UDP", length=150, flags="", payload=110,
                 ts=i * 0.5, dns=q) for i in range(n)]
    return _flow(pkts, pkts[0]["src_ip"], "8.8.8.8",
                 pkts[0]["src_port"], 53, "UDP"), "DNS Tunneling"


def port_scan(rng: random.Random):
    # one scanner flow touching many ports (aggregated recon behavior)
    n = rng.randint(16, 40)
    pkts = [_pkt(src="10.0.0.99", dport=rng.randint(1, 2048), length=60,
                 flags="S", payload=0, ts=i * 0.2) for i in range(n)]
    return _flow(pkts, "10.0.0.99", pkts[0]["dst_ip"],
                 pkts[0]["src_port"], pkts[0]["dst_port"], "TCP"), "Port Scan"


def sqli(rng: random.Random):
    n = rng.randint(2, 6)
    pay = "GET /item?id=1' UNION SELECT password FROM users-- "
    pkts = [_pkt(src="45.33.9.9", dport=80, length=500, payload=400,
                 ts=i * 0.5, http=pay) for i in range(n)]
    return _flow(pkts, "45.33.9.9", pkts[0]["dst_ip"],
                 pkts[0]["src_port"], 80, "TCP"), "SQL Injection"


def exfil(rng: random.Random):
    n = rng.randint(200, 600)
    dur = rng.uniform(10, 60)
    pkts = [_pkt(dport=443, length=1500, payload=1440, ts=i * dur / n)
            for i in range(n)]
    # make it one-sided: strip reverse traffic influence by single direction
    return _flow(pkts, pkts[0]["src_ip"], "203.0.113.9",
                 pkts[0]["src_port"], 443, "TCP"), "Data Exfiltration"


ATTACKS = [syn_flood, udp_flood, brute_force, dns_tunnel, port_scan, sqli, exfil]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=6000)
    ap.add_argument("--attack-ratio", type=float, default=0.33)
    ap.add_argument("--out", default="data/nad_dataset.csv")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    n_attack = int(args.flows * args.attack_ratio)
    n_normal = args.flows - n_attack
    rows = []
    for _ in range(n_normal):
        f, label = benign(rng)
        rows.append((f, label))
    for i in range(n_attack):
        f, label = ATTACKS[i % len(ATTACKS)](rng)
        rows.append((f, label))
    rng.shuffle(rows)

    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FEATURE_NAMES + ["label", "attack_type"])
        w.writeheader()
        for f, label in rows:
            feats = extract_features(f)
            w.writerow({**{k: round(float(feats[k]), 4) for k in FEATURE_NAMES},
                        "label": label, "attack_type": label})
    print(f"wrote {len(rows)} flows ({n_normal} normal, {n_attack} attack) -> {args.out}")


if __name__ == "__main__":
    main()
