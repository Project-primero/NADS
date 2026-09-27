"""5-tuple flow tracking with timeout expiry."""
from __future__ import annotations
import time
from dataclasses import dataclass, field


@dataclass
class Flow:
    key: tuple
    start_time: float
    last_seen: float
    packets: list[dict] = field(default_factory=list)
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""

    @property
    def duration(self) -> float:
        return max(self.last_seen - self.start_time, 1e-6)

    def add(self, pkt: dict) -> None:
        self.packets.append(pkt)
        self.last_seen = time.time()


def flow_key(pkt: dict) -> tuple:
    s = (pkt.get("src_ip"), pkt.get("src_port"), pkt.get("dst_ip"),
         pkt.get("dst_port"), pkt.get("protocol"))
    r = (pkt.get("dst_ip"), pkt.get("dst_port"), pkt.get("src_ip"),
         pkt.get("src_port"), pkt.get("protocol"))
    return min(s, r)  # direction-agnostic


class FlowManager:
    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.flows: dict[tuple, Flow] = {}
        self.completed: int = 0

    def ingest(self, pkt: dict) -> Flow:
        key = flow_key(pkt)
        now = time.time()
        f = self.flows.get(key)
        if f is None:
            f = Flow(key=key, start_time=now, last_seen=now,
                     src_ip=pkt.get("src_ip", ""), dst_ip=pkt.get("dst_ip", ""),
                     src_port=pkt.get("src_port", 0), dst_port=pkt.get("dst_port", 0),
                     protocol=pkt.get("protocol", ""))
            self.flows[key] = f
        f.add(pkt)
        return f

    def expire(self) -> list[Flow]:
        """Return and remove flows older than timeout."""
        now = time.time()
        dead = [k for k, f in self.flows.items() if now - f.last_seen > self.timeout]
        out = [self.flows.pop(k) for k in dead]
        self.completed += len(out)
        return out

    def active_flows(self) -> list[Flow]:
        self.expire()
        return list(self.flows.values())
