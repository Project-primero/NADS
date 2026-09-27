"""Alert manager: dedup, severity scoring, persistence hook."""
from __future__ import annotations
import time
from collections import deque

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class AlertManager:
    def __init__(self, dedup_window: int = 60, max_history: int = 1000,
                 save_fn=None):
        self.dedup_window = dedup_window
        self.history: deque = deque(maxlen=max_history)
        self._seen: dict[tuple, float] = {}
        self.save_fn = save_fn
        self.counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    def _dedup_key(self, a: dict) -> tuple:
        return (a.get("attack_type"), a.get("src_ip"), a.get("dst_ip"),
                a.get("dst_port"))

    def push(self, alert: dict) -> dict | None:
        """Return alert if new, None if duplicate within window."""
        now = time.time()
        key = self._dedup_key(alert)
        if key in self._seen and now - self._seen[key] < self.dedup_window:
            return None
        self._seen[key] = now
        alert = {**alert, "timestamp": now, "id": len(self.history) + 1}
        self.history.append(alert)
        self.counts[alert.get("severity", "LOW")] = \
            self.counts.get(alert.get("severity", "LOW"), 0) + 1
        if self.save_fn:
            try:
                self.save_fn(alert)
            except Exception:
                pass
        return alert

    def recent(self, n: int = 50) -> list[dict]:
        return list(self.history)[-n:][::-1]
