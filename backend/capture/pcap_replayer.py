"""PCAP/PCAPNG Replay Engine for offline traffic analysis."""
from __future__ import annotations
import os
import threading
import time
from typing import Callable

PacketHandler = Callable[[dict], None]


class PcapReplayer:
    def __init__(self, filepath: str, handler: PacketHandler, speed: str = "instant",
                 on_progress: Callable[[dict], None] | None = None):
        self.filepath = filepath
        self.handler = handler
        self.speed = speed
        self.on_progress = on_progress
        self._running = False
        self._thread: threading.Thread | None = None
        self.stats = {
            "total_packets": 0,
            "processed_packets": 0,
            "alerts_triggered": 0,
            "status": "QUEUED",
            "error": "",
            "start_time": 0.0,
            "end_time": 0.0,
        }

    def _get_speed_delay(self, delta_ts: float) -> float:
        if self.speed == "instant":
            return 0.0
        if self.speed == "realtime":
            return max(0.0, min(delta_ts, 1.0))
        if self.speed.endswith("x"):
            try:
                mult = float(self.speed[:-1])
                return max(0.0, min(delta_ts / mult, 1.0))
            except ValueError:
                pass
        return 0.001

    def _replay_worker(self) -> None:
        self.stats["status"] = "RUNNING"
        self.stats["start_time"] = time.time()
        self._running = True

        try:
            from scapy.utils import PcapReader
            from backend.capture.packet_parser import parse_raw, dict_from_parsed
        except ImportError:
            self.stats["status"] = "FAILED"
            self.stats["error"] = "Scapy is required for PCAP parsing"
            return

        if not os.path.exists(self.filepath):
            self.stats["status"] = "FAILED"
            self.stats["error"] = f"File not found: {self.filepath}"
            return

        last_pkt_time = None
        processed = 0

        try:
            reader = PcapReader(self.filepath)
            for pkt in reader:
                if not self._running:
                    self.stats["status"] = "STOPPED"
                    break

                # Timing calculation
                pkt_time = float(getattr(pkt, "time", time.time()))
                if last_pkt_time is not None and self.speed != "instant":
                    delta = pkt_time - last_pkt_time
                    delay = self._get_speed_delay(delta)
                    if delay > 0.0001:
                        time.sleep(delay)
                last_pkt_time = pkt_time

                parsed = parse_raw(pkt)
                if parsed is not None:
                    d = dict_from_parsed(parsed)
                    self.handler(d)

                processed += 1
                self.stats["processed_packets"] = processed

                if processed % 50 == 0 and self.on_progress:
                    self.on_progress(dict(self.stats))

            reader.close()
            if self._running:
                self.stats["status"] = "COMPLETED"
        except Exception as e:
            self.stats["status"] = "FAILED"
            self.stats["error"] = str(e)
        finally:
            self.stats["end_time"] = time.time()
            self._running = False
            if self.on_progress:
                self.on_progress(dict(self.stats))

    def start(self) -> None:
        if self._running:
            return
        self._thread = threading.Thread(target=self._replay_worker, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
