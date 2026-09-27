"""FastAPI entry point: capture -> flows -> signature+ML -> correlation -> alerts -> WS."""
from __future__ import annotations
import asyncio
import time
from collections import Counter, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.capture.packet_capture import PacketCapture
from backend.flow.flow_manager import FlowManager
from backend.detection.signature_engine import SignatureEngine, CATALOG
from backend.detection.inference import DetectionEngine
from backend.detection.correlation import correlate
from backend.alerts.alert_manager import AlertManager
from backend.database.db import Database
from backend.api import routes, websocket

db = Database(settings.db_path)
capture = PacketCapture(settings.interface, settings.capture_mode)
flows = FlowManager(settings.flow_timeout)
sig = SignatureEngine(port_scan_ports=settings.port_scan_ports,
                      port_scan_window=settings.port_scan_window,
                      syn_flood_count=settings.syn_flood_count,
                      syn_flood_window=settings.syn_flood_window,
                      udp_flood_count=settings.udp_flood_count,
                      udp_flood_window=settings.udp_flood_window,
                      icmp_flood_count=settings.icmp_flood_count,
                      icmp_flood_window=settings.icmp_flood_window,
                      ddos_pps=settings.ddos_pps,
                      brute_force_fails=settings.brute_force_fails,
                      brute_force_window=settings.brute_force_window,
                      dns_tunnel_len=settings.dns_tunnel_len,
                      exfil_bytes=settings.exfil_bytes,
                      sweep_dsts=settings.sweep_dsts,
                      sweep_window=settings.sweep_window,
                      horiz_dsts=settings.horiz_dsts,
                      horiz_window=settings.horiz_window,
                      spray_dsts=settings.spray_dsts,
                      smb_count=settings.smb_count,
                      smb_window=settings.smb_window,
                      slowloris_count=settings.slowloris_count,
                      slowloris_window=settings.slowloris_window,
                      amp_count=settings.amp_count,
                      amp_window=settings.amp_window)
ml = DetectionEngine(settings.anomaly_threshold, f"{settings.model_dir}/hybrid.pkl")
alerts = AlertManager(save_fn=db.save_alert)

# analytics ring buffers (per-second)
traffic_series: deque = deque(maxlen=120)   # [(ts, packets, pps)]
attack_mix: Counter = Counter()
proto_counts: Counter = Counter()
talker_bytes: Counter = Counter()
talker_packets: Counter = Counter()
recent_packets: deque = deque(maxlen=200)
_last_tick = [time.time()]
_tick_pkts = [0]

state = {"capture": capture, "flows": flows, "alerts": alerts, "db": db,
         "catalog": CATALOG, "traffic_series": traffic_series,
         "attack_mix": attack_mix, "proto_counts": proto_counts,
         "talker_bytes": talker_bytes, "talker_packets": talker_packets,
         "recent_packets": recent_packets}
routes.init(state)
websocket.init(state)


def _on_packet(pkt: dict) -> None:
    now = time.time()
    pkt["_ts"] = now
    recent_packets.append({k: pkt.get(k) for k in
                           ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "flags")})
    proto_counts[pkt.get("protocol", "OTHER")] += 1
    talker_bytes[pkt.get("src_ip", "?")] += int(pkt.get("length", 0))
    talker_packets[pkt.get("src_ip", "?")] += 1
    _tick_pkts[0] += 1
    if now - _last_tick[0] >= 1.0:
        traffic_series.append({"ts": int(now), "pps": capture.current_pps(),
                               "packets": capture.stats["packets"]})
        _last_tick[0] = now
        _tick_pkts[0] = 0

    flow = flows.ingest(pkt)
    sig_alerts = sig.check_packet(pkt)

    ml_res = None
    if len(flow.packets) % 10 == 0:
        ml_res = ml.analyze_flow(flow)

    final = correlate(sig_alerts, ml_res)
    if final:
        attack_mix[final["attack_type"]] += 1
        pushed = alerts.push(final)
        if pushed:
            try:
                loop = asyncio.get_event_loop()
                loop.call_soon_threadsafe(
                    lambda p=pushed: asyncio.ensure_future(websocket.push_alert(p)))
            except RuntimeError:
                pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    capture.add_handler(_on_packet)
    capture.start()
    task = asyncio.ensure_future(websocket.broadcast_loop())
    yield
    capture.stop()
    task.cancel()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(routes.router, prefix="/api")


@app.websocket("/ws")
async def ws(ws: WebSocket):
    await websocket.handler(ws)


@app.get("/")
def root():
    return {"app": settings.app_name, "mode": settings.capture_mode, "docs": "/docs",
            "detectors": sorted(CATALOG.keys())}
