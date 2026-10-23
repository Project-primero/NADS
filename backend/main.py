"""FastAPI entry point: capture -> flows -> signature+ML -> correlation -> alerts -> WS."""
from __future__ import annotations
import asyncio
import os
import sys
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
from backend.monitor.site_checker import SiteMonitor
from backend.api import routes, websocket

# Startup validation & notifications
if settings.capture_mode == "live":
    host_ifaces = [i["name"] for i in PacketCapture.get_host_interfaces()]
    if settings.interface not in host_ifaces:
        print(f"⚠️  [CONFIG WARNING] Interface '{settings.interface}' not found on host. Available interfaces: {', '.join(host_ifaces)}")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"ℹ️  [PERMISSION NOTICE] Live capture requires raw socket privilege. Run with sudo or grant CAP_NET_RAW: sudo setcap cap_net_raw,cap_net_admin=eip {sys.executable}")

db = Database(settings.db_path)
capture = PacketCapture(
    interface=settings.interface,
    mode=settings.capture_mode,
    bpf_filter=settings.bpf_filter
)
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


def _push_monitor_alert(pushed: dict) -> None:
    try:
        loop = asyncio.get_event_loop()
        loop.call_soon_threadsafe(
            lambda p=pushed: asyncio.ensure_future(websocket.push_alert(p)))
    except RuntimeError:
        pass


monitor = SiteMonitor(db, alerts, on_alert=_push_monitor_alert,
                      allow_private=settings.allow_private_targets,
                      timeout=settings.site_check_timeout)

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
         "recent_packets": recent_packets, "monitor": monitor,
         "default_interval": settings.site_check_default_interval,
         "learning_mode": settings.learning_mode}
routes.init(state)
websocket.init(state)


def _on_packet(pkt: dict) -> None:
    now = time.time()
    pkt["_ts"] = now
    src_ip = pkt.get("src_ip", "?")
    dst_ip = pkt.get("dst_ip", "?")
    sport = int(pkt.get("src_port", 0) or 0)
    dport = int(pkt.get("dst_port", 0) or 0)

    recent_packets.append({k: pkt.get(k) for k in
                           ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "flags")})
    proto_counts[pkt.get("protocol", "OTHER")] += 1
    talker_bytes[src_ip] += int(pkt.get("length", 0))
    talker_packets[src_ip] += 1
    _tick_pkts[0] += 1

    # Discover and update Assets
    db.touch_asset(src_ip)
    db.touch_asset(dst_ip)

    if now - _last_tick[0] >= 1.0:
        traffic_series.append({"ts": int(now), "pps": capture.current_pps(),
                               "packets": capture.stats["packets"]})
        _last_tick[0] = now
        _tick_pkts[0] = 0
        flows.expire()

    # Check allowlist — trusted scanners / backup servers never generate alerts
    if db.is_allowlisted(src_ip, sport) or db.is_allowlisted(dst_ip, dport):
        return

    flow = flows.ingest(pkt)
    sig_alerts = sig.check_packet(pkt)

    ml_res = None
    if len(flow.packets) % 10 == 0:
        ml_res = ml.analyze_flow(flow)

    # In Learning Mode, we train/extract features but suppress alerting
    if state.get("learning_mode", False):
        return

    final = correlate(sig_alerts, ml_res)
    if final:
        # Tag alert with agent site/computer if available
        if pkt.get("_agent_id"):
            final["agent_id"] = pkt["_agent_id"]
        if pkt.get("_site"):
            final["site"] = pkt["_site"]

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
    # seed default site on first boot
    if settings.seed_site_url and not db.list_sites():
        db.add_site("Primary site", settings.seed_site_url,
                    settings.site_check_default_interval)
    monitor.start()
    yield
    await monitor.stop()
    capture.stop()
    task.cancel()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])
app.include_router(routes.router, prefix="/api")


@app.websocket("/ws")
async def ws(ws: WebSocket):
    await websocket.handler(ws)


@app.websocket("/ws/agent")
async def ws_agent(ws: WebSocket):
    await websocket.agent_handler(ws)


@app.get("/")
def root():
    return {"app": settings.app_name, "mode": capture.mode, "source": capture.current_source_info,
            "docs": "/docs", "detectors": sorted(CATALOG.keys())}
