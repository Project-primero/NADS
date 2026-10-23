"""WebSocket live streaming: stats + alerts + analytics snapshot + agent ingest."""
import asyncio
import json
import time
from fastapi import WebSocket

_state: dict = {}
_clients: set[WebSocket] = set()


def init(state: dict):
    global _state
    _state = state


def snapshot() -> dict:
    cap = _state["capture"]
    mon = _state.get("monitor")
    db = _state.get("db")
    agents = db.list_agents() if db else []
    online_count = sum(1 for a in agents if a.get("status") == "ONLINE")

    return {
        "type": "stats",
        "packets": cap.stats["packets"],
        "pps": cap.current_pps(),
        "active_flows": len(_state["flows"].flows),
        "alerts": _state["alerts"].recent(25),
        "counts": _state["alerts"].counts,
        "attack_mix": dict(_state["attack_mix"]),
        "protocols": dict(_state["proto_counts"]),
        "series": list(_state["traffic_series"])[-60:],
        "sites": mon.snapshot() if mon else [],
        "connect": cap.get_status(),
        "learning_mode": bool(_state.get("learning_mode", False)),
        "online_agents": online_count,
        "total_agents": len(agents)
    }


async def broadcast_loop():
    while True:
        if _clients and _state:
            msg = json.dumps(snapshot(), default=str)
            dead = []
            for ws in _clients:
                try:
                    await ws.send_text(msg)
                except Exception:
                    dead.append(ws)
            for d in dead:
                _clients.discard(d)
        await asyncio.sleep(1.0)


async def handler(ws: WebSocket):
    await ws.accept()
    _clients.add(ws)
    try:
        # immediate snapshot on connect
        await ws.send_text(json.dumps(snapshot(), default=str))
        while True:
            await ws.receive_text()
    except Exception:
        pass
    finally:
        _clients.discard(ws)


async def push_alert(alert: dict):
    msg = json.dumps({"type": "alert", **alert}, default=str)
    dead = []
    for ws in _clients:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for d in dead:
        _clients.discard(d)


async def agent_handler(ws: WebSocket):
    """Authenticated WebSocket stream for remote computer agents."""
    await ws.accept()
    db = _state.get("db")
    cap = _state.get("capture")
    agent_info = None

    try:
        # Step 1: Wait for auth handshake
        auth_raw = await asyncio.wait_for(ws.receive_text(), timeout=10.0)
        auth_data = json.loads(auth_raw)
        token = auth_data.get("token", "")
        agent = db.verify_agent_token(token) if db else None

        if not agent:
            await ws.send_text(json.dumps({"ok": False, "error": "Unauthorized: invalid or revoked token"}))
            await ws.close(code=4001)
            return

        agent_info = agent
        db.update_agent_telemetry(
            agent_id=agent["agent_id"],
            ip=auth_data.get("ip", ""),
            hostname=auth_data.get("hostname", ""),
            os_name=auth_data.get("os", "")
        )
        await ws.send_text(json.dumps({"ok": True, "agent_id": agent["agent_id"], "site": agent["site"]}))

        # Step 2: Stream packets and telemetry
        while True:
            msg_raw = await ws.receive_text()
            data = json.loads(msg_raw)
            msg_type = data.get("type", "packets")

            if msg_type == "packets":
                pkts = data.get("packets", [])
                pps = float(data.get("pps", 0.0))
                for pkt in pkts:
                    cap.ingest_remote_packet(pkt, agent_id=agent["agent_id"], site=agent["site"])
                db.update_agent_telemetry(agent_id=agent["agent_id"], pps=pps, packets_inc=len(pkts))
            elif msg_type == "heartbeat":
                db.update_agent_telemetry(agent_id=agent["agent_id"], pps=float(data.get("pps", 0.0)))

    except Exception:
        pass
    finally:
        if agent_info and db:
            pass
