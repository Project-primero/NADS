"""WebSocket live streaming: stats + alerts + analytics snapshot."""
import asyncio
import json
from fastapi import WebSocket

_state: dict = {}
_clients: set[WebSocket] = set()


def init(state: dict):
    global _state
    _state = state


def snapshot() -> dict:
    cap = _state["capture"]
    return {"type": "stats",
            "packets": cap.stats["packets"],
            "pps": cap.current_pps(),
            "active_flows": len(_state["flows"].flows),
            "alerts": _state["alerts"].recent(25),
            "counts": _state["alerts"].counts,
            "attack_mix": dict(_state["attack_mix"]),
            "protocols": dict(_state["proto_counts"]),
            "series": list(_state["traffic_series"])[-60:]}


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
    for ws in list(_clients):
        try:
            await ws.send_text(msg)
        except Exception:
            _clients.discard(ws)
