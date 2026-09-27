"""REST endpoints: stats, alerts, flows, analytics, catalog."""
from fastapi import APIRouter

router = APIRouter()
_state: dict = {}


def init(state: dict):
    global _state
    _state = state


@router.get("/stats")
def stats():
    cap = _state["capture"]
    fm = _state["flows"]
    am = _state["alerts"]
    return {"packets": cap.stats["packets"], "pps": cap.current_pps(),
            "active_flows": len(fm.flows), "completed_flows": fm.completed,
            "alerts": dict(am.counts), "total_alerts": len(am.history)}


@router.get("/alerts")
def alerts(limit: int = 50):
    return {"alerts": _state["alerts"].recent(limit)}


@router.get("/alerts/history")
def history(limit: int = 100):
    return {"alerts": _state["db"].get_alerts(limit)}


@router.get("/flows")
def flows():
    out = []
    for f in list(_state["flows"].flows.values())[:60]:
        out.append({"src_ip": f.src_ip, "dst_ip": f.dst_ip,
                    "src_port": f.src_port, "dst_port": f.dst_port,
                    "protocol": f.protocol, "packets": len(f.packets),
                    "duration": round(f.duration, 2)})
    return {"flows": out}


@router.get("/analytics/traffic")
def traffic_series():
    return {"series": list(_state["traffic_series"]),
            "protocols": dict(_state["proto_counts"]),
            "attack_mix": dict(_state["attack_mix"]),
            "recent": list(_state["recent_packets"])[-40:]}


@router.get("/analytics/top-talkers")
def top_talkers(limit: int = 10):
    b = _state["talker_bytes"]
    p = _state["talker_packets"]
    ips = sorted(set(list(b) + list(p)), key=lambda ip: b.get(ip, 0), reverse=True)[:limit]
    return {"talkers": [{"ip": ip, "bytes": b.get(ip, 0),
                         "packets": p.get(ip, 0)} for ip in ips]}


@router.get("/catalog")
def catalog():
    return {"detectors": [{"attack": k, **v} for k, v in _state["catalog"].items()]}


@router.get("/health")
def health():
    return {"status": "ok"}
