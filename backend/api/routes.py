"""REST endpoints: stats, alerts, flows, analytics, catalog, sites."""
import asyncio
import time
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter()
_state: dict = {}


def init(state: dict):
    global _state
    _state = state


class SiteIn(BaseModel):
    name: str = ""
    url: str
    interval: int = 60


class SiteUpdate(BaseModel):
    name: str | None = None
    interval: int | None = None
    enabled: bool | None = None


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


# ── Sites ────────────────────────────────────────────────

@router.get("/sites")
def list_sites():
    mon = _state.get("monitor")
    summaries = mon.snapshot() if mon else []
    # merge full site rows with monitor snapshots
    rows = {s["id"]: s for s in _state["db"].list_sites()}
    merged = []
    for snap in summaries:
        row = rows.get(snap["id"], {})
        merged.append({**row, **snap})
    # include sites with no check yet
    seen = {m["id"] for m in merged}
    for sid, row in rows.items():
        if sid not in seen:
            merged.append({**row, "up": None, "status_code": 0, "latency_ms": 0,
                           "error": "", "tls_days_left": -1, "tls_issuer": "",
                           "security_score": 0, "server_banner": "",
                           "findings": [], "uptime_24h": -1.0})
    return {"sites": merged}


@router.post("/sites")
async def add_site(body: SiteIn):
    url = body.url.strip().rstrip("/")
    if not url:
        raise HTTPException(400, "url is required")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        site = _state["db"].add_site(body.name.strip() or url, url,
                                     body.interval or _state.get("default_interval", 60))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"failed to save site: {e}") from e
    mon = _state.get("monitor")
    check = None
    if mon:
        try:
            check = await mon.check_now(site)
        except Exception as e:  # noqa: BLE001
            # site is saved even if the first probe fails
            check = mon._error_check(site, f"initial probe error: {e}")
    merged_site = {**site}
    if check:
        merged_site.update({
            "up": check.get("up"),
            "status_code": check.get("status_code", 0),
            "latency_ms": check.get("latency_ms", 0.0),
            "error": check.get("error", ""),
            "tls_days_left": check.get("tls_days_left", -1),
            "tls_issuer": check.get("tls_issuer", ""),
            "tls_valid": check.get("tls_valid", False),
            "tls_proto": check.get("tls_proto", ""),
            "tls_cipher": check.get("tls_cipher", ""),
            "security_score": check.get("security_score", 0),
            "server_banner": check.get("server_banner", ""),
            "technology": check.get("technology", ""),
            "headers": check.get("headers", {}),
            "findings": check.get("findings", []),
            "uptime_24h": 100.0 if check.get("up") else 0.0,
        })
    return {"site": merged_site, "check": check}


@router.delete("/sites/{site_id}")
def delete_site(site_id: int):
    ok = _state["db"].delete_site(site_id)
    if not ok:
        raise HTTPException(404, "site not found")
    return {"deleted": site_id}


@router.get("/sites/{site_id}/history")
def site_history(site_id: int, limit: int = 288):
    site = _state["db"].get_site(site_id)
    if not site:
        raise HTTPException(404, "site not found")
    return {"site": site, "checks": _state["db"].get_checks(site_id, limit)}


@router.get("/sites/{site_id}/audit")
def site_audit(site_id: int):
    site = _state["db"].get_site(site_id)
    if not site:
        raise HTTPException(404, "site not found")
    checks = _state["db"].get_checks(site_id, 1)
    latest = checks[0] if checks else None
    return {"site": site, "audit": latest}


@router.post("/sites/{site_id}/check")
async def force_check(site_id: int):
    site = _state["db"].get_site(site_id)
    if not site:
        raise HTTPException(404, "site not found")
    mon = _state.get("monitor")
    if not mon:
        raise HTTPException(503, "monitor not running")
    check = await mon.check_now(site)
    return {"check": check}


@router.post("/sites/{site_id}/scan-now")
async def scan_now(site_id: int):
    return await force_check(site_id)


@router.post("/sites/scan-all")
async def scan_all():
    mon = _state.get("monitor")
    if not mon:
        raise HTTPException(503, "monitor not running")
    sites = _state["db"].list_sites()
    tasks = [mon.check_now(site) for site in sites if site.get("enabled", True)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return {"scanned": len(tasks), "results_count": len(results)}


class InstantScanIn(BaseModel):
    url: str
    name: str = ""


@router.post("/scanner/instant")
async def scanner_instant(body: InstantScanIn):
    raw_url = body.url.strip()
    if not raw_url:
        raise HTTPException(400, "URL is required")
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    fake_site = {
        "id": 0,
        "name": body.name.strip() or raw_url,
        "url": raw_url,
        "check_interval_sec": 60,
        "enabled": True,
    }
    mon = _state.get("monitor")
    if not mon:
        raise HTTPException(503, "monitor not running")
    import httpx
    from backend.monitor.site_checker import BROWSER_HEADERS, check_site
    try:
        async with httpx.AsyncClient(timeout=mon.timeout, headers=BROWSER_HEADERS, follow_redirects=True) as client:
            check = await check_site(client, fake_site, mon.allow_private)
    except Exception as e:  # noqa: BLE001
        check = mon._error_check(fake_site, f"scan error: {e}")
    merged_site = {
        **fake_site,
        "up": check.get("up"),
        "status_code": check.get("status_code", 0),
        "latency_ms": check.get("latency_ms", 0.0),
        "error": check.get("error", ""),
        "tls_days_left": check.get("tls_days_left", -1),
        "tls_issuer": check.get("tls_issuer", ""),
        "tls_valid": check.get("tls_valid", False),
        "tls_proto": check.get("tls_proto", ""),
        "tls_cipher": check.get("tls_cipher", ""),
        "security_score": check.get("security_score", 0),
        "server_banner": check.get("server_banner", ""),
        "technology": check.get("technology", ""),
        "headers": check.get("headers", {}),
        "findings": check.get("findings", []),
        "uptime_24h": 100.0 if check.get("up") else 0.0,
    }
    return {"site": merged_site, "check": check}


@router.get("/sites/summary")
def sites_summary():
    mon = _state.get("monitor")
    summaries = mon.snapshot() if mon else []
    total = len(summaries)
    if total == 0:
        return {
            "total_sites": 0,
            "avg_security_score": 100.0,
            "up_count": 0,
            "down_count": 0,
            "critical_high_count": 0,
            "tls_expiring_count": 0,
            "avg_uptime_24h": 100.0,
        }
    scores = [s.get("security_score", 0) for s in summaries if s.get("security_score") is not None]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 100.0
    up_count = sum(1 for s in summaries if s.get("up") is True)
    down_count = sum(1 for s in summaries if s.get("up") is False)
    tls_expiring = sum(1 for s in summaries if 0 <= s.get("tls_days_left", -1) < 30)

    crit_high = 0
    for s in summaries:
        for f in s.get("findings", []):
            if f.get("severity") in ("CRITICAL", "HIGH"):
                crit_high += 1

    uptimes = [s.get("uptime_24h", -1.0) for s in summaries if s.get("uptime_24h", -1.0) >= 0]
    avg_uptime = round(sum(uptimes) / len(uptimes), 1) if uptimes else 100.0

    return {
        "total_sites": total,
        "avg_security_score": avg_score,
        "up_count": up_count,
        "down_count": down_count,
        "critical_high_count": crit_high,
        "tls_expiring_count": tls_expiring,
        "avg_uptime_24h": avg_uptime,
    }


@router.get("/sites/{site_id}/trend")
def site_trend(site_id: int, limit: int = 48):
    site = _state["db"].get_site(site_id)
    if not site:
        raise HTTPException(404, "site not found")
    checks = _state["db"].get_checks(site_id, limit)
    trend = []
    for c in reversed(checks):
        crit_count = sum(1 for f in c.get("findings", []) if f.get("severity") in ("CRITICAL", "HIGH"))
        trend.append({
            "id": c.get("id"),
            "ts": c.get("ts"),
            "score": c.get("security_score", 0),
            "up": c.get("up", False),
            "latency": c.get("latency_ms", 0.0),
            "status_code": c.get("status_code", 0),
            "findings_count": len(c.get("findings", [])),
            "critical_high_count": crit_count,
        })
    return {"site": site, "trend": trend}


@router.patch("/sites/{site_id}")
def update_site(site_id: int, body: SiteUpdate):
    site = _state["db"].update_site(site_id, name=body.name, interval=body.interval, enabled=body.enabled)
    if not site:
        raise HTTPException(404, "site not found")
    return {"site": site}


@router.get("/sites/{site_id}/report")
def site_report(site_id: int):
    site = _state["db"].get_site(site_id)
    if not site:
        raise HTTPException(404, "site not found")
    checks = _state["db"].get_checks(site_id, 1)
    latest = checks[0] if checks else {}
    is_up = bool(latest.get("up"))
    score = latest.get("security_score", 0) if is_up else 0
    grade = ("A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 35 else "F") if is_up else "F"
    findings = latest.get("findings", [])

    categorized = {}
    for f in findings:
        cat = f.get("category", "General") or "General"
        categorized.setdefault(cat, []).append(f)

    report_payload = {
        "platform": "Website Security Monitoring & Vulnerability Assessment Platform",
        "generated_at": time.time(),
        "target": {
            "id": site.get("id"),
            "name": site.get("name"),
            "url": site.get("url"),
            "check_interval_sec": site.get("check_interval_sec"),
        },
        "executive_summary": {
            "security_score": score,
            "security_grade": grade,
            "status": "UP" if latest.get("up") else "DOWN",
            "http_status_code": latest.get("status_code", 0),
            "response_latency_ms": latest.get("latency_ms", 0.0),
            "uptime_24h_pct": _state["db"].uptime_24h(site_id),
            "total_findings": len(findings),
            "critical_findings": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high_findings": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "medium_findings": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "low_findings": sum(1 for f in findings if f.get("severity") == "LOW"),
            "info_findings": sum(1 for f in findings if f.get("severity") == "INFO"),
        },
        "tls_cryptography": {
            "valid": latest.get("tls_valid", False),
            "days_until_expiration": latest.get("tls_days_left", -1),
            "issuer": latest.get("tls_issuer", ""),
            "protocol_negotiated": latest.get("tls_proto", ""),
            "cipher_suite": latest.get("tls_cipher", ""),
        },
        "technologies_fingerprinted": latest.get("technology", ""),
        "server_banner": latest.get("server_banner", ""),
        "response_headers": latest.get("headers", {}),
        "vulnerabilities_by_category": categorized,
        "findings_remediation_catalog": [
            {
                "title": f.get("title"),
                "severity": f.get("severity"),
                "category": f.get("category"),
                "description": f.get("description"),
                "evidence": f.get("evidence"),
                "cwe": f.get("cwe"),
                "mitre_technique": f.get("mitre"),
                "prescriptive_remediation": f.get("remediation"),
            }
            for f in findings
        ],
    }

    sanitized_name = "".join(c if c.isalnum() else "_" for c in site.get("name", "site"))
    filename = f"security_vulnerability_report_{sanitized_name}_{int(time.time())}.json"
    return JSONResponse(
        content=report_payload,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
