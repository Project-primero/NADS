"""REST endpoints: stats, alerts, flows, analytics, catalog, sites, connect, agents, assets."""
import asyncio
import csv
import io
import os
import secrets
import shutil
import time
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
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


# ── Connect Models ───────────────────────────────────────
class ConnectStartIn(BaseModel):
    mode: str = "simulate"  # simulate | live | pcap | agent
    interface: str = "lo"
    intensity: str = "medium"  # low | medium | high | stress
    attacks: list[str] = ["all"]
    bpf_filter: str = ""
    promiscuous: bool = False
    speed: str = "instant"
    pcap_file: str = ""


class ConnectTestIn(BaseModel):
    interface: str = "lo"
    duration: int = 10


class AgentTokenIn(BaseModel):
    name: str = ""
    site: str = "Default Site"


class AgentVerifyIn(BaseModel):
    token: str
    hostname: str = ""
    site: str = "Default Site"
    name: str = ""
    ip: str = ""
    os: str = ""


class AgentIngestIn(BaseModel):
    agent_id: str = ""
    site: str = "Default Site"
    packets: list[dict] = []
    pps: float = 0.0


class AssetUpdateIn(BaseModel):
    hostname: str | None = None
    owner: str | None = None
    department: str | None = None
    device_type: str | None = None


class AllowlistIn(BaseModel):
    cidr_or_ip: str
    port: int = 0
    description: str = ""


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


@router.get("/alerts/export")
def export_alerts(format: str = "json", limit: int = 5000):
    records = _state["db"].export_alerts(limit)
    if format.lower() == "csv":
        output = io.StringIO()
        fieldnames = ["id", "timestamp", "attack_type", "severity", "description",
                      "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "anomaly_score"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow({k: r.get(k, "") for k in fieldnames})
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="nad_alerts_{int(time.time())}.csv"'}
        )
    return {"alerts": records, "count": len(records), "timestamp": time.time()}


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


# ── Universal Connect Endpoints ─────────────────────────

@router.get("/connect/interfaces")
def get_interfaces():
    cap = _state["capture"]
    return {"interfaces": cap.get_host_interfaces()}


@router.get("/connect/status")
def get_connect_status():
    cap = _state["capture"]
    status = cap.get_status()
    db = _state["db"]
    agents = db.list_agents()
    online_agents = [a for a in agents if a["status"] == "ONLINE"]
    status.update({
        "online_agents": len(online_agents),
        "total_agents": len(agents),
        "allowlist_rules": len(db.list_allowlist()),
        "learning_mode": bool(_state.get("learning_mode", False))
    })
    return status


@router.post("/connect/start")
def start_capture(body: ConnectStartIn):
    cap = _state["capture"]
    db = _state["db"]

    try:
        status = cap.switch_mode(
            mode=body.mode,
            interface=body.interface,
            intensity=body.intensity,
            attacks=body.attacks,
            bpf_filter=body.bpf_filter,
            promiscuous=body.promiscuous,
            speed=body.speed,
            pcap_file=body.pcap_file
        )
        db.log_audit("CONNECT_START", details=f"Switched mode to {body.mode} ({body.interface})")
        return {"ok": True, "status": status}
    except Exception as e:
        raise HTTPException(500, f"Failed to start capture: {e}") from e


@router.post("/connect/stop")
def stop_capture():
    cap = _state["capture"]
    db = _state["db"]
    cap.stop()
    db.log_audit("CONNECT_STOP", details=f"Stopped active capture mode ({cap.mode})")
    return {"ok": True, "status": cap.get_status()}


@router.post("/connect/test")
def test_interface(body: ConnectTestIn):
    cap = _state["capture"]
    res = cap.test_interface_traffic(interface=body.interface, duration=body.duration)
    return res


# ── PCAP File Ingestion ──────────────────────────────────

@router.post("/pcap/upload")
async def upload_pcap(request: Request, speed: str = "instant"):
    pcap_dir = "data/pcaps"
    os.makedirs(pcap_dir, exist_ok=True)
    job_id = f"job-{secrets.token_hex(6)}"

    filename = "capture.pcap"
    content_type = request.headers.get("content-type", "")
    save_path = os.path.join(pcap_dir, f"{job_id}_{filename}")
    size = 0

    if "multipart/form-data" in content_type:
        try:
            form = await request.form()
            uploaded_file = form.get("file")
            if uploaded_file and hasattr(uploaded_file, "filename"):
                filename = uploaded_file.filename
                save_path = os.path.join(pcap_dir, f"{job_id}_{filename}")
                content = await uploaded_file.read()
                size = len(content)
                if size > 100 * 1024 * 1024:
                    raise HTTPException(400, "File too large (max 100MB)")
                with open(save_path, "wb") as buffer:
                    buffer.write(content)
            else:
                raise HTTPException(400, "No file found in upload form")
        except RuntimeError as e:
            raise HTTPException(500, f"Multipart upload requires python-multipart: {e}") from e
    else:
        # Raw binary streaming upload
        content = await request.body()
        size = len(content)
        if size > 100 * 1024 * 1024:
            raise HTTPException(400, "File too large (max 100MB)")
        with open(save_path, "wb") as buffer:
            buffer.write(content)

    if not filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        if os.path.exists(save_path):
            os.remove(save_path)
        raise HTTPException(400, "Unsupported file format. Please upload .pcap or .pcapng")

    db = _state["db"]
    job = db.save_pcap_job(job_id=job_id, filename=filename, speed=speed)

    # Callback to update database during replay
    def _progress(stats: dict):
        db.update_pcap_job(
            job_id,
            total_packets=stats.get("total_packets", 0),
            processed_packets=stats.get("processed_packets", 0),
            alerts_count=stats.get("alerts_triggered", 0),
            status=stats.get("status", "RUNNING"),
            error=stats.get("error", "")
        )

    # Automatically launch replay in the pipeline
    cap = _state["capture"]
    cap.switch_mode(mode="pcap", pcap_file=save_path, speed=speed, on_progress=_progress)
    db.log_audit("PCAP_UPLOAD", details=f"Uploaded {filename} (Job {job_id})")

    return {"ok": True, "job_id": job_id, "filename": filename, "size_bytes": size}


@router.get("/pcap/status/{job_id}")
def pcap_status(job_id: str):
    db = _state["db"]
    job = db.get_pcap_job(job_id)
    if not job:
        raise HTTPException(404, "PCAP job not found")
    return {"job": job}


# ── Remote Computer Agents (Multi-Site / Universities) ───

@router.get("/agents")
def list_agents():
    db = _state["db"]
    return {"agents": db.list_agents()}


@router.post("/agents/tokens")
def create_agent_token(body: AgentTokenIn):
    db = _state["db"]
    agent_info = db.create_agent(name=body.name, site=body.site)
    db.log_audit("AGENT_TOKEN_CREATED", details=f"Created token for {agent_info['name']} ({agent_info['site']})")
    return {"ok": True, "agent": agent_info}


@router.post("/agents/verify")
def verify_agent(body: AgentVerifyIn):
    db = _state["db"]
    agent = db.verify_agent_token(body.token)
    if not agent:
        return JSONResponse(status_code=401, content={"ok": False, "error": "Invalid or revoked agent token"})

    db.update_agent_telemetry(
        agent_id=agent["agent_id"],
        ip=body.ip,
        hostname=body.hostname or body.name,
        os_name=body.os
    )
    return {"ok": True, "agent_id": agent["agent_id"], "site": agent["site"], "name": agent["name"]}


@router.post("/agents/ingest")
def ingest_agent_packets(body: AgentIngestIn, authorization: str = Header(None)):
    token = ""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()

    db = _state["db"]
    agent = db.verify_agent_token(token)
    if not agent:
        raise HTTPException(401, "Invalid agent authentication token")

    cap = _state["capture"]
    count = len(body.packets)
    for pkt in body.packets:
        cap.ingest_remote_packet(pkt, agent_id=agent["agent_id"], site=body.site or agent["site"])

    db.update_agent_telemetry(
        agent_id=agent["agent_id"],
        pps=body.pps,
        packets_inc=count
    )
    return {"ok": True, "ingested": count}


@router.delete("/agents/{agent_id}")
def delete_agent(agent_id: str):
    db = _state["db"]
    deleted = db.delete_agent(agent_id)
    if not deleted:
        raise HTTPException(404, "Agent not found")
    db.log_audit("AGENT_REVOKED", details=f"Revoked agent {agent_id}")
    return {"ok": True}


@router.get("/agents/install.sh")
def agent_installer(request: Request):
    base_url = str(request.base_url).rstrip("/")
    script = f"""#!/usr/bin/env bash
# Network Anomaly Detection Endpoint Agent Installer for Remote Computers & Universities
set -e
SERVER_URL="${{NAD_SERVER:-${{AEGIS_SERVER:-{base_url}}}}}"
TOKEN="$1"
SITE="${{2:-Default Site}}"
NAME="${{3:-$(hostname)}}"

if [ -z "$TOKEN" ]; then
  echo "Usage: curl -sSL $SERVER_URL/api/agents/install.sh | bash -s -- <TOKEN> [SITE] [NAME]"
  exit 1
fi

echo "=================================================="
echo "🛡️  Installing Network Anomaly Detection Endpoint Agent"
echo "Server : $SERVER_URL"
echo "Site   : $SITE"
echo "Node   : $NAME"
echo "=================================================="

INSTALL_DIR="${{HOME:-/tmp}}/.nad-agent"
mkdir -p "$INSTALL_DIR"
curl -sSL "$SERVER_URL/api/agents/script" -o "$INSTALL_DIR/agent.py"

python3 "$INSTALL_DIR/agent.py" --server "$SERVER_URL" --token "$TOKEN" --site "$SITE" --name "$NAME"
"""
    return PlainTextResponse(script)


@router.get("/agents/install.ps1")
def agent_installer_windows(request: Request):
    base_url = str(request.base_url).rstrip("/")
    script = f"""param(
    [Parameter(Position=0)]
    [string]$Token = "",
    [Parameter(Position=1)]
    [string]$Site = "Default Site",
    [Parameter(Position=2)]
    [string]$Name = $env:COMPUTERNAME
)
$ServerUrl = "{base_url}"
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "🛡️  Installing Network Anomaly Detection Agent (Windows)" -ForegroundColor Cyan
Write-Host "Server : $ServerUrl"
Write-Host "Site   : $Site"
Write-Host "Node   : $Name"
Write-Host "==================================================" -ForegroundColor Cyan

$AgentScript = "$env:TEMP\\aegis-agent.py"
Invoke-WebRequest -Uri "$ServerUrl/api/agents/script" -OutFile $AgentScript -UseBasicParsing
python $AgentScript --server "$ServerUrl" --token "$Token" --site "$Site" --name "$Name"
"""
    return PlainTextResponse(script)


@router.get("/agents/script")
def get_agent_script():
    agent_path = "scripts/aegis-agent.py"
    if os.path.exists(agent_path):
        with open(agent_path, "r") as f:
            return PlainTextResponse(f.read())
    raise HTTPException(404, "Agent script not found")


# ── Asset Inventory & Allowlist ──────────────────────────

@router.get("/assets")
def list_assets():
    db = _state["db"]
    return {"assets": db.list_assets()}


@router.put("/assets/{ip}")
def update_asset(ip: str, body: AssetUpdateIn):
    db = _state["db"]
    res = db.update_asset(
        ip=ip,
        hostname=body.hostname,
        owner=body.owner,
        department=body.department,
        device_type=body.device_type
    )
    if not res:
        raise HTTPException(404, "Asset IP not found")
    return {"asset": res}


@router.get("/allowlist")
def list_allowlist():
    db = _state["db"]
    return {"allowlist": db.list_allowlist()}


@router.post("/allowlist")
def add_allowlist(body: AllowlistIn):
    db = _state["db"]
    try:
        rule = db.add_allowlist(cidr_or_ip=body.cidr_or_ip, port=body.port, description=body.description)
        db.log_audit("ALLOWLIST_ADD", details=f"Added {body.cidr_or_ip}:{body.port}")
        return {"ok": True, "rule": rule}
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.delete("/allowlist/{allowlist_id}")
def delete_allowlist(allowlist_id: int):
    db = _state["db"]
    deleted = db.delete_allowlist(allowlist_id)
    if not deleted:
        raise HTTPException(404, "Allowlist entry not found")
    db.log_audit("ALLOWLIST_DELETE", details=f"Removed rule ID {allowlist_id}")
    return {"ok": True}


# ── System Health & Safe Response ───────────────────────

@router.get("/system/health")
def system_health():
    cap = _state["capture"]
    import resource
    usage = resource.getrusage(resource.RUSAGE_SELF)
    mem_mb = round(usage.ru_maxrss / 1024, 1) if sys.platform != "darwin" else round(usage.ru_maxrss / (1024 * 1024), 1)

    return {
        "status": "healthy",
        "pps": cap.current_pps(),
        "total_packets": cap.stats["packets"],
        "dropped_packets": cap.stats.get("dropped", 0),
        "memory_mb": mem_mb,
        "mode": cap.mode,
        "source": cap.current_source_info
    }


@router.get("/firewall/rule/{ip}")
def get_firewall_rule(ip: str):
    return {
        "ip": ip,
        "iptables": f"sudo iptables -A INPUT -s {ip} -j DROP",
        "ufw": f"sudo ufw deny from {ip} to any",
        "nftables": f"sudo nft add rule inet filter input ip saddr {ip} drop",
        "cisco_ios": f"access-list 100 deny ip host {ip} any",
        "mikrotik": f"/ip firewall filter add chain=input src-address={ip} action=drop comment=\"NAD Auto-Block\""
    }


# ── Sites (WebSec) ──────────────────────────────────────

@router.get("/sites")
def list_sites():
    mon = _state.get("monitor")
    summaries = mon.snapshot() if mon else []
    rows = {s["id"]: s for s in _state["db"].list_sites()}
    merged = []
    for snap in summaries:
        row = rows.get(snap["id"], {})
        merged.append({**row, **snap})
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
    except Exception as e:
        raise HTTPException(500, f"failed to save site: {e}") from e
    mon = _state.get("monitor")
    check = None
    if mon:
        try:
            check = await mon.check_now(site)
        except Exception as e:
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
    mon = _state.get("monitor")
    if mon:
        mon.forget(site_id)
    return {"deleted": True}


@router.post("/sites/{site_id}/scan-now")
async def scan_now(site_id: int):
    site = _state["db"].get_site(site_id)
    if not site:
        raise HTTPException(404, "site not found")
    mon = _state.get("monitor")
    if not mon:
        raise HTTPException(500, "monitor not initialized")
    check = await mon.check_now(site)
    return {"check": check}


@router.get("/sites/{site_id}/history")
def site_history(site_id: int, limit: int = 50):
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
