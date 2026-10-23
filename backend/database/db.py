"""SQLite persistence helpers."""
from __future__ import annotations
import hashlib
import ipaddress
import os
import secrets
import time
from sqlalchemy.orm import sessionmaker
from backend.database.models import (
    Base, Alert, Site, SiteCheck, Agent, Asset, Allowlist, AuditLog, PcapJob, get_engine
)


class Database:
    def __init__(self, db_path: str = "data/alerts.db"):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.engine = get_engine(db_path)
        Base.metadata.create_all(self.engine)
        self._migrate()
        self.Session = sessionmaker(bind=self.engine)

    def _migrate(self) -> None:
        try:
            with self.engine.connect() as conn:
                cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(site_checks)")]
                if "technology" not in cols:
                    conn.exec_driver_sql(
                        "ALTER TABLE site_checks ADD COLUMN technology VARCHAR DEFAULT ''")
                if "tls_proto" not in cols:
                    conn.exec_driver_sql(
                        "ALTER TABLE site_checks ADD COLUMN tls_proto VARCHAR DEFAULT ''")
                if "tls_cipher" not in cols:
                    conn.exec_driver_sql(
                        "ALTER TABLE site_checks ADD COLUMN tls_cipher VARCHAR DEFAULT ''")
        except Exception:
            pass

    # ── Alerts ─────────────────────────────────────────
    def save_alert(self, a: dict) -> None:
        s = self.Session()
        try:
            s.add(Alert(timestamp=a.get("timestamp", 0),
                        attack_type=a.get("attack_type", ""),
                        severity=a.get("severity", "LOW"),
                        description=a.get("description", ""),
                        src_ip=a.get("src_ip", ""), dst_ip=a.get("dst_ip", ""),
                        src_port=a.get("src_port", 0), dst_port=a.get("dst_port", 0),
                        protocol=a.get("protocol", ""), engine=a.get("engine", ""),
                        anomaly_score=a.get("anomaly_score", 0.0)))
            s.commit()
        finally:
            s.close()

    def get_alerts(self, limit: int = 100) -> list[dict]:
        s = self.Session()
        try:
            rows = s.query(Alert).order_by(Alert.id.desc()).limit(limit).all()
            return [{"id": r.id, "timestamp": r.timestamp, "attack_type": r.attack_type,
                     "severity": r.severity, "description": r.description,
                     "src_ip": r.src_ip, "dst_ip": r.dst_ip, "src_port": r.src_port,
                     "dst_port": r.dst_port, "protocol": r.protocol,
                     "engine": r.engine, "anomaly_score": r.anomaly_score}
                    for r in rows]
        finally:
            s.close()

    def export_alerts(self, limit: int = 5000) -> list[dict]:
        return self.get_alerts(limit=limit)

    def cleanup_old_records(self, retention_days: int = 30) -> int:
        s = self.Session()
        try:
            cutoff = time.time() - (retention_days * 86400)
            deleted = s.query(Alert).filter(Alert.timestamp < cutoff).delete()
            s.query(SiteCheck).filter(SiteCheck.ts < cutoff).delete()
            s.commit()
            return deleted
        finally:
            s.close()

    # ── Sites ──────────────────────────────────────────
    def add_site(self, name: str, url: str, interval: int = 60) -> dict:
        s = self.Session()
        try:
            existing = s.query(Site).filter_by(url=url).first()
            if existing:
                return self._site_row(existing)
            row = Site(name=name or url, url=url, enabled=True,
                       check_interval_sec=max(15, interval), created_at=time.time())
            s.add(row)
            s.commit()
            s.refresh(row)
            return self._site_row(row)
        finally:
            s.close()

    def list_sites(self, enabled_only: bool = False) -> list[dict]:
        s = self.Session()
        try:
            q = s.query(Site)
            if enabled_only:
                q = q.filter_by(enabled=True)
            return [self._site_row(r) for r in q.order_by(Site.id).all()]
        finally:
            s.close()

    def get_site(self, site_id: int) -> dict | None:
        s = self.Session()
        try:
            r = s.query(Site).get(site_id)
            return self._site_row(r) if r else None
        finally:
            s.close()

    def update_site(self, site_id: int, name: str | None = None,
                    interval: int | None = None, enabled: bool | None = None) -> dict | None:
        s = self.Session()
        try:
            r = s.query(Site).get(site_id)
            if not r:
                return None
            if name is not None:
                r.name = name.strip() or r.name
            if interval is not None:
                r.check_interval_sec = max(15, interval)
            if enabled is not None:
                r.enabled = bool(enabled)
            s.commit()
            s.refresh(r)
            return self._site_row(r)
        finally:
            s.close()

    def delete_site(self, site_id: int) -> bool:
        s = self.Session()
        try:
            r = s.query(Site).get(site_id)
            if not r:
                return False
            s.query(SiteCheck).filter_by(site_id=site_id).delete()
            s.delete(r)
            s.commit()
            return True
        finally:
            s.close()

    def save_check(self, c: dict) -> None:
        s = self.Session()
        try:
            s.add(SiteCheck(site_id=c["site_id"], ts=c["ts"], up=c["up"],
                            status_code=c.get("status_code", 0),
                            latency_ms=c.get("latency_ms", 0.0),
                            error=c.get("error", ""),
                            tls_days_left=c.get("tls_days_left", -1),
                            tls_issuer=c.get("tls_issuer", ""),
                            tls_valid=c.get("tls_valid", False),
                            tls_proto=c.get("tls_proto", ""),
                            tls_cipher=c.get("tls_cipher", ""),
                            security_score=c.get("security_score", 0),
                            server_banner=c.get("server_banner", ""),
                            technology=c.get("technology", ""),
                            headers=c.get("headers", {}),
                            findings=c.get("findings", [])))
            s.commit()
        finally:
            s.close()

    def get_checks(self, site_id: int, limit: int = 288) -> list[dict]:
        s = self.Session()
        try:
            rows = (s.query(SiteCheck).filter_by(site_id=site_id)
                    .order_by(SiteCheck.id.desc()).limit(limit).all())
            return [{"id": r.id, "site_id": r.site_id, "ts": r.ts, "up": r.up,
                     "status_code": r.status_code, "latency_ms": r.latency_ms,
                     "error": r.error, "tls_days_left": r.tls_days_left,
                     "tls_issuer": r.tls_issuer, "tls_valid": r.tls_valid,
                     "tls_proto": getattr(r, "tls_proto", "") or "",
                     "tls_cipher": getattr(r, "tls_cipher", "") or "",
                     "security_score": r.security_score,
                     "server_banner": r.server_banner,
                     "technology": getattr(r, "technology", "") or "",
                     "headers": r.headers or {}, "findings": r.findings or []}
                    for r in rows]
        finally:
            s.close()

    def uptime_24h(self, site_id: int) -> float:
        s = self.Session()
        try:
            cutoff = time.time() - 86400
            total = s.query(SiteCheck).filter(SiteCheck.site_id == site_id,
                                              SiteCheck.ts >= cutoff).count()
            if total == 0:
                return -1.0
            up = s.query(SiteCheck).filter(SiteCheck.site_id == site_id,
                                           SiteCheck.ts >= cutoff,
                                           SiteCheck.up.is_(True)).count()
            return round(100.0 * up / total, 2)
        finally:
            s.close()

    @staticmethod
    def _site_row(r: Site) -> dict:
        return {"id": r.id, "name": r.name, "url": r.url, "enabled": r.enabled,
                "check_interval_sec": r.check_interval_sec, "created_at": r.created_at}

    # ── Agents (Remote Computers & Endpoints) ──────────
    @staticmethod
    def _hash_token(raw_token: str) -> str:
        return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()

    def create_agent(self, name: str, site: str = "Default Site") -> dict:
        raw_token = "agt_" + secrets.token_hex(24)
        token_hash = self._hash_token(raw_token)
        agent_id = f"agent-{secrets.token_hex(6)}"
        now = time.time()
        s = self.Session()
        try:
            agent = Agent(
                agent_id=agent_id,
                name=name or f"Node-{agent_id[-4:]}",
                site=site or "Default Site",
                token_hash=token_hash,
                status="OFFLINE",
                created_at=now,
                last_seen=0.0
            )
            s.add(agent)
            s.commit()
            return {
                "agent_id": agent.agent_id,
                "name": agent.name,
                "site": agent.site,
                "token": raw_token,  # returned only once upon creation
                "created_at": agent.created_at
            }
        finally:
            s.close()

    def verify_agent_token(self, raw_token: str) -> dict | None:
        if not raw_token:
            return None
        token_hash = self._hash_token(raw_token)
        s = self.Session()
        try:
            agent = s.query(Agent).filter_by(token_hash=token_hash).first()
            if not agent:
                return None
            return {
                "id": agent.id,
                "agent_id": agent.agent_id,
                "name": agent.name,
                "site": agent.site,
                "status": agent.status
            }
        finally:
            s.close()

    def update_agent_telemetry(self, agent_id: str, ip: str = "", hostname: str = "",
                               os_name: str = "", pps: float = 0.0, packets_inc: int = 0) -> None:
        s = self.Session()
        try:
            agent = s.query(Agent).filter_by(agent_id=agent_id).first()
            if agent:
                agent.last_seen = time.time()
                agent.status = "ONLINE"
                if ip:
                    agent.ip = ip
                if hostname:
                    agent.hostname = hostname
                if os_name:
                    agent.os = os_name
                agent.pps = pps
                agent.total_packets += packets_inc
                s.commit()
        finally:
            s.close()

    def list_agents(self) -> list[dict]:
        s = self.Session()
        now = time.time()
        try:
            rows = s.query(Agent).order_by(Agent.id.desc()).all()
            res = []
            for r in rows:
                is_online = (now - (r.last_seen or 0)) < 30.0 if r.last_seen else False
                res.append({
                    "id": r.id,
                    "agent_id": r.agent_id,
                    "name": r.name,
                    "site": r.site,
                    "ip": r.ip,
                    "hostname": r.hostname,
                    "os": r.os,
                    "status": "ONLINE" if is_online else "OFFLINE",
                    "pps": round(r.pps or 0.0, 1),
                    "total_packets": r.total_packets or 0,
                    "last_seen": r.last_seen or 0.0,
                    "created_at": r.created_at or 0.0
                })
            return res
        finally:
            s.close()

    def delete_agent(self, agent_id: str) -> bool:
        s = self.Session()
        try:
            agent = s.query(Agent).filter_by(agent_id=agent_id).first()
            if not agent:
                return False
            s.delete(agent)
            s.commit()
            return True
        finally:
            s.close()

    # ── Assets (Discovered Computers & Devices) ────────
    def touch_asset(self, ip: str, mac: str = "", device_type: str = "Unknown") -> None:
        if not ip or ip in ("?", "0.0.0.0", "127.0.0.1"):
            return
        s = self.Session()
        now = time.time()
        try:
            asset = s.query(Asset).filter_by(ip=ip).first()
            if not asset:
                asset = Asset(
                    ip=ip,
                    mac=mac or "",
                    hostname="",
                    owner="",
                    department="",
                    device_type=device_type or "Unknown",
                    first_seen=now,
                    last_seen=now,
                    packet_count=1
                )
                s.add(asset)
            else:
                asset.last_seen = now
                asset.packet_count += 1
                if mac and not asset.mac:
                    asset.mac = mac
            s.commit()
        except Exception:
            s.rollback()
        finally:
            s.close()

    def list_assets(self, limit: int = 100) -> list[dict]:
        s = self.Session()
        try:
            rows = s.query(Asset).order_by(Asset.last_seen.desc()).limit(limit).all()
            return [{
                "id": r.id,
                "ip": r.ip,
                "mac": r.mac,
                "hostname": r.hostname or "",
                "owner": r.owner or "",
                "department": r.department or "",
                "device_type": r.device_type or "Unknown",
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
                "packet_count": r.packet_count
            } for r in rows]
        finally:
            s.close()

    def update_asset(self, ip: str, hostname: str | None = None, owner: str | None = None,
                     department: str | None = None, device_type: str | None = None) -> dict | None:
        s = self.Session()
        try:
            asset = s.query(Asset).filter_by(ip=ip).first()
            if not asset:
                return None
            if hostname is not None:
                asset.hostname = hostname.strip()
            if owner is not None:
                asset.owner = owner.strip()
            if department is not None:
                asset.department = department.strip()
            if device_type is not None:
                asset.device_type = device_type.strip()
            s.commit()
            return {
                "id": asset.id, "ip": asset.ip, "hostname": asset.hostname,
                "owner": asset.owner, "department": asset.department,
                "device_type": asset.device_type
            }
        finally:
            s.close()

    # ── Allowlist ──────────────────────────────────────
    def add_allowlist(self, cidr_or_ip: str, port: int = 0, description: str = "") -> dict:
        cidr_or_ip = cidr_or_ip.strip()
        # validate IP or CIDR
        try:
            if "/" in cidr_or_ip:
                ipaddress.ip_network(cidr_or_ip, strict=False)
            else:
                ipaddress.ip_address(cidr_or_ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP or CIDR format: {cidr_or_ip}") from e

        s = self.Session()
        try:
            row = Allowlist(cidr_or_ip=cidr_or_ip, port=max(0, port),
                            description=description.strip(), created_at=time.time())
            s.add(row)
            s.commit()
            s.refresh(row)
            return {"id": row.id, "cidr_or_ip": row.cidr_or_ip, "port": row.port,
                    "description": row.description, "created_at": row.created_at}
        finally:
            s.close()

    def list_allowlist(self) -> list[dict]:
        s = self.Session()
        try:
            rows = s.query(Allowlist).order_by(Allowlist.id.desc()).all()
            return [{"id": r.id, "cidr_or_ip": r.cidr_or_ip, "port": r.port,
                     "description": r.description, "created_at": r.created_at}
                    for r in rows]
        finally:
            s.close()

    def delete_allowlist(self, allowlist_id: int) -> bool:
        s = self.Session()
        try:
            row = s.query(Allowlist).get(allowlist_id)
            if not row:
                return False
            s.delete(row)
            s.commit()
            return True
        finally:
            s.close()

    def is_allowlisted(self, ip: str, port: int = 0) -> bool:
        if not ip:
            return False
        rules = self.list_allowlist()
        if not rules:
            return False
        try:
            target_ip = ipaddress.ip_address(ip)
        except ValueError:
            return False

        for r in rules:
            if r["port"] != 0 and port != 0 and r["port"] != port:
                continue
            entry = r["cidr_or_ip"]
            try:
                if "/" in entry:
                    if target_ip in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if target_ip == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                continue
        return False

    # ── Audit Logs ─────────────────────────────────────
    def log_audit(self, action: str, user: str = "Admin", details: str = "") -> None:
        s = self.Session()
        try:
            s.add(AuditLog(timestamp=time.time(), action=action, user=user, details=details))
            s.commit()
        except Exception:
            pass
        finally:
            s.close()

    def list_audit_logs(self, limit: int = 50) -> list[dict]:
        s = self.Session()
        try:
            rows = s.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
            return [{"id": r.id, "timestamp": r.timestamp, "action": r.action,
                     "user": r.user, "details": r.details} for r in rows]
        finally:
            s.close()

    # ── PCAP Jobs ──────────────────────────────────────
    def save_pcap_job(self, job_id: str, filename: str, speed: str = "instant") -> dict:
        s = self.Session()
        try:
            job = PcapJob(id=job_id, filename=filename, speed=speed, status="QUEUED",
                          started_at=time.time())
            s.add(job)
            s.commit()
            return {"id": job.id, "filename": job.filename, "status": job.status,
                    "speed": job.speed, "started_at": job.started_at}
        finally:
            s.close()

    def update_pcap_job(self, job_id: str, **kwargs) -> None:
        s = self.Session()
        try:
            job = s.query(PcapJob).filter_by(id=job_id).first()
            if job:
                for k, v in kwargs.items():
                    if hasattr(job, k):
                        setattr(job, k, v)
                s.commit()
        finally:
            s.close()

    def get_pcap_job(self, job_id: str) -> dict | None:
        s = self.Session()
        try:
            job = s.query(PcapJob).filter_by(id=job_id).first()
            if not job:
                return None
            return {
                "id": job.id, "filename": job.filename, "total_packets": job.total_packets,
                "processed_packets": job.processed_packets, "alerts_count": job.alerts_count,
                "status": job.status, "speed": job.speed, "error": job.error,
                "started_at": job.started_at, "completed_at": job.completed_at
            }
        finally:
            s.close()
