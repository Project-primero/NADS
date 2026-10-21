"""SQLite persistence helpers."""
from __future__ import annotations
import os
import time
from sqlalchemy.orm import sessionmaker
from backend.database.models import Base, Alert, Site, SiteCheck, get_engine


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
