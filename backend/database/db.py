"""SQLite persistence helpers."""
from __future__ import annotations
import os
from sqlalchemy.orm import sessionmaker
from backend.database.models import Base, Alert, get_engine


class Database:
    def __init__(self, db_path: str = "data/alerts.db"):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.engine = get_engine(db_path)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

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
