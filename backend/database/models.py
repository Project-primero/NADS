"""SQLAlchemy models."""
from sqlalchemy import Column, Integer, String, Float, Boolean, JSON, create_engine
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    timestamp = Column(Float)
    attack_type = Column(String)
    severity = Column(String)
    description = Column(String)
    src_ip = Column(String)
    dst_ip = Column(String)
    src_port = Column(Integer, default=0)
    dst_port = Column(Integer, default=0)
    protocol = Column(String, default="")
    engine = Column(String, default="")
    anomaly_score = Column(Float, default=0.0)


class Site(Base):
    __tablename__ = "sites"
    id = Column(Integer, primary_key=True)
    name = Column(String, default="")
    url = Column(String, unique=True)
    enabled = Column(Boolean, default=True)
    check_interval_sec = Column(Integer, default=60)
    created_at = Column(Float, default=0.0)


class SiteCheck(Base):
    __tablename__ = "site_checks"
    id = Column(Integer, primary_key=True)
    site_id = Column(Integer, index=True)
    ts = Column(Float)
    up = Column(Boolean, default=False)
    status_code = Column(Integer, default=0)
    latency_ms = Column(Float, default=0.0)
    error = Column(String, default="")
    tls_days_left = Column(Integer, default=-1)
    tls_issuer = Column(String, default="")
    tls_valid = Column(Boolean, default=False)
    tls_proto = Column(String, default="")
    tls_cipher = Column(String, default="")
    security_score = Column(Integer, default=0)
    server_banner = Column(String, default="")
    technology = Column(String, default="")
    headers = Column(JSON, default=dict)
    findings = Column(JSON, default=list)


class Agent(Base):
    __tablename__ = "agents"
    id = Column(Integer, primary_key=True)
    agent_id = Column(String, unique=True, index=True)
    name = Column(String, default="")
    site = Column(String, default="Default Site")
    token_hash = Column(String, index=True)
    ip = Column(String, default="")
    hostname = Column(String, default="")
    os = Column(String, default="")
    status = Column(String, default="OFFLINE")  # ONLINE / OFFLINE
    pps = Column(Float, default=0.0)
    total_packets = Column(Integer, default=0)
    last_seen = Column(Float, default=0.0)
    created_at = Column(Float, default=0.0)


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    ip = Column(String, unique=True, index=True)
    mac = Column(String, default="")
    hostname = Column(String, default="")
    owner = Column(String, default="")
    department = Column(String, default="")
    device_type = Column(String, default="Unknown")  # Server, Workstation, IoT, Router, Unknown
    first_seen = Column(Float, default=0.0)
    last_seen = Column(Float, default=0.0)
    packet_count = Column(Integer, default=0)


class Allowlist(Base):
    __tablename__ = "allowlist"
    id = Column(Integer, primary_key=True)
    cidr_or_ip = Column(String, index=True)
    port = Column(Integer, default=0)  # 0 means all ports
    description = Column(String, default="")
    created_at = Column(Float, default=0.0)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(Float)
    action = Column(String)
    user = Column(String, default="Admin")
    details = Column(String, default="")


class PcapJob(Base):
    __tablename__ = "pcap_jobs"
    id = Column(String, primary_key=True)
    filename = Column(String)
    total_packets = Column(Integer, default=0)
    processed_packets = Column(Integer, default=0)
    alerts_count = Column(Integer, default=0)
    status = Column(String, default="QUEUED")  # QUEUED, RUNNING, COMPLETED, FAILED
    speed = Column(String, default="instant")
    error = Column(String, default="")
    started_at = Column(Float, default=0.0)
    completed_at = Column(Float, default=0.0)


def get_engine(db_path: str = "data/alerts.db"):
    return create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
