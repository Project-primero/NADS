"""SQLAlchemy models."""
from sqlalchemy import Column, Integer, String, Float, create_engine
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


def get_engine(db_path: str = "data/alerts.db"):
    return create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
