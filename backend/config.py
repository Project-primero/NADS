"""Central configuration for NAD system."""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Network Anomaly Detector"
    interface: str = "lo"
    capture_mode: str = "simulate"  # simulate | live (scapy)
    flow_timeout: int = 60          # seconds before flow expires
    db_path: str = "data/alerts.db"
    model_dir: str = "models"
    model_type: str = "hybrid"      # isolation_forest | lstm | transformer | hybrid
    anomaly_threshold: float = 0.7
    ws_broadcast_interval: float = 1.0

    # Signature thresholds (see docs/DETECTION_CATALOG.md)
    port_scan_ports: int = 15
    port_scan_window: int = 60
    syn_flood_count: int = 50
    syn_flood_window: int = 10
    udp_flood_count: int = 200
    udp_flood_window: int = 10
    icmp_flood_count: int = 100
    icmp_flood_window: int = 10
    ddos_pps: int = 1000
    brute_force_fails: int = 10
    brute_force_window: int = 300
    dns_tunnel_len: int = 53
    exfil_bytes: int = 10_000_000
    sweep_dsts: int = 10
    sweep_window: int = 60
    horiz_dsts: int = 10
    horiz_window: int = 60
    spray_dsts: int = 5
    smb_count: int = 20
    smb_window: int = 60
    slowloris_count: int = 50
    slowloris_window: int = 60
    amp_count: int = 50
    amp_window: int = 10

    class Config:
        env_prefix = "NAD_"


settings = Settings()
