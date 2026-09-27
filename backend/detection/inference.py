"""Real-time inference: flow features -> anomaly score + combined verdict."""
from __future__ import annotations
from backend.flow.feature_extractor import extract_features, features_to_vector
from backend.detection.models.hybrid_model import HybridModel


class DetectionEngine:
    def __init__(self, threshold: float = 0.7, model_path: str = "models/hybrid.pkl"):
        self.model = HybridModel(threshold=threshold)
        self.model.load(model_path)

    def analyze_flow(self, flow) -> dict:
        feats = extract_features(flow)
        vec = features_to_vector(feats)
        score, is_anomaly = self.model.score(vec)
        severity = "LOW"
        if score > 0.9:
            severity = "CRITICAL"
        elif score > 0.8:
            severity = "HIGH"
        elif score > 0.7:
            severity = "MEDIUM"
        return {"anomaly_score": round(score, 4), "is_anomaly": is_anomaly,
                "severity": severity, "features": feats,
                "attack_type": "Anomaly" if is_anomaly else "Normal",
                "engine": "ml",
                "src_ip": getattr(flow, "src_ip", ""), "dst_ip": getattr(flow, "dst_ip", ""),
                "src_port": getattr(flow, "src_port", 0), "dst_port": getattr(flow, "dst_port", 0),
                "protocol": getattr(flow, "protocol", "")}
