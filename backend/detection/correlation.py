"""Correlation engine: fuse signature + ML outputs into one scored verdict.

threat_score 0-100; level: LOW <40, MEDIUM <60, HIGH <80, CRITICAL >=80.
"""
from __future__ import annotations

SEV_BASE = {"LOW": 20, "MEDIUM": 45, "HIGH": 70, "CRITICAL": 90}


def correlate(sig_alerts: list[dict], ml_result: dict | None) -> dict | None:
    """Return final alert dict or None. Prefers signature; boosts with ML."""
    best = None
    if sig_alerts:
        # highest severity wins
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        best = max(sig_alerts, key=lambda a: order.get(a.get("severity", "LOW"), 0))
        best = dict(best)
        score = SEV_BASE.get(best["severity"], 30)
        score += int(10 * float(best.get("confidence", 0.8)))
        if ml_result and ml_result.get("is_anomaly"):
            score += 10  # independent ML confirmation
            best["description"] += f" + ML confirms (score {ml_result['anomaly_score']})"
            best["engine"] = "signature+ml"
        best["threat_score"] = min(score, 100)
        return best
    if ml_result and ml_result.get("is_anomaly"):
        s = float(ml_result["anomaly_score"])
        level = "CRITICAL" if s > 0.9 else "HIGH" if s > 0.8 else "MEDIUM"
        return {"attack_type": f"Anomaly ({level})", "severity": level,
                "confidence": round(s, 2), "mitre": "T1498/T1071",
                "remediation": "Investigate flow: check bytes/pps/ports vs baseline.",
                "description": f"ML anomaly score {s}",
                "src_ip": ml_result.get("src_ip", ""), "dst_ip": ml_result.get("dst_ip", ""),
                "src_port": ml_result.get("src_port", 0), "dst_port": ml_result.get("dst_port", 0),
                "protocol": ml_result.get("protocol", ""), "engine": "ml",
                "anomaly_score": s, "threat_score": int(30 + 70 * s)}
    return None


def threat_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"
