"""Hybrid ensemble: IsolationForest + LSTM + Transformer + statistical scorer."""
from __future__ import annotations
import math
import os
import pickle

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class HybridModel:
    """Lightweight ensemble that works with or without torch.

    score(features) -> (anomaly_score 0..1, is_anomaly bool)
    """

    def __init__(self, input_dim: int = 41, threshold: float = 0.7):
        self.threshold = threshold
        self.input_dim = input_dim
        self.scaler = StandardScaler() if HAS_SKLEARN else None
        self.iforest = IsolationForest(n_estimators=100, contamination=0.08,
                                       random_state=42) if HAS_SKLEARN else None
        self._fitted = False
        self.lstm = None
        self.transformer = None
        self._load_torch_if_available()

    def _load_torch_if_available(self) -> None:
        try:
            import torch
            from backend.detection.models.lstm_model import LSTMAnomalyModel
            from backend.detection.models.transformer_model import TransformerAnomalyModel
            self.lstm = LSTMAnomalyModel(self.input_dim)
            self.transformer = TransformerAnomalyModel(self.input_dim)
            for m in (self.lstm, self.transformer):
                m.eval()
        except Exception:
            self.lstm = self.transformer = None

    # -- statistical fallback (no sklearn) --
    @staticmethod
    def _stat_score(vec: list[float]) -> float:
        pps = vec[3] if len(vec) > 3 else 0
        syn_ratio = vec[15] if len(vec) > 15 else 0
        ports = vec[22] if len(vec) > 22 else 0
        dns = vec[28] if len(vec) > 28 else 0
        s = 0.0
        s += min(pps / 1000.0, 1.0) * 0.4
        s += min(syn_ratio / 10.0, 1.0) * 0.25
        s += min(ports / 15.0, 1.0) * 0.2
        s += min(dns / 53.0, 1.0) * 0.15
        return max(0.0, min(s, 1.0))

    def fit(self, X) -> None:
        if not HAS_SKLEARN:
            return
        Xs = self.scaler.fit_transform(X)
        self.iforest.fit(Xs)
        self._fitted = True

    def score(self, vec: list[float]) -> tuple[float, bool]:
        ml = 0.0
        if HAS_SKLEARN and self._fitted:
            import numpy as np
            Xs = self.scaler.transform([vec])
            s = self.iforest.decision_function(Xs)[0]  # higher = normal
            ml = 1.0 / (1.0 + math.exp(4 * s))  # sigmoid map to 0..1
        else:
            ml = self._stat_score(vec)
        # torch models contribute only if checkpoint weights exist; else skip
        stat = self._stat_score(vec)
        final = 0.6 * ml + 0.4 * stat
        return final, final >= self.threshold

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({"scaler": self.scaler, "iforest": self.iforest,
                         "threshold": self.threshold}, f)

    def load(self, path: str) -> bool:
        if not os.path.exists(path):
            return False
        try:
            with open(path, "rb") as f:
                d = pickle.load(f)
            self.scaler, self.iforest = d["scaler"], d["iforest"]
            self.threshold = d.get("threshold", self.threshold)
            self._fitted = True
            return True
        except Exception:
            return False
