"""Transformer-based anomaly model (PyTorch)."""
from __future__ import annotations

try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


if HAS_TORCH:
    class TransformerAnomalyModel(nn.Module):
        def __init__(self, input_dim: int = 41, d_model: int = 64,
                     nhead: int = 4, layers: int = 2, seq_len: int = 10):
            super().__init__()
            self.seq_len = seq_len
            self.proj = nn.Linear(input_dim, d_model)
            enc = nn.TransformerEncoderLayer(d_model, nhead, dim_feedforward=128,
                                             batch_first=True, dropout=0.1)
            self.encoder = nn.TransformerEncoder(enc, layers)
            self.head = nn.Sequential(nn.Linear(d_model, 32), nn.ReLU(),
                                      nn.Linear(32, 1))

        def forward(self, x):
            h = self.proj(x)
            h = self.encoder(h)
            return self.head(h[:, -1, :]).squeeze(-1)
else:
    class TransformerAnomalyModel:  # type: ignore
        def __init__(self, *a, **k):
            raise ImportError("torch not installed")
