"""Bidirectional LSTM anomaly model (PyTorch)."""
from __future__ import annotations

try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


if HAS_TORCH:
    class LSTMAnomalyModel(nn.Module):
        def __init__(self, input_dim: int = 41, hidden: int = 64,
                     layers: int = 2, seq_len: int = 10):
            super().__init__()
            self.seq_len = seq_len
            self.lstm = nn.LSTM(input_dim, hidden, layers, batch_first=True,
                                bidirectional=True, dropout=0.2)
            self.head = nn.Sequential(nn.Linear(hidden * 2, 32), nn.ReLU(),
                                      nn.Linear(32, 1))

        def forward(self, x):
            out, _ = self.lstm(x)
            return self.head(out[:, -1, :]).squeeze(-1)
else:
    class LSTMAnomalyModel:  # type: ignore
        def __init__(self, *a, **k):
            raise ImportError("torch not installed")
