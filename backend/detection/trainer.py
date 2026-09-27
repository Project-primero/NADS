"""Training pipeline: synthetic + CSV (CICIDS/NSL-KDD style) -> HybridModel."""
from __future__ import annotations
import argparse
import os
import numpy as np

from backend.flow.feature_extractor import FEATURE_NAMES
from backend.detection.models.hybrid_model import HybridModel, HAS_SKLEARN


def synthetic_data(n_normal: int = 5000, n_attack: int = 1000, seed: int = 42):
    rng = np.random.default_rng(seed)
    d = len(FEATURE_NAMES)
    X = np.abs(rng.normal(0.5, 0.3, size=(n_normal, d)))
    Xa = np.abs(rng.normal(0.5, 0.3, size=(n_attack, d)))
    # make attacks anomalous: high pps, syn ratio, ports, dns len
    Xa[:, 3] *= 8   # pps
    Xa[:, 15] *= 6  # syn ratio
    Xa[:, 22] += 10  # unique ports
    Xa[:, 28] += 30  # dns len
    y = np.array([0] * n_normal + [1] * n_attack)
    return np.vstack([X, Xa]), y


def load_csv(path: str):
    import pandas as pd
    df = pd.read_csv(path)
    label_col = next((c for c in df.columns if c.lower() in ("label", "class", "attack")), None)
    if label_col:
        y = (df[label_col].astype(str).str.lower() != "normal").astype(int).values
        X = df.drop(columns=[label_col]).select_dtypes(include=[np.number]).values
    else:
        y = np.zeros(len(df))
        X = df.select_dtypes(include=[np.number]).values
    # align dims
    d = len(FEATURE_NAMES)
    if X.shape[1] < d:
        X = np.pad(X, ((0, 0), (0, d - X.shape[1])))
    return X[:, :d], y


def evaluate(y_true, scores, thr=0.5):
    pred = (scores >= thr).astype(int)
    tp = int(((pred == 1) & (y_true == 1)).sum())
    fp = int(((pred == 1) & (y_true == 0)).sum())
    fn = int(((pred == 0) & (y_true == 1)).sum())
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    f1 = 2 * prec * rec / max(prec + rec, 1e-9)
    return {"precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=None)
    ap.add_argument("--model", default="hybrid", choices=["hybrid", "isolation_forest"])
    ap.add_argument("--out", default="models/hybrid.pkl")
    args = ap.parse_args()

    if args.dataset and os.path.exists(args.dataset):
        X, y = load_csv(args.dataset)
        print(f"Loaded {args.dataset}: {X.shape}")
    else:
        X, y = synthetic_data()
        print(f"Using synthetic data: {X.shape}")

    model = HybridModel(threshold=0.7)
    if HAS_SKLEARN:
        model.fit(X[y == 0])  # train on normal only (unsupervised)
        scores = np.array([model.score(v.tolist())[0] for v in X])
    else:
        scores = np.array([model.score(v.tolist())[0] for v in X])
        print("sklearn missing: using statistical scorer only")
    print("Metrics:", evaluate(y, scores, 0.5))
    print("Metrics@0.7:", evaluate(y, scores, 0.7))
    model.save(args.out)
    print(f"Saved -> {args.out}")


if __name__ == "__main__":
    main()
